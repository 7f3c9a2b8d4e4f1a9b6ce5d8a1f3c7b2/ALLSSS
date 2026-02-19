### Title
Zero-Value Side Chain Creation Bypasses Indexing Fee Mechanism

### Summary
The `ChargeSideChainIndexingFee` helper function returns early when `amount <= 0`, allowing side chains to be created with zero locked tokens and zero indexing price. This completely bypasses the indexing fee economic model, enabling side chain creators to receive free indexing services indefinitely without compensating parent chain validators.

### Finding Description

The vulnerability exists in the interaction between three code locations:

**Location 1 - Insufficient Validation:** [1](#0-0) 

The validation only requires `IndexingPrice >= 0` and `LockedTokenAmount >= IndexingPrice`, which allows both values to be zero simultaneously. The validation treats zero as a valid value rather than enforcing a minimum positive amount.

**Location 2 - Early Return Without Locking:** [2](#0-1) 

When `ChargeSideChainIndexingFee` is called with `amount = 0`, the function returns immediately without executing the `TransferFrom` operation. This means no tokens are locked to the side chain's virtual address.

**Location 3 - Fee-Free Indexing:** [3](#0-2) 

During side chain block indexing, when `lockedToken = 0` and `indexingPrice = 0`, the arithmetic `lockedToken -= indexingPrice` results in `0 - 0 = 0`. Since `lockedToken` is not negative, no debt is recorded, and blocks are indexed without payment. The condition `if (indexingFeeAmount > 0)` at line 861 prevents any fee transfer, and no arrears accumulate.

**Execution Path:**
1. Attacker calls `RequestSideChainCreation` with `IndexingPrice = 0` and `LockedTokenAmount = 0` [4](#0-3) 

2. Proposal is approved and `CreateSideChain` is executed, which calls the vulnerable helper [5](#0-4) 

3. Side chain is created with `Status = Active`, `IndexingPrice = 0`, and zero locked balance

4. When miners index the side chain blocks through `IndexSideChainBlockData`, no fees are charged or accumulated as debt

### Impact Explanation

**Direct Economic Impact:**
- **Fund Theft/Loss:** Parent chain validators perform computational work to index side chain blocks but receive zero compensation. The indexing fee mechanism, designed to pay validators for their services, is completely bypassed.
- **Protocol Revenue Loss:** The cross-chain bridge loses all indexing fee revenue from affected side chains.
- **Unfair Advantage:** Malicious actors can create unlimited "free-riding" side chains while honest side chain creators pay fees.

**Affected Parties:**
- Parent chain validators who index side chain blocks without payment
- Honest side chain creators who face unfair competition
- The AElf ecosystem's economic sustainability

**Severity Justification (HIGH):**
- Complete bypass of critical economic mechanism
- Zero cost to exploit (no tokens needed)
- Unlimited exploitation potential (create many side chains)
- Violates fundamental protocol invariant: "indexing services must be compensated"
- No natural rate limiting or detection mechanism

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to submit side chain creation proposals (any account with approval allowance)
- Ability to get proposal approved through governance (standard governance process)
- No special privileges or insider access required

**Attack Complexity: LOW**
- Single transaction to propose: `RequestSideChainCreation` with zero values
- Standard governance approval flow
- No complex state manipulation or timing requirements
- Attack parameters are straightforward: set both fields to zero

**Feasibility Conditions:**
- Governance approval is the only barrier, but setting zero fees appears economically reasonable to approvers who may not recognize the exploitation
- The validation logic explicitly allows zero values, suggesting this may pass code review
- Test coverage gap: no tests validate the zero-zero case [6](#0-5) [7](#0-6) 

**Economic Rationality:**
- Zero cost to exploit (literally zero tokens required)
- High benefit: free indexing services indefinitely
- Risk: minimal (governance rejection is the only risk)

**Detection Difficulty:**
- No on-chain event signals this as anomalous
- Side chain appears legitimate with `Status = Active`
- Only economic analysis reveals the free-riding behavior

### Recommendation

**Fix 1 - Enforce Minimum Positive Values:**
Modify the validation in `AssertValidSideChainCreationRequest`:

```csharp
Assert(
    sideChainCreationRequest.IndexingPrice > 0 &&
    sideChainCreationRequest.LockedTokenAmount >= sideChainCreationRequest.IndexingPrice,
    "Invalid chain creation request.");
```

Change `>= 0` to `> 0` for `IndexingPrice` to require a minimum positive indexing fee.

**Fix 2 - Add Minimum Locked Amount Check:**
Add an explicit check for minimum locked token amount:

```csharp
const long MinimumLockedTokenAmount = 1000000; // Define reasonable minimum
Assert(
    sideChainCreationRequest.LockedTokenAmount >= MinimumLockedTokenAmount,
    "Insufficient locked token amount.");
```

**Fix 3 - Remove Early Return in ChargeSideChainIndexingFee:**
Replace the early return with an assertion:

```csharp
private void ChargeSideChainIndexingFee(Address lockAddress, long amount, int chainId)
{
    Assert(amount > 0, "Locked token amount must be positive.");
    TransferFrom(...);
}
```

**Test Cases to Add:**
1. Test `RequestSideChainCreation` with `IndexingPrice = 0` and `LockedTokenAmount = 0` - should FAIL
2. Test `RequestSideChainCreation` with `IndexingPrice = 0` and `LockedTokenAmount > 0` - should FAIL
3. Test that minimum locked amount is enforced across all creation paths
4. Integration test verifying indexing fee deduction with minimum values

### Proof of Concept

**Initial State:**
- Cross-chain contract initialized
- Attacker has approval allowance of 0 tokens (since LockedTokenAmount = 0)
- Governance organization exists and can approve proposals

**Exploitation Steps:**

**Step 1:** Attacker calls `RequestSideChainCreation`:
```
SideChainCreationRequest {
    indexing_price: 0,
    locked_token_amount: 0,
    is_privilege_preserved: false,
    initial_resource_amount: {} // Can be empty for non-exclusive chains
}
```

**Expected:** Validation passes because `0 >= 0 AND 0 >= 0` evaluates to TRUE [1](#0-0) 

**Step 2:** Governance approves and releases the proposal

**Step 3:** `CreateSideChain` executes:
- Calls `ChargeSideChainIndexingFee(proposer, 0, chainId)`
- Function returns early without locking tokens
- Side chain created with `IndexingPrice = 0`, `LockedTokenAmount = 0`, `Status = Active`

**Step 4:** Miners index side chain blocks via `IndexSideChainBlockData`:
- `lockedToken = GetSideChainIndexingFeeDeposit(chainId)` returns 0
- `lockedToken -= indexingPrice` → `0 - 0 = 0`
- No debt recorded because `lockedToken (0)` is not `< 0`
- Blocks indexed successfully

**Expected vs Actual Result:**
- **Expected:** Side chain creation should fail with "Invalid chain creation request" or require minimum positive values
- **Actual:** Side chain is created successfully and can be indexed indefinitely without paying any fees

**Success Condition:** 
Side chain exists in `State.SideChainInfo` with `IndexingPrice = 0` and `GetSideChainIndexingFeeDeposit(chainId) = 0`, yet blocks can be indexed through `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal` without triggering `SideChainStatus.IndexingFeeDebt`.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L60-71)
```csharp
    private void ChargeSideChainIndexingFee(Address lockAddress, long amount, int chainId)
    {
        if (amount <= 0)
            return;
        TransferFrom(new TransferFromInput
        {
            From = lockAddress,
            To = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Amount = amount,
            Symbol = Context.Variables.NativeSymbol
        });
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L119-122)
```csharp
        Assert(
            sideChainCreationRequest.IndexingPrice >= 0 &&
            sideChainCreationRequest.LockedTokenAmount >= sideChainCreationRequest.IndexingPrice,
            "Invalid chain creation request.");
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L828-859)
```csharp
            var lockedToken = sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt
                ? 0
                : GetSideChainIndexingFeeDeposit(chainId);

            foreach (var sideChainBlockData in sideChainBlockDataList)
            {
                var target = currentSideChainHeight != 0
                    ? currentSideChainHeight + 1
                    : AElfConstants.GenesisBlockHeight;
                var sideChainHeight = sideChainBlockData.Height;
                if (target != sideChainHeight)
                    break;

                // indexing fee
                var indexingPrice = sideChainInfo.IndexingPrice;

                lockedToken -= indexingPrice;

                if (lockedToken < 0)
                {
                    // record arrears
                    arrearsAmount += indexingPrice;
                    sideChainInfo.SideChainStatus = SideChainStatus.IndexingFeeDebt;
                }
                else
                {
                    indexingFeeAmount += indexingPrice;
                }

                currentSideChainHeight++;
                indexedSideChainBlockData.Add(sideChainBlockData);
            }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L90-96)
```csharp
    public override Empty RequestSideChainCreation(SideChainCreationRequest input)
    {
        AssertValidSideChainCreationRequest(input, Context.Sender);
        var sideChainCreationRequestState = ProposeNewSideChain(input, Context.Sender);
        State.ProposedSideChainCreationRequestState[Context.Sender] = sideChainCreationRequestState;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L121-167)
```csharp
    public override Int32Value CreateSideChain(CreateSideChainInput input)
    {
        // side chain creation should be triggered by organization address.
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var proposedSideChainCreationRequestState = State.ProposedSideChainCreationRequestState[input.Proposer];
        State.ProposedSideChainCreationRequestState.Remove(input.Proposer);
        var sideChainCreationRequest = input.SideChainCreationRequest;
        Assert(
            proposedSideChainCreationRequestState != null &&
            proposedSideChainCreationRequestState.SideChainCreationRequest.Equals(sideChainCreationRequest),
            "Side chain creation failed without proposed data.");
        AssertValidSideChainCreationRequest(sideChainCreationRequest, input.Proposer);

        State.SideChainSerialNumber.Value = State.SideChainSerialNumber.Value.Add(1);
        var serialNumber = State.SideChainSerialNumber.Value;
        var chainId = GetChainId(serialNumber);
        State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;

        // lock token
        ChargeSideChainIndexingFee(input.Proposer, sideChainCreationRequest.LockedTokenAmount, chainId);

        var sideChainInfo = new SideChainInfo
        {
            Proposer = input.Proposer,
            SideChainId = chainId,
            SideChainStatus = SideChainStatus.Active,
            IndexingPrice = sideChainCreationRequest.IndexingPrice,
            IsPrivilegePreserved = sideChainCreationRequest.IsPrivilegePreserved,
            CreationTimestamp = Context.CurrentBlockTime,
            CreationHeightOnParentChain = Context.CurrentHeight,
            IndexingFeeController = CreateDefaultOrganizationForIndexingFeePriceManagement(input.Proposer)
        };
        State.SideChainInfo[chainId] = sideChainInfo;
        State.CurrentSideChainHeight[chainId] = 0;

        var chainInitializationData =
            GetChainInitializationData(sideChainInfo, sideChainCreationRequest);
        State.SideChainInitializationData[sideChainInfo.SideChainId] = chainInitializationData;

        Context.Fire(new SideChainCreatedEvent
        {
            ChainId = chainId,
            Creator = input.Proposer
        });
        return new Int32Value { Value = chainId };
    }
```

**File:** test/AElf.Contracts.CrossChain.Tests/SideChainLifeTimeManagementTest.cs (L1112-1126)
```csharp
            var createProposalInput = CreateSideChainCreationRequest(10, 0, GetValidResourceAmount(),
                new[]
                {
                    new SideChainTokenInitialIssue
                    {
                        Address = DefaultSender,
                        Amount = 100
                    }
                }, true);
            var requestSideChainCreation =
                await CrossChainContractStub.RequestSideChainCreation.SendWithExceptionAsync(createProposalInput);

            requestSideChainCreation.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            requestSideChainCreation.TransactionResult.Error.ShouldContain("Invalid chain creation request.");
        }
```

**File:** test/AElf.Contracts.CrossChain.Tests/SideChainLifeTimeManagementTest.cs (L1129-1143)
```csharp
            var createProposalInput = CreateSideChainCreationRequest(-1, 10, GetValidResourceAmount(),
                new[]
                {
                    new SideChainTokenInitialIssue
                    {
                        Address = DefaultSender,
                        Amount = 100
                    }
                }, true);
            var requestSideChainCreation =
                await CrossChainContractStub.RequestSideChainCreation.SendWithExceptionAsync(createProposalInput);

            requestSideChainCreation.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            requestSideChainCreation.TransactionResult.Error.ShouldContain("Invalid chain creation request.");
        }
```
