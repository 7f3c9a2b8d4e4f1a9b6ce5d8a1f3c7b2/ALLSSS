### Title
Missing Bounds Validation in IndexingPrice Enables Permanent DoS on Recharge and Fee Manipulation

### Summary
The `AdjustIndexingFeePrice()` function only validates that the new price is non-negative but lacks upper bound validation, allowing the IndexingPrice to be set to extremely high or zero values. Setting an extremely high price renders the `Recharge()` function permanently unusable, trapping side chains in IndexingFeeDebt status indefinitely, while zero pricing breaks the economic model by enabling free indexing operations.

### Finding Description

The vulnerability exists in the `AdjustIndexingFeePrice()` function which allows modification of a side chain's indexing fee price: [1](#0-0) 

The validation only checks for non-negative values, with no upper bound: [2](#0-1) 

During side chain creation, there is an additional check ensuring LockedTokenAmount >= IndexingPrice: [3](#0-2) 

However, this check is NOT enforced when adjusting the price post-creation, allowing IndexingPrice to be set to values far exceeding the locked token amount.

The IndexingPrice is consumed during the indexing process where fees are deducted from the deposited balance: [4](#0-3) 

When the balance cannot cover the fee, the side chain enters IndexingFeeDebt status, but indexing continues with arrears tracked. The critical failure occurs in the `Recharge()` function: [5](#0-4) 

This assertion requires the recharge amount plus existing balance to cover all arrears PLUS at least one more IndexingPrice. If IndexingPrice is set to an extremely high value (e.g., near max int64), this becomes economically impossible or causes arithmetic overflow, permanently preventing the side chain from exiting the IndexingFeeDebt status.

### Impact Explanation

**Extremely High Price Scenario:**
- Side chain becomes trapped in IndexingFeeDebt status permanently
- Recharge operation becomes impossible due to the requirement: `input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice`
- With IndexingPrice near max int64, no realistic token amount can satisfy this condition
- Side chain cannot return to Active status despite continued indexing
- Complete operational denial-of-service on the recharge functionality

**Zero Price Scenario:**
- Indexing becomes free (no fees deducted at line 844)
- Breaks the economic model where side chains should pay for mainchain indexing services
- Enables indefinite free indexing operations
- Undermines the tokenomics and value capture mechanism

The IndexingFeeDebt status is defined as: [6](#0-5) 

Test evidence confirms indexing continues even in debt status: [7](#0-6) 

### Likelihood Explanation

**Authorization Requirement:**
The attack requires authorization from the IndexingFeeController organization, which is a 2-of-2 multisig created at side chain initialization: [8](#0-7) 

The controller consists of the side chain creator and the CrossChainIndexingController owner (governance). Authorization is enforced: [9](#0-8) 

**Attack Scenarios:**
1. **Governance compromise**: Malicious proposal approved through the multisig process
2. **Accidental misconfiguration**: Legitimate governance sets high price without understanding permanent recharge DoS consequences
3. **Economic attack**: Coordinated malicious actors within the authorized parties

While requiring multisig authorization increases the barrier, governance compromise is a realistic threat model for smart contract systems, and the complete absence of bounds validation represents a fundamental design flaw that can cause unintended consequences even in legitimate usage.

### Recommendation

**1. Add Upper Bound Validation:**
Implement maximum price limits in `AdjustIndexingFeePrice()`:
```csharp
Assert(input.IndexingFee >= 0 && input.IndexingFee <= MaxAllowedIndexingPrice, 
    "Invalid side chain fee price.");
```

Define `MaxAllowedIndexingPrice` based on economic analysis, considering:
- Typical locked token amounts
- Reasonable indexing fee economics
- Prevention of recharge DoS

**2. Validate Against Locked Amount:**
Add consistency check similar to creation validation:
```csharp
var lockedAmount = GetSideChainIndexingFeeDeposit(input.SideChainId);
Assert(input.IndexingFee <= lockedAmount, 
    "Indexing fee cannot exceed current locked amount.");
```

**3. Add Zero Price Protection:**
If zero pricing is intentionally disallowed:
```csharp
Assert(input.IndexingFee > 0 && input.IndexingFee <= MaxAllowedIndexingPrice, 
    "Invalid side chain fee price.");
```

**4. Enhance Recharge Safety:**
Add overflow protection and better error messages:
```csharp
var requiredAmount = arrearsAmount.Add(sideChainInfo.IndexingPrice);
Assert(!requiredAmount.HasOverflow() && input.Amount + originBalance >= requiredAmount,
    "Indexing fee recharging not enough or overflow detected.");
```

**5. Test Coverage:**
Add regression tests for:
- Attempting to set IndexingPrice to max int64
- Attempting to set IndexingPrice to zero
- Attempting to set IndexingPrice higher than locked amount
- Verifying recharge works correctly with various price levels

### Proof of Concept

**Initial State:**
- Side chain created with IndexingPrice = 100, LockedTokenAmount = 1000
- Side chain status = Active

**Attack Sequence:**

1. **Setup malicious price adjustment proposal:**
   - Create multisig proposal to call `AdjustIndexingFeePrice()`
   - Set IndexingFee = 9223372036854775807 (max int64)
   - Target: existing side chain ID

2. **Execute through governance:**
   - Obtain approval from side chain creator (via compromise or collusion)
   - Obtain approval from CrossChainIndexingController owner
   - Release and execute the proposal
   - IndexingPrice now set to max int64

3. **Trigger debt status:**
   - Wait for next indexing operation
   - Indexing deducts max int64 from locked balance of 1000
   - Side chain immediately enters IndexingFeeDebt status
   - Arrears = max int64

4. **Verify DoS on recharge:**
   - Attempt to call `Recharge()` with any realistic amount
   - Required amount = arrears (max int64) + IndexingPrice (max int64)
   - Either arithmetic overflow or economically impossible amount
   - Transaction fails with "Indexing fee recharging not enough"
   - Side chain permanently stuck in IndexingFeeDebt status

**Expected vs Actual:**
- **Expected**: Bounds validation prevents extreme IndexingPrice values
- **Actual**: No upper bound check exists, allowing permanent recharge DoS

**Success Condition:**
- Side chain enters IndexingFeeDebt status and cannot exit via Recharge() due to impossible fee requirements

### Notes

The vulnerability stems from incomplete validation that only checks the lower bound (>= 0) without considering upper bounds or economic feasibility. While the attack requires multisig authorization from the IndexingFeeController, the missing validation represents a fundamental design flaw that could cause unintended consequences even during legitimate governance operations. The severity is heightened because the impact is permanent and irreversible once an extremely high price is set, with no recovery mechanism available.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L206-208)
```csharp
            var originBalance = GetSideChainIndexingFeeDeposit(chainId);
            Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
                "Indexing fee recharging not enough.");
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L244-255)
```csharp
    public override Empty AdjustIndexingFeePrice(AdjustIndexingFeeInput input)
    {
        var info = State.SideChainInfo[input.SideChainId];
        Assert(info != null && info.SideChainStatus != SideChainStatus.Terminated,
            "Side chain not found or incorrect side chain status.");
        Assert(input.IndexingFee >= 0, "Invalid side chain fee price.");
        var expectedOrganizationAddress = info.IndexingFeeController.OwnerAddress;
        Assert(expectedOrganizationAddress == Context.Sender, "No permission.");
        info.IndexingPrice = input.IndexingFee;
        State.SideChainInfo[input.SideChainId] = info;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L119-122)
```csharp
        Assert(
            sideChainCreationRequest.IndexingPrice >= 0 &&
            sideChainCreationRequest.LockedTokenAmount >= sideChainCreationRequest.IndexingPrice,
            "Invalid chain creation request.");
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L657-673)
```csharp
    private AuthorityInfo CreateDefaultOrganizationForIndexingFeePriceManagement(Address sideChainCreator)
    {
        var createOrganizationInput =
            GenerateOrganizationInputForIndexingFeePrice(new List<Address>
            {
                sideChainCreator,
                GetCrossChainIndexingController().OwnerAddress
            });
        SetContractStateRequired(State.AssociationContract, SmartContractConstants.AssociationContractSystemName);
        State.AssociationContract.CreateOrganization.Send(createOrganizationInput);

        var controllerAddress = CalculateSideChainIndexingFeeControllerOrganizationAddress(createOrganizationInput);
        return new AuthorityInfo
        {
            ContractAddress = State.AssociationContract.Value,
            OwnerAddress = controllerAddress
        };
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L842-855)
```csharp
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
```

**File:** protobuf/cross_chain_contract.proto (L189-199)
```text
enum SideChainStatus
{
    // Currently no meaning.
    FATAL = 0;
    // The side chain is being indexed.
    ACTIVE = 1;
    // The side chain is in debt for indexing fee.
    INDEXING_FEE_DEBT = 2;
    // The side chain is disposed.
    TERMINATED = 3;
}
```

**File:** test/AElf.Contracts.CrossChain.Tests/CrossChainIndexingActionTest.cs (L398-408)
```csharp
            await DoIndexAsync(crossChainBlockData, new[] { sideChainId });
            var chainStatus = await GetSideChainStatusAsync(sideChainId);
            chainStatus.ShouldBe(SideChainStatus.IndexingFeeDebt);

            (await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallWithExceptionAsync(new Int32Value
                { Value = 0 })).Value.ShouldContain("Side chain not found.");

            var debt = await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallAsync(new Int32Value
                { Value = sideChainId });
            debt.Value.ShouldBe(1);
        }
```
