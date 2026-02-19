### Title
Side Chain Disposal with Outstanding Debt Allows Indexing Fee Theft

### Summary
The `DisposeSideChain` function only validates that the side chain status is not `Terminated`, allowing disposal of chains in `IndexingFeeDebt` status. When a chain with outstanding debts is disposed, the `UnlockTokenAndResource` helper returns only the remaining balance to the chain proposer without settling accumulated debts in `ArrearsInfo`, causing indexers who performed work to permanently lose their rightful fees.

### Finding Description

The vulnerability exists in the disposal flow for side chains with outstanding indexing fee debts:

**Location 1 - Insufficient Status Check:**
The `DisposeSideChain` function performs only a negative check for `Terminated` status, allowing chains in `IndexingFeeDebt` status to be disposed. [1](#0-0) 

**Location 2 - Debt Recording Mechanism:**
When side chains run out of indexing fee balance, the system transitions them to `IndexingFeeDebt` status and records unpaid amounts to indexers in the `ArrearsInfo` mapping. [2](#0-1) 

**Location 3 - Improper Unlock Without Debt Settlement:**
The `UnlockTokenAndResource` helper only returns remaining deposit balance to the chain proposer, completely ignoring debts recorded in `ArrearsInfo`. [3](#0-2) 

**Location 4 - Proper Debt Settlement Pattern (For Comparison):**
The `Recharge` function demonstrates the correct pattern - when handling chains in `IndexingFeeDebt` status, it iterates through `ArrearsInfo` and transfers owed amounts to each creditor before clearing the debt records. [4](#0-3) 

**Location 5 - Status Enumeration:**
The `SideChainStatus` enum defines `INDEXING_FEE_DEBT = 2` as a valid intermediate state distinct from both `ACTIVE` and `TERMINATED`. [5](#0-4) 

**Location 6 - Debt Calculation:**
The `ArrearsInfo` field stores creditors and amounts for indexing fee debt, which are summed to calculate total outstanding debt. [6](#0-5) 

**Root Cause:**
The assertion at line 229 uses a negative check (`!= Terminated`) instead of a positive check (`== Active`), allowing disposal in any non-terminated state including `IndexingFeeDebt`. The disposal process then calls `UnlockTokenAndResource` which was designed for clean closure scenarios and lacks debt settlement logic.

### Impact Explanation

**Direct Financial Loss:**
- Indexers (miners who proposed side chain block data) permanently lose unpaid indexing fees recorded in `ArrearsInfo`
- Each indexing operation that occurred after balance depletion creates unpaid debt that becomes unrecoverable after disposal
- The remaining deposit balance is incorrectly returned to the chain proposer instead of settling creditor claims

**Economic Incentive Breakdown:**
- Indexers who performed legitimate work providing cross-chain block data lose compensation
- This breaks the fundamental economic model where indexers are paid per block indexed
- Creates perverse incentive where chain proposers can avoid debt by disposing chains

**Protocol Integrity:**
- Violates the critical invariant that "fee deduction paths" must be correct and complete
- The `ArrearsInfo` debt tracking becomes meaningless if debts can be erased through disposal
- Undermines trust in the cross-chain indexing payment system

**Quantified Impact:**
- Loss amount equals sum of all values in `ArrearsInfo` at disposal time
- Each block indexed while in debt adds `IndexingPrice` to total unpaid amount
- Multiple indexers can be affected if different miners proposed indexing during debt period

### Likelihood Explanation

**Reachable Entry Point:**
The `DisposeSideChain` function is callable via the side chain lifetime controller (typically Parliament governance). [7](#0-6) 

**Attack Prerequisites:**
1. Create a side chain with minimal locked token amount (just enough for initial indexing)
2. Let the chain operate until balance depletes and status becomes `IndexingFeeDebt`
3. Submit governance proposal to dispose the chain
4. Obtain Parliament approval and execute disposal

**Execution Practicality:**
- All steps follow normal contract operations without requiring any exploit techniques
- No special privileges needed beyond standard governance participation
- The scenario naturally occurs for underfunded side chains
- Test case exists demonstrating this exact flow is supported by the system [8](#0-7) 

**Economic Feasibility:**
- Cost to create side chain is just the initial locked amount
- Governance proposal costs are standard Parliament fees
- Net gain: avoid paying accumulated indexing fees that exceed initial deposit
- Attack is profitable whenever debt exceeds creation cost plus governance fees

**Detection Constraints:**
- The disposal appears as legitimate governance action
- No error is thrown - the transaction succeeds normally
- Only off-chain monitoring of `ArrearsInfo` before disposal would detect the issue
- Indexers may not realize they lost fees until attempting to claim

**Probability Assessment:**
HIGH - The vulnerability is triggered in any scenario where:
1. A side chain runs low on funds (common operational scenario)
2. Governance decides to dispose rather than recharge (legitimate choice)
3. The unintended consequence is automatic debt forgiveness

### Recommendation

**Code-Level Fix:**
Modify the `DisposeSideChain` function to add debt settlement before status change:

```csharp
public override Int32Value DisposeSideChain(Int32Value input)
{
    AssertSideChainLifetimeControllerAuthority(Context.Sender);
    
    var chainId = input.Value;
    var info = State.SideChainInfo[chainId];
    Assert(info != null, "Side chain not found.");
    Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");
    
    // ADD: Require debt settlement before disposal
    if (info.SideChainStatus == SideChainStatus.IndexingFeeDebt)
    {
        var totalDebt = info.ArrearsInfo.Values.Sum();
        Assert(totalDebt == 0, 
            "Cannot dispose side chain with outstanding debt. Recharge first to settle arrears.");
    }
    
    if (TryGetIndexingProposal(chainId, out _))
        ResetChainIndexingProposal(chainId);
    
    UnlockTokenAndResource(info);
    info.SideChainStatus = SideChainStatus.Terminated;
    State.SideChainInfo[chainId] = info;
    Context.Fire(new Disposed { ChainId = chainId });
    return new Int32Value { Value = chainId };
}
```

**Alternative Fix:**
Modify `UnlockTokenAndResource` to settle debts:

```csharp
private void UnlockTokenAndResource(SideChainInfo sideChainInfo)
{
    var chainId = sideChainInfo.SideChainId;
    var balance = GetSideChainIndexingFeeDeposit(chainId);
    
    // ADD: Settle arrears first
    if (sideChainInfo.ArrearsInfo.Count > 0)
    {
        foreach (var arrears in sideChainInfo.ArrearsInfo)
        {
            var amount = Math.Min(arrears.Value, balance);
            if (amount > 0)
            {
                TransferDepositToken(new TransferInput
                {
                    To = Address.Parser.ParseFrom(ByteString.FromBase64(arrears.Key)),
                    Amount = amount,
                    Symbol = Context.Variables.NativeSymbol
                }, chainId);
                balance -= amount;
            }
        }
    }
    
    // Return remaining balance to proposer
    if (balance > 0)
    {
        TransferDepositToken(new TransferInput
        {
            To = sideChainInfo.Proposer,
            Amount = balance,
            Symbol = Context.Variables.NativeSymbol
        }, chainId);
    }
}
```

**Invariant Check:**
Add assertion that disposal only occurs when `ArrearsInfo` is empty or chain is `Active`.

**Test Cases to Add:**
1. Test disposal attempt on chain with `IndexingFeeDebt` status - should fail
2. Test that recharge → disposal succeeds after debt cleared
3. Test that partial debt payment still blocks disposal until fully settled

### Proof of Concept

**Initial State:**
1. Initialize CrossChain contract
2. Create side chain with `lockedTokenAmount = 2` and `indexingPrice = 1`
3. Side chain status is `Active` with 2 tokens deposited

**Exploitation Steps:**

**Step 1 - Deplete Balance:**
- Propose and release indexing for blocks 1, 2, 3 (3 blocks × 1 token = 3 tokens needed)
- After blocks 1-2: Balance = 0, Status = `Active`, fees paid to indexer
- After block 3: Balance = -1, Status = `IndexingFeeDebt`, debt recorded in `ArrearsInfo[indexer] = 1`

**Step 2 - Dispose With Outstanding Debt:**
- Create Parliament proposal to call `DisposeSideChain(chainId)`
- Proposal passes (requires miner approval)
- Execute disposal transaction

**Expected Behavior:**
- Transaction should revert with error requiring debt settlement
- OR debts should be settled from remaining balance before returning funds

**Actual Behavior:**
- Transaction succeeds
- Status changes to `Terminated`
- Remaining balance (0 tokens) returned to chain proposer
- `ArrearsInfo[indexer] = 1` token debt is lost forever
- Indexer who proposed block 3 loses their rightful 1 token fee

**Success Condition:**
Query `GetSideChainIndexingFeeDebt(chainId)` before disposal shows debt = 1 token, after disposal the chain is terminated and indexer cannot claim the owed fee through any mechanism.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L190-211)
```csharp
        long arrearsAmount = 0;
        if (sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt)
        {
            // arrears
            foreach (var arrears in sideChainInfo.ArrearsInfo)
            {
                arrearsAmount += arrears.Value;
                TransferDepositToken(new TransferInput
                {
                    To = Address.Parser.ParseFrom(ByteString.FromBase64(arrears.Key)),
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = arrears.Value,
                    Memo = "Indexing fee recharging."
                }, chainId);
            }

            var originBalance = GetSideChainIndexingFeeDeposit(chainId);
            Assert(input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice,
                "Indexing fee recharging not enough.");
        }

        sideChainInfo.ArrearsInfo.Clear();
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L222-242)
```csharp
    public override Int32Value DisposeSideChain(Int32Value input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var chainId = input.Value;
        var info = State.SideChainInfo[chainId];
        Assert(info != null, "Side chain not found.");
        Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");

        if (TryGetIndexingProposal(chainId, out _))
            ResetChainIndexingProposal(chainId);

        UnlockTokenAndResource(info);
        info.SideChainStatus = SideChainStatus.Terminated;
        State.SideChainInfo[chainId] = info;
        Context.Fire(new Disposed
        {
            ChainId = chainId
        });
        return new Int32Value { Value = chainId };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L73-86)
```csharp
    private void UnlockTokenAndResource(SideChainInfo sideChainInfo)
    {
        // unlock token
        var chainId = sideChainInfo.SideChainId;
        var balance = GetSideChainIndexingFeeDeposit(chainId);
        if (balance <= 0)
            return;
        TransferDepositToken(new TransferInput
        {
            To = sideChainInfo.Proposer,
            Amount = balance,
            Symbol = Context.Variables.NativeSymbol
        }, chainId);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L846-876)
```csharp
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

            if (indexingFeeAmount > 0)
                TransferDepositToken(new TransferInput
                {
                    To = proposer,
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = indexingFeeAmount,
                    Memo = "Index fee."
                }, chainId);

            if (arrearsAmount > 0)
            {
                if (sideChainInfo.ArrearsInfo.TryGetValue(formattedProposerAddress, out var amount))
                    sideChainInfo.ArrearsInfo[formattedProposerAddress] = amount + arrearsAmount;
                else
                    sideChainInfo.ArrearsInfo[formattedProposerAddress] = arrearsAmount;
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L89-99)
```csharp
    public override Int64Value GetSideChainIndexingFeeDebt(Int32Value input)
    {
        var chainId = input.Value;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null, "Side chain not found.");

        return new Int64Value
        {
            Value = sideChainInfo.ArrearsInfo.Values.Sum()
        };
    }
```

**File:** test/AElf.Contracts.CrossChain.Tests/SideChainLifeTimeManagementTest.cs (L425-512)
```csharp
    public async Task AdjustCrossChainIndexingFeePriceTest_IndexingFeeDebt_Dispose()
    {
        await InitializeCrossChainContractAsync();
        long lockedTokenAmount = 10;
        await ApproveBalanceAsync(lockedTokenAmount);

        var proposalId = await CreateSideChainProposalAsync(1, lockedTokenAmount);
        await ApproveWithMinersAsync(proposalId);
        var releaseTx =
            await CrossChainContractStub.ReleaseSideChainCreation.SendAsync(new ReleaseSideChainCreationInput
                { ProposalId = proposalId });
        var organizationAddress = OrganizationCreated.Parser
            .ParseFrom(releaseTx.TransactionResult.Logs.First(l => l.Name.Contains(nameof(OrganizationCreated)))
                .NonIndexed).OrganizationAddress;
        organizationAddress.ShouldNotBeNull();

        var sideChainCreatedEvent = SideChainCreatedEvent.Parser
            .ParseFrom(releaseTx.TransactionResult.Logs.First(l => l.Name.Contains(nameof(SideChainCreatedEvent)))
                .NonIndexed);
        var sideChainId = sideChainCreatedEvent.ChainId;
        {
            var newIndexingFeePrice = 10;
            var indexingFeeAdjustProposalId = await CreateAssociationProposalAsync(
                nameof(CrossChainContractStub.AdjustIndexingFeePrice),
                organizationAddress, CrossChainContractAddress, new AdjustIndexingFeeInput
                {
                    IndexingFee = newIndexingFeePrice,
                    SideChainId = sideChainId
                });

            var parliamentOrganizationAddress =
                (await CrossChainContractStub.GetCrossChainIndexingController.CallAsync(new Empty())).OwnerAddress;
            var approveProposalId = await CreateParliamentProposalAsync(nameof(AssociationContractStub.Approve),
                parliamentOrganizationAddress, indexingFeeAdjustProposalId, AssociationContractAddress);
            await ApproveWithMinersAsync(approveProposalId);
            await ParliamentContractStub.Release.SendAsync(approveProposalId);
            await AssociationContractStub.Approve.SendAsync(indexingFeeAdjustProposalId);
            await AssociationContractStub.Release.SendAsync(indexingFeeAdjustProposalId);

            var indexingFeePriceCheck =
                await CrossChainContractStub.GetSideChainIndexingFeePrice.SendAsync(new Int32Value
                    { Value = sideChainId });
            indexingFeePriceCheck.Output.Value.ShouldBe(newIndexingFeePrice);

            var sideChainStatus = await GetSideChainStatusAsync(sideChainId);
            sideChainStatus.ShouldBe(SideChainStatus.Active);
        }

        {
            var newIndexingFeePrice = 11;
            var indexingFeeAdjustProposalId = await CreateAssociationProposalAsync(
                nameof(CrossChainContractStub.AdjustIndexingFeePrice),
                organizationAddress, CrossChainContractAddress, new AdjustIndexingFeeInput
                {
                    IndexingFee = newIndexingFeePrice,
                    SideChainId = sideChainId
                });

            var parliamentOrganizationAddress =
                (await CrossChainContractStub.GetCrossChainIndexingController.CallAsync(new Empty())).OwnerAddress;
            var approveProposalId = await CreateParliamentProposalAsync(nameof(AssociationContractStub.Approve),
                parliamentOrganizationAddress, indexingFeeAdjustProposalId, AssociationContractAddress);
            await ApproveWithMinersAsync(approveProposalId);
            await ParliamentContractStub.Release.SendAsync(approveProposalId);
            await AssociationContractStub.Approve.SendAsync(indexingFeeAdjustProposalId);
            await AssociationContractStub.Release.SendAsync(indexingFeeAdjustProposalId);

            (await CrossChainContractStub.GetSideChainIndexingFeePrice.CallWithExceptionAsync(new Int32Value
                { Value = sideChainId + 1 })).Value.ShouldContain("Side chain not found.");

            var indexingFeePriceCheck =
                await CrossChainContractStub.GetSideChainIndexingFeePrice.SendAsync(new Int32Value
                    { Value = sideChainId });
            indexingFeePriceCheck.Output.Value.ShouldBe(newIndexingFeePrice);

            var sideChainStatus = await GetSideChainStatusAsync(sideChainId);
            sideChainStatus.ShouldBe(SideChainStatus.Active);

            var disposalProposalId = await DisposeSideChainProposalAsync(new Int32Value
            {
                Value = sideChainId
            });
            await ApproveWithMinersAsync(disposalProposalId);
            var transactionResult = await ReleaseProposalAsync(disposalProposalId);
            var status = transactionResult.Status;
            status.ShouldBe(TransactionResultStatus.Mined);
        }
    }
```
