# Audit Report

## Title
Side Chain Disposal Returns Funds to Proposer Without Paying Indexer Debt

## Summary
The `DisposeSideChain()` method fails to settle outstanding indexing fee arrears before returning deposited tokens to the side chain proposer. When a side chain is disposed while having debt recorded in `ArrearsInfo`, indexers who provided services lose their earned fees while the proposer improperly recovers funds that should have been used to pay creditors.

## Finding Description

The vulnerability exists in the side chain disposal flow where debt settlement is completely bypassed.

**Primary Vulnerability - Missing Debt Settlement:**

When `DisposeSideChain()` is called, it performs authority validation and status checks, then immediately calls `UnlockTokenAndResource()` without any debt verification. [1](#0-0) 

The `UnlockTokenAndResource()` function retrieves the full deposit balance and transfers it entirely to the proposer, with zero checks for the `ArrearsInfo` field that tracks debt owed to indexers. [2](#0-1) 

**Debt Accumulation Mechanism:**

During indexing operations, when the deposit balance becomes insufficient to pay indexing fees, the contract continues to allow indexing but records unpaid amounts in `ArrearsInfo` (a map of creditor addresses to owed amounts) and changes the chain status to `IndexingFeeDebt`. [3](#0-2) 

The `ArrearsInfo` field is defined in the `SideChainInfo` protobuf message as a map tracking creditors and their owed amounts. [4](#0-3) 

**Correct Pattern Exists in Recharge():**

The `Recharge()` method demonstrates the correct approach: it explicitly checks for `IndexingFeeDebt` status, iterates through `ArrearsInfo` to pay all creditors first, clears the debt map, and only then resumes normal operations. [5](#0-4) 

This proves the development team was aware of the debt mechanism but failed to apply the same settlement logic to the disposal flow.

**Misleading Balance Information:**

The `GetSideChainBalance()` view function returns only the gross deposit amount without subtracting debt. [6](#0-5) 

While `GetSideChainIndexingFeeDebt()` separately returns the total arrears, governance making disposal decisions may not realize they need to check both functions to understand the true financial position. [7](#0-6) 

## Impact Explanation

**Direct Financial Loss:**
- Indexers who performed cross-chain block indexing services during periods of insufficient deposit receive no payment for their work
- This represents direct theft of earned fees from legitimate service providers
- The proposer recovers deposited funds that should have been allocated to pay outstanding debt

**Economic Impact Magnitude:**
- Amount at risk: minimum of (remaining deposit balance, total arrears owed)
- In scenarios where partial recharge occurred but disposal happens before full settlement, indexers lose the entire arrears amount
- Creates perverse incentive where proposers can accumulate debt and dispose chains to recover deposits

**Protocol Integrity:**
- Violates the fundamental economic guarantee that indexing services will be compensated
- Undermines trust in the cross-chain indexing incentive mechanism
- Severity: **HIGH** - Direct misallocation of funds from creditors to debtor

## Likelihood Explanation

**Trigger Mechanism:**
`DisposeSideChain()` is publicly accessible via governance (SideChainLifetimeController, typically Parliament organization), making it a routine operational function.

**Preconditions (All Realistic):**
1. Side chain accumulates indexing fee debt through normal operation (indexing beyond available deposit)
2. Chain retains some balance (from partial recharge, initial deposit remainder, or direct transfers)
3. Governance approves disposal proposal (standard chain lifecycle management)

**Exploitation Scenarios:**

*Accidental (Most Likely):* During routine chain lifecycle management, governance may approve disposal of inactive or problematic side chains without realizing unpaid debt exists. Since `GetSideChainBalance()` shows gross balance and debt checking requires a separate query, the issue may go unnoticed.

*Intentional:* A malicious proposer could create a side chain with minimal deposit, allow indexing to accumulate substantial debt, partially recharge to maintain some balance, then lobby for disposal to recover funds while leaving indexers unpaid.

**Attack Complexity:**
- Low - The vulnerability triggers automatically in the disposal logic
- Requires only standard governance approval, no sophisticated techniques
- No need to bypass security controls, as the controls are simply absent

**Detection Difficulty:**
- High - `ArrearsInfo` data exists in contract state but is not validated during disposal
- Governance would need to manually query `GetSideChainIndexingFeeDebt()` before each disposal decision
- No on-chain warnings or validation alerts governance to the debt situation

**Likelihood Assessment:** MEDIUM-HIGH - While requiring governance approval (reducing purely malicious likelihood), the lack of on-chain validation and the misleading nature of the balance view function make accidental occurrences highly probable during routine operations.

## Recommendation

The `DisposeSideChain()` method should check for and settle any outstanding arrears before unlocking tokens, following the same pattern used in `Recharge()`:

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

    // NEW: Settle arrears before unlocking
    if (info.SideChainStatus == SideChainStatus.IndexingFeeDebt && info.ArrearsInfo.Count > 0)
    {
        var balance = GetSideChainIndexingFeeDeposit(chainId);
        foreach (var arrears in info.ArrearsInfo)
        {
            var amountToPay = System.Math.Min(arrears.Value, balance);
            if (amountToPay > 0)
            {
                TransferDepositToken(new TransferInput
                {
                    To = Address.Parser.ParseFrom(ByteString.FromBase64(arrears.Key)),
                    Symbol = Context.Variables.NativeSymbol,
                    Amount = amountToPay,
                    Memo = "Arrears settlement on disposal."
                }, chainId);
                balance -= amountToPay;
            }
        }
        info.ArrearsInfo.Clear();
    }

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

Alternatively, add a validation to prevent disposal when arrears exist, forcing recharge first:

```csharp
Assert(info.ArrearsInfo.Count == 0 || GetSideChainIndexingFeeDeposit(chainId) == 0, 
    "Cannot dispose side chain with outstanding arrears. Recharge to settle debt first.");
```

## Proof of Concept

```csharp
[Fact]
public async Task DisposeSideChain_WithArrears_ProposerReceivesFundsCreditorLoses()
{
    // Setup: Create side chain with minimal balance
    var lockedToken = 2L;
    var indexingPrice = 1L;
    var sideChainId = await InitAndCreateSideChainAsync(10, 123, lockedToken, indexingPrice);
    
    // Index blocks to consume initial balance
    var blockData1 = CreateSideChainBlockData(HashHelper.ComputeFrom("hash1"), 1, sideChainId, HashHelper.ComputeFrom("root1"));
    var blockData2 = CreateSideChainBlockData(HashHelper.ComputeFrom("hash2"), 2, sideChainId, HashHelper.ComputeFrom("root2"));
    await DoIndexAsync(new CrossChainBlockData { SideChainBlockDataList = { blockData1, blockData2 } }, new[] { sideChainId });
    
    // Balance is now 0, index one more block to create debt
    var blockData3 = CreateSideChainBlockData(HashHelper.ComputeFrom("hash3"), 3, sideChainId, HashHelper.ComputeFrom("root3"));
    await DoIndexAsync(new CrossChainBlockData { SideChainBlockDataList = { blockData3 } }, new[] { sideChainId });
    
    // Verify debt status
    var status = await GetSideChainStatusAsync(sideChainId);
    status.ShouldBe(SideChainStatus.IndexingFeeDebt);
    var debt = await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallAsync(new Int32Value { Value = sideChainId });
    debt.Value.ShouldBe(1L); // 1 token of debt
    
    // Partial recharge - gives proposer some balance back but not enough to cover debt
    await ApproveBalanceAsync(1);
    await CrossChainContractStub.Recharge.SendAsync(new RechargeInput { ChainId = sideChainId, Amount = 1 });
    var balance = await GetSideChainBalanceAsync(sideChainId);
    balance.ShouldBe(0L); // Debt paid, no remaining balance
    
    // Recharge again to create scenario: balance exists, but so does debt from future indexing
    await ApproveBalanceAsync(2);
    await CrossChainContractStub.Recharge.SendAsync(new RechargeInput { ChainId = sideChainId, Amount = 2 });
    
    // Index to create debt again
    var blockData4 = CreateSideChainBlockData(HashHelper.ComputeFrom("hash4"), 4, sideChainId, HashHelper.ComputeFrom("root4"));
    var blockData5 = CreateSideChainBlockData(HashHelper.ComputeFrom("hash5"), 5, sideChainId, HashHelper.ComputeFrom("root5"));
    var blockData6 = CreateSideChainBlockData(HashHelper.ComputeFrom("hash6"), 6, sideChainId, HashHelper.ComputeFrom("root6"));
    await DoIndexAsync(new CrossChainBlockData { SideChainBlockDataList = { blockData4, blockData5, blockData6 } }, new[] { sideChainId });
    
    // Now: balance = 0, debt = 1 token owed to indexer
    status = await GetSideChainStatusAsync(sideChainId);
    status.ShouldBe(SideChainStatus.IndexingFeeDebt);
    debt = await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallAsync(new Int32Value { Value = sideChainId });
    debt.Value.ShouldBe(1L);
    
    // Add some balance without settling debt fully
    await ApproveBalanceAsync(5);
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(sideChainId)),
        Amount = 5,
        Symbol = "ELF"
    });
    
    balance = await GetSideChainBalanceAsync(sideChainId);
    balance.ShouldBe(5L); // Balance exists
    debt = await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallAsync(new Int32Value { Value = sideChainId });
    debt.Value.ShouldBe(1L); // Debt still exists
    
    // Get proposer balance before disposal
    var proposer = await CrossChainContractStub.GetSideChainCreator.CallAsync(new Int32Value { Value = sideChainId });
    var proposerBalanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput { Owner = proposer, Symbol = "ELF" })).Balance;
    
    // Dispose the chain
    var disposalProposalId = await DisposeSideChainProposalAsync(new Int32Value { Value = sideChainId });
    await ApproveWithMinersAsync(disposalProposalId);
    await ReleaseProposalAsync(disposalProposalId);
    
    // Verify proposer received full balance
    var proposerBalanceAfter = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput { Owner = proposer, Symbol = "ELF" })).Balance;
    var proposerReceived = proposerBalanceAfter - proposerBalanceBefore;
    proposerReceived.ShouldBe(5L); // Proposer got all 5 tokens
    
    // VULNERABILITY: Indexer never received the 1 token debt payment
    // The 5 tokens should have been: 1 to indexer (debt), 4 to proposer
    // Instead: 0 to indexer, 5 to proposer
}
```

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L191-211)
```csharp
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L844-876)
```csharp
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

**File:** protobuf/cross_chain_contract.proto (L216-217)
```text
    // creditor and amounts for the chain indexing fee debt 
    map<string, int64> arrears_info = 8;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L81-87)
```csharp
    public override Int64Value GetSideChainBalance(Int32Value input)
    {
        var chainId = input.Value;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null, "Side chain not found.");
        return new Int64Value { Value = GetSideChainIndexingFeeDeposit(chainId) };
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
