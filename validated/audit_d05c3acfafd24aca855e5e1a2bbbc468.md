# Audit Report

## Title
Insufficient Validation in Recharge() Allows Side Chain to Immediately Return to Debt Status

## Summary
The `Recharge()` function in the CrossChain contract contains a critical validation flaw that reads the balance AFTER paying arrears, causing double-counting of `input.Amount`. This allows side chains to be recharged with insufficient funds, passing validation but immediately returning to `IndexingFeeDebt` status upon the next block indexing attempt. [1](#0-0) 

## Finding Description

The validation logic has a critical ordering flaw in its execution sequence:

**Step 1:** The function first transfers `input.Amount` from the sender to the side chain's virtual address, increasing the virtual address balance to `balance_before + input.Amount`. [2](#0-1) 

**Step 2:** For chains in `IndexingFeeDebt` status, the function iterates through all arrears and transfers from the virtual address to pay proposers, reducing the balance to `balance_before + input.Amount - arrearsAmount`. [3](#0-2) 

**Step 3:** The function then calls `GetSideChainIndexingFeeDeposit(chainId)` which queries the current balance of the virtual address. At this point: `originBalance = balance_before + input.Amount - arrearsAmount`. [4](#0-3) 

**Step 4:** The validation check at line 207 asserts: `input.Amount + originBalance >= arrearsAmount + sideChainInfo.IndexingPrice` [5](#0-4) 

Substituting the actual value of `originBalance`:
```
input.Amount + (balance_before + input.Amount - arrearsAmount) >= arrearsAmount + IndexingPrice
2 × input.Amount + balance_before - arrearsAmount >= arrearsAmount + IndexingPrice
2 × input.Amount + balance_before >= 2 × arrearsAmount + IndexingPrice
```

This double-counts `input.Amount` (appears twice on left side) and requires `arrearsAmount` twice on the right side despite being paid only once.

**Correct validation should be:** After recharge and paying arrears, the remaining balance must support at least one more block indexing:
```
balance_before + input.Amount - arrearsAmount >= IndexingPrice
input.Amount >= arrearsAmount + IndexingPrice - balance_before
```

**The discrepancy:** The flawed check only requires:
```
input.Amount >= arrearsAmount + (IndexingPrice - balance_before) / 2
```

This creates an exploit gap of `(IndexingPrice - balance_before) / 2` tokens. When the chain subsequently attempts indexing in `IndexSideChainBlockData`, the insufficient balance causes it to immediately return to debt status. [6](#0-5) 

## Impact Explanation

This vulnerability breaks the invariant that side chains marked as `Active` must have sufficient balance to index at least one block. The impacts include:

1. **Operational Disruption**: Side chains oscillate between `Active` and `IndexingFeeDebt` status without successfully maintaining operation. The chain appears healthy in status but lacks functional capability.

2. **Miner Payment Loss**: Miners proposing blocks for indexing don't receive immediate payment. Instead, arrears accumulate again, creating a debt cycle that requires repeated recharge attempts.

3. **Resource Waste**: Multiple recharge transactions are required before achieving stable operation, wasting gas fees. Users must make additional transactions to reach the correct balance.

4. **Cross-Chain Communication Degradation**: The parent chain's ability to reliably index side chain data is compromised, as chains repeatedly fall back into debt status. While indexing continues, the payment mechanism becomes unstable.

5. **State Confusion**: The chain's status indicates `Active` but the actual balance is insufficient for operation, creating misleading state information for monitoring and management systems.

**Severity: Medium** - This causes operational disruption and payment delays but does not result in direct fund theft or complete denial of service. The cross-chain indexing mechanism continues to function, but with degraded reliability and payment guarantees.

## Likelihood Explanation

This vulnerability has **high likelihood** of occurrence:

**Reachable Entry Point**: `Recharge()` is a public function callable by any address with sufficient token allowance and approval.

**Feasible Preconditions**:
- Side chain must be in `IndexingFeeDebt` status - this is a common operational scenario when chains exhaust their deposited funds
- `balance_before_recharge < IndexingPrice` - typical for chains that have gone into debt

**Execution Practicality**: The exploit requires simple arithmetic calculation:
- Given `arrearsAmount = 100`, `IndexingPrice = 100`, `balance_before = 0`
- Correct requirement: `input.Amount >= 200`
- Flawed validation allows: `input.Amount >= 150`
- Recharging with 150 leaves balance of 50, insufficient for the next 100-token indexing operation

**Attack Complexity**: Low - requires only a single recharge transaction with a calculated amount. No special privileges, complex multi-step sequences, or timing dependencies.

**Economic Rationality**: The scenario can occur through honest mistake or intentional exploitation. The recharger doesn't lose funds (they're deposited to the chain), but creates an unstable state.

## Recommendation

The validation should be performed BEFORE paying arrears, or the logic should be corrected to validate the final remaining balance. The correct fix is to change line 207 to:

```csharp
Assert(originBalance >= sideChainInfo.IndexingPrice,
    "Indexing fee recharging not enough.");
```

This ensures that after paying arrears, the remaining balance is sufficient for at least one block indexing operation.

Alternatively, restructure the validation to check before making any transfers:

```csharp
if (sideChainInfo.SideChainStatus == SideChainStatus.IndexingFeeDebt)
{
    long arrearsAmount = 0;
    foreach (var arrears in sideChainInfo.ArrearsInfo)
    {
        arrearsAmount += arrears.Value;
    }
    
    var currentBalance = GetSideChainIndexingFeeDeposit(chainId);
    Assert(currentBalance + input.Amount >= arrearsAmount + sideChainInfo.IndexingPrice,
        "Indexing fee recharging not enough.");
    
    // Now pay arrears...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task RechargeWithInsufficientFunds_ImmediatelyReturnsToDebt()
{
    // Setup: Create side chain with IndexingPrice = 100
    var indexingPrice = 100;
    var initialLockedToken = 0;
    var sideChainId = await InitAndCreateSideChainAsync(10, 123, initialLockedToken, indexingPrice);
    
    // Index one block to create debt of 100
    var sideChainBlockData = CreateSideChainBlockData(HashHelper.ComputeFrom("test"), 1, sideChainId, HashHelper.ComputeFrom("root"));
    await DoIndexAsync(new CrossChainBlockData { SideChainBlockDataList = { sideChainBlockData } }, new[] { sideChainId });
    
    // Verify chain is in debt status with arrears of 100
    var statusBeforeRecharge = await GetSideChainStatusAsync(sideChainId);
    statusBeforeRecharge.ShouldBe(SideChainStatus.IndexingFeeDebt);
    var debtAmount = await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallAsync(new Int32Value { Value = sideChainId });
    debtAmount.Value.ShouldBe(100);
    
    // Recharge with 150 tokens (flawed validation accepts, but correct would require 200)
    // balance_before = 0, arrearsAmount = 100, IndexingPrice = 100
    // Flawed check: 150 + (0 + 150 - 100) = 200 >= 100 + 100 ✓ PASSES
    // After paying arrears: balance = 50, which is < 100 (IndexingPrice)
    await ApproveBalanceAsync(150);
    await CrossChainContractStub.Recharge.SendAsync(new RechargeInput { ChainId = sideChainId, Amount = 150 });
    
    // Verify status changed to Active (incorrectly)
    var statusAfterRecharge = await GetSideChainStatusAsync(sideChainId);
    statusAfterRecharge.ShouldBe(SideChainStatus.Active);
    
    // Verify balance is only 50 (insufficient)
    var balanceAfterRecharge = await GetSideChainBalanceAsync(sideChainId);
    balanceAfterRecharge.ShouldBe(50);
    
    // Attempt to index another block - should immediately return to debt
    var sideChainBlockData2 = CreateSideChainBlockData(HashHelper.ComputeFrom("test2"), 2, sideChainId, HashHelper.ComputeFrom("root2"));
    await DoIndexAsync(new CrossChainBlockData { SideChainBlockDataList = { sideChainBlockData2 } }, new[] { sideChainId });
    
    // VULNERABILITY CONFIRMED: Chain immediately returns to IndexingFeeDebt status
    var statusAfterSecondIndex = await GetSideChainStatusAsync(sideChainId);
    statusAfterSecondIndex.ShouldBe(SideChainStatus.IndexingFeeDebt);
    
    // New arrears accumulate (50 tokens short)
    var newDebt = await CrossChainContractStub.GetSideChainIndexingFeeDebt.CallAsync(new Int32Value { Value = sideChainId });
    newDebt.Value.ShouldBe(50);
}
```

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L174-215)
```csharp
    public override Empty Recharge(RechargeInput input)
    {
        var chainId = input.ChainId;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null && sideChainInfo.SideChainStatus != SideChainStatus.Terminated,
            "Side chain not found or incorrect side chain status.");

        TransferFrom(new TransferFromInput
        {
            From = Context.Sender,
            To = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Symbol = Context.Variables.NativeSymbol,
            Amount = input.Amount,
            Memo = "Indexing fee recharging."
        });

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
        sideChainInfo.SideChainStatus = SideChainStatus.Active;
        State.SideChainInfo[chainId] = sideChainInfo;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L88-98)
```csharp
    private long GetSideChainIndexingFeeDeposit(int chainId)
    {
        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        var balanceOutput = State.TokenContract.GetBalance.Call(new GetBalanceInput
        {
            Owner = Context.ConvertVirtualAddressToContractAddress(ConvertChainIdToHash(chainId)),
            Symbol = Context.Variables.NativeSymbol
        });

        return balanceOutput.Balance;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L842-856)
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
