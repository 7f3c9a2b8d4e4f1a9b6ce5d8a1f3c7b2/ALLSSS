# Audit Report

## Title
Resource Token Debt Accumulates Indefinitely Without Repayment Mechanism, Causing Eventual Overflow

## Summary
The `PayResourceTokens()` function in the MultiToken contract accumulates resource token debt in the `OwningResourceToken` state when contracts have insufficient balance, but provides no mechanism to repay or clear this debt. This violates accounting integrity and will eventually cause overflow exceptions in the `DonateResourceToken` system transaction, potentially disrupting block production.

## Finding Description

The vulnerability exists in the debt tracking mechanism for resource tokens. When `PayResourceTokens()` is called and a contract has insufficient balance to pay resource fees, the shortfall is recorded as debt in `OwningResourceToken` state. [1](#0-0) 

However, this debt is never cleared even when contracts later have sufficient balance. A comprehensive search confirms that this is the only location where `OwningResourceToken` is modified in all contract files, and it only performs addition operations. [2](#0-1) 

The `CheckResourceToken()` function verifies that balance exceeds debt but does not reduce the accumulated debt. [3](#0-2) 

This contrasts sharply with the similar `PayRental()` function, which implements proper debt repayment logic. The `PayRental()` function explicitly clears debt when sufficient balance exists, demonstrating the expected pattern that `PayResourceTokens()` fails to implement. [4](#0-3) 

The `.Add()` operation uses checked arithmetic that throws `OverflowException` when overflow occurs. [5](#0-4)  This is confirmed by test cases. [6](#0-5) 

The `DonateResourceToken()` method is executed as a system transaction at the end of each block [7](#0-6)  and calls `PayResourceTokens()`. [8](#0-7) 

## Impact Explanation

**Immediate Impact - Accounting Integrity**: Once debt accumulates for any contract, it never clears even when the contract has sufficient balance. This makes the debt tracking system meaningless and prevents accurate resource accounting across the chain.

**Long-term Impact - System DoS**: When accumulated debt exceeds `long.MaxValue`, the `Add()` operation will throw an `OverflowException`. Since this occurs in `DonateResourceToken`, a system transaction generated automatically for each block, the failure could disrupt block production and consensus operations.

**Affected Parties**:
- Any contract consuming resource tokens without maintaining sufficient balance
- The entire chain when overflow causes system transaction failures
- Node operators attempting to produce blocks

## Likelihood Explanation

**Attacker Capabilities**: Any contract that consumes resource tokens (CPU, RAM, DISK, NET) can contribute to debt accumulation by operating without sufficient balance. No special privileges are required.

**Attack Complexity**: Low - debt accumulates passively through normal resource consumption when balance is insufficient.

**Timeline**: For tokens with 8 decimals (like ELF), reaching `long.MaxValue` (~9.22 quintillion) requires accumulating approximately 92 billion tokens worth of debt. At 1,000 tokens per block, this requires ~92 million blocks (~11.6 years at 4-second block times). However, multiple contracts and symbols can accelerate accumulation.

**Probability**: Low-to-Medium. While overflow may take years, the accounting integrity violation occurs immediately and permanently for any contract that incurs debt.

## Recommendation

Implement debt repayment logic in `PayResourceTokens()` similar to the pattern used in `PayRental()`. When a contract has sufficient balance to cover accumulated debt, clear the debt before charging new resource fees:

```csharp
private void PayResourceTokens(TotalResourceTokensMaps billMaps, bool isMainChain)
{
    foreach (var bill in billMaps.Value)
    {
        foreach (var feeMap in bill.TokensMap.Value)
        {
            var symbol = feeMap.Key;
            var amount = feeMap.Value;
            var existingBalance = GetBalance(bill.ContractAddress, symbol);
            
            // NEW: Try to clear existing debt first
            var owingResourceToken = State.OwningResourceToken[bill.ContractAddress][symbol];
            if (owingResourceToken > 0)
            {
                if (existingBalance > owingResourceToken)
                {
                    // Clear debt and update available balance
                    amount = amount.Add(owingResourceToken);
                    existingBalance = existingBalance.Sub(owingResourceToken);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = 0;
                }
            }
            
            // Existing logic continues...
            if (amount > existingBalance)
            {
                var owned = amount.Sub(existingBalance);
                var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
                // ...
            }
            // ...
        }
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated by deploying a contract that consumes resources with insufficient balance, observing debt accumulation in `OwningResourceToken`, then adding sufficient balance and verifying the debt never clears in subsequent `DonateResourceToken` calls. The debt will continue accumulating monotonically across multiple blocks until eventually reaching overflow conditions.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L602-614)
```csharp
    public override Empty CheckResourceToken(Empty input)
    {
        AssertTransactionGeneratedByPlugin();
        foreach (var symbol in Context.Variables.GetStringArray(TokenContractConstants.PayTxFeeSymbolListName))
        {
            var balance = GetBalance(Context.Sender, symbol);
            var owningBalance = State.OwningResourceToken[Context.Sender][symbol];
            Assert(balance > owningBalance,
                $"Contract balance of {symbol} token is not enough. Owning {owningBalance}.");
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L945-945)
```csharp
        PayResourceTokens(input, isMainChain);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L968-982)
```csharp
                // Check balance in case of insufficient balance.
                var existingBalance = GetBalance(bill.ContractAddress, symbol);
                if (amount > existingBalance)
                {
                    var owned = amount.Sub(existingBalance);
                    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
                    Context.Fire(new ResourceTokenOwned
                    {
                        Symbol = symbol,
                        Amount = currentOwning,
                        ContractAddress = bill.ContractAddress
                    });
                    amount = existingBalance;
                }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1047-1058)
```csharp
            var owningRental = State.OwningRental[symbol];
            if (owningRental > 0)
            {
                // If Creator own this symbol and current balance can cover the debt, pay the debt at first.
                if (availableBalance > owningRental)
                {
                    donates = owningRental;
                    // Need to update available balance,
                    // cause existing balance not necessary equals to available balance.
                    availableBalance = availableBalance.Sub(owningRental);
                    State.OwningRental[symbol] = 0;
                }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L29-32)
```csharp
    /// <summary>
    ///     Contract Address -> (Owning) Resource Token Symbol -> Amount.
    /// </summary>
    public MappedState<Address, string, long> OwningResourceToken { get; set; }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L100-106)
```csharp
    public static long Add(this long a, long b)
    {
        checked
        {
            return a + b;
        }
    }
```

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L63-66)
```csharp
        number1.Add(5).ShouldBe(11UL);
        number2.Add(5).ShouldBe(11L);
        Should.Throw<OverflowException>(() => { long.MaxValue.Add(8); });
        Should.Throw<OverflowException>(() => { ulong.MaxValue.Add(8); });
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/DonateResourceTransactionGenerator.cs (L13-13)
```csharp
internal class DonateResourceTransactionGenerator : ISystemTransactionGenerator
```
