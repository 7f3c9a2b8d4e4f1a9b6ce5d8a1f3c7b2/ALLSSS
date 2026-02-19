# Audit Report

## Title
Resource Token Debt Accumulates Indefinitely Without Repayment Mechanism, Causing Eventual Overflow

## Summary
The `PayResourceTokens()` function in the MultiToken contract accumulates resource token debt in the `OwningResourceToken` state when contracts have insufficient balance, but provides no mechanism to repay or clear this debt. This violates accounting integrity and will eventually cause overflow exceptions in the `DonateResourceToken` system transaction, potentially disrupting block production.

## Finding Description

The vulnerability exists in the debt tracking mechanism for resource tokens. When `PayResourceTokens()` is called and a contract has insufficient balance to pay resource fees, the shortfall is recorded as debt in `OwningResourceToken` state. [1](#0-0) 

However, this debt is never cleared even when contracts later have sufficient balance. A comprehensive search confirms that line 974 is the only location where `OwningResourceToken` is modified in all contract files, and it only performs addition operations.

The `CheckResourceToken()` function verifies that balance exceeds debt but does not reduce the accumulated debt. [2](#0-1) 

This contrasts sharply with the similar `PayRental()` function, which implements proper debt repayment logic. [3](#0-2)  The `PayRental()` function explicitly clears debt when sufficient balance exists (line 1057), demonstrating the expected pattern that `PayResourceTokens()` fails to implement.

The `.Add()` operation uses checked arithmetic that throws `OverflowException` when overflow occurs. [4](#0-3)  This is confirmed by test cases. [5](#0-4) 

The `DonateResourceToken()` method is executed as a system transaction at the end of each block and calls `PayResourceTokens()`. [6](#0-5) [7](#0-6) 

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

Implement debt repayment logic in `PayResourceTokens()` following the pattern used in `PayRental()`:

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
            
            // NEW: Try to repay existing debt first
            var owingBalance = State.OwningResourceToken[bill.ContractAddress][symbol];
            if (owingBalance > 0 && existingBalance > owingBalance)
            {
                // Clear the debt
                State.OwningResourceToken[bill.ContractAddress][symbol] = 0;
                existingBalance = existingBalance.Sub(owingBalance);
            }
            
            // Existing logic continues...
            if (amount > existingBalance)
            {
                var owned = amount.Sub(existingBalance);
                var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
                // ... rest of logic
            }
            // ... rest of function
        }
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploying a contract that consumes resource tokens
2. Allowing the contract to run with insufficient balance, causing debt accumulation
3. Funding the contract with sufficient balance
4. Observing that subsequent `PayResourceTokens()` calls do not clear the accumulated debt
5. Verifying that debt persists in `State.OwningResourceToken` despite adequate balance

The debt will accumulate indefinitely across all affected contracts until eventually causing overflow when the sum exceeds `long.MaxValue`.

## Notes

This vulnerability represents a clear inconsistency in the codebase - the `PayRental()` function properly implements debt repayment logic while `PayResourceTokens()` does not, despite serving similar purposes. The immediate impact is broken accounting integrity, while the long-term risk is eventual system transaction failure. The Medium severity rating is justified given the concrete DoS potential affecting critical system operations, though exploitation requires an extended timeline.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-945)
```csharp
    public override Empty DonateResourceToken(TotalResourceTokensMaps input)
    {
        AssertSenderIsCurrentMiner();
        var donateResourceTokenExecuteHeight = State.DonateResourceTokenExecuteHeight.Value;
        if (donateResourceTokenExecuteHeight == 0)
        {
            donateResourceTokenExecuteHeight = Context.CurrentHeight;
        }

        Assert(donateResourceTokenExecuteHeight == Context.CurrentHeight,
            $"This method already executed in height {State.DonateResourceTokenExecuteHeight.Value}");
        State.DonateResourceTokenExecuteHeight.Value = donateResourceTokenExecuteHeight.Add(1);
        Context.LogDebug(() => $"Start donate resource token. {input}");
        State.LatestTotalResourceTokensMapsHash.Value = HashHelper.ComputeFrom(input);
        Context.LogDebug(() =>
            $"Now LatestTotalResourceTokensMapsHash is {State.LatestTotalResourceTokensMapsHash.Value}");

        var isMainChain = true;
        if (State.DividendPoolContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            if (treasuryContractAddress == null)
            {
                isMainChain = false;
            }
            else
            {
                State.DividendPoolContract.Value = treasuryContractAddress;
            }
        }

        PayResourceTokens(input, isMainChain);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L970-974)
```csharp
                if (amount > existingBalance)
                {
                    var owned = amount.Sub(existingBalance);
                    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
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

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L65-65)
```csharp
        Should.Throw<OverflowException>(() => { long.MaxValue.Add(8); });
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/DonateResourceTransactionGenerator.cs (L60-71)
```csharp
        generatedTransactions.AddRange(new List<Transaction>
        {
            new()
            {
                From = from,
                MethodName = nameof(TokenContractImplContainer.TokenContractImplStub.DonateResourceToken),
                To = tokenContractAddress,
                RefBlockNumber = preBlockHeight,
                RefBlockPrefix = BlockHelper.GetRefBlockPrefix(preBlockHash),
                Params = input
            }
        });
```
