# Audit Report

## Title
Resource Token Debt Accumulates Indefinitely Without Repayment Mechanism, Causing Eventual Overflow

## Summary
The `PayResourceTokens()` function accumulates resource token debt in `OwningResourceToken` state when contracts have insufficient balance, but unlike the similar `OwningRental` system, provides no mechanism to repay or clear this debt. This causes unbounded debt accumulation that will eventually exceed `long.MaxValue`, triggering an overflow exception in the system transaction `DonateResourceToken` and potentially disrupting block production.

## Finding Description

The vulnerability exists in the `PayResourceTokens()` function where debt accumulation occurs without any corresponding repayment logic. When a contract consumes resource tokens but has insufficient balance, the code calculates the shortfall and adds it to existing debt [1](#0-0) .

The system only ever adds to `OwningResourceToken` debt - a codebase-wide grep search confirms that line 974 is the only location where this state variable is assigned, and it exclusively performs addition operations. The `CheckResourceToken()` function only verifies that balance exceeds debt but does not reduce the accumulated debt [2](#0-1) .

This contrasts sharply with the `PayRental()` function, which implements proper debt repayment for the similar `OwningRental` system [3](#0-2) . The `PayRental` implementation explicitly clears debt when sufficient balance exists, demonstrating the expected pattern that `PayResourceTokens()` fails to implement.

The `.Add()` operation uses checked arithmetic for overflow detection [4](#0-3) , meaning when debt accumulation exceeds `long.MaxValue`, the operation will throw an `OverflowException` rather than silently wrapping around.

The execution path involves `DonateResourceToken()` being called as a system transaction at the end of each block [5](#0-4) , which then invokes `PayResourceTokens()` [6](#0-5) .

## Impact Explanation

When the accumulated debt exceeds `long.MaxValue`, the overflow exception will cause the `DonateResourceToken` system transaction to fail. Since this transaction is generated automatically at the end of each block as part of the resource fee collection mechanism, its failure could disrupt block production and consensus operations.

Once debt begins accumulating, it never clears even when contracts have sufficient balance. This violates the expected invariant that debts should be repayable, making the debt tracking system meaningless and preventing accurate resource accounting.

The affected parties include:
- Contracts that consume resources without maintaining sufficient balances
- The entire chain when overflow causes system transaction failures
- Node operators attempting to produce blocks

This represents a Medium severity issue due to concrete DoS potential affecting critical system operations, though exploitation requires an extended timeline.

## Likelihood Explanation

Any contract that consumes resource tokens can contribute to debt accumulation simply by operating without sufficient balance. No special privileges are required - this is passive accumulation through normal resource consumption when balance is insufficient.

For a token with 8 decimals (like ELF), reaching overflow requires accumulating approximately 92 billion tokens worth of debt. At 1,000 tokens per block, this would require approximately 92 million blocks (roughly 11.6 years at 4 seconds per block). However, contracts with higher consumption rates or multiple tokens accumulating debt simultaneously could accelerate this timeline.

The probability is Low-to-Medium. While normal operations are unlikely to reach overflow quickly, the complete lack of any repayment mechanism means ANY debt accumulation is permanent and will eventually cause issues over sufficient time.

## Recommendation

Implement debt repayment logic in `PayResourceTokens()` similar to the pattern used in `PayRental()`. When a contract has sufficient balance and outstanding debt exists, the function should:

1. Check if `State.OwningResourceToken[bill.ContractAddress][symbol] > 0`
2. If the contract's current balance can cover the debt, deduct the debt amount from the balance
3. Clear the debt by setting `State.OwningResourceToken[bill.ContractAddress][symbol] = 0`
4. Then proceed with normal resource token payment for the current period

This would ensure that debts are eventually repaid when contracts regain sufficient balance, preventing unbounded accumulation and maintaining accounting integrity.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploy a contract that consumes resource tokens
2. Ensure the contract has insufficient balance for resource token payments
3. Observe `ResourceTokenOwned` events showing debt accumulation in `OwningResourceToken`
4. Add balance to the contract
5. Observe that debt remains unchanged - `CheckResourceToken()` only validates but doesn't clear debt
6. Continue this pattern across multiple blocks/contracts until debt approaches `long.MaxValue`
7. The system will eventually throw `OverflowException` when `.Add()` operation exceeds the maximum value

The core issue is structural: there exists no code path in the entire codebase that reduces `State.OwningResourceToken` values once they are incremented, making eventual overflow mathematically inevitable given sufficient time and resource consumption.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-953)
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

        if (!isMainChain)
        {
            PayRental();
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L970-974)
```csharp
                if (amount > existingBalance)
                {
                    var owned = amount.Sub(existingBalance);
                    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1047-1059)
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
