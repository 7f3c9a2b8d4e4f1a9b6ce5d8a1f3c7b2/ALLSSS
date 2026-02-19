# Audit Report

## Title
Incorrect Factorial Array Initialization in Exp() Causes Systematic Bancor Pricing Errors

## Summary
The production `BancorHelper.cs` contains an off-by-one error in factorial array initialization that causes all token swaps with non-equal connector weights to use mathematically incorrect exponential calculations, resulting in systematically wrong pricing for all Buy() and Sell() operations.

## Finding Description

The vulnerability stems from a discrepancy between how the factorial array is initialized and how it is indexed during exponential calculations.

**Production Code Initialization:**
The static constructor initializes the factorial array with factorials 0! through 19! at array indices 0-19. [1](#0-0) 

The `DynFact()` helper function computes factorial values where `DynFact(0)` returns 0!=1, `DynFact(1)` returns 1!=1, `DynFact(2)` returns 2!=2, etc. [2](#0-1) 

**Incorrect Usage in Exp():**
The `Exp()` function computes the exponential series and accesses the factorial array using `Fact[iteration - 1]`. [3](#0-2) 

This creates an off-by-one error:
- When iteration=2: Uses Fact[1] = 1! to compute y²/1! (should be y²/2!)
- When iteration=3: Uses Fact[2] = 2! to compute y³/2! (should be y³/3!)
- When iteration=n: Uses Fact[n-1] = (n-1)! to compute y^n/(n-1)! (should be y^n/n!)

**Correct Implementation in Test Code:**
The test version explicitly initializes the array with 1! through 20! at indices 0-19, making the same indexing pattern `Fact[iteration - 1]` retrieve the correct factorial values. [4](#0-3) 

**Affected Operations:**
Both `Buy()` and `Sell()` operations in the TokenConverter contract call Bancor pricing functions that use the buggy `Exp()` function when connector weights differ. [5](#0-4) [6](#0-5) 

The `GetAmountToPayFromReturn()` and `GetReturnFromPaid()` functions only invoke `Exp()` when `wf != wt` (connector weights differ), which is the common case as seen in production configurations using weights like 0.5 and 0.005. [7](#0-6) [8](#0-7) 

## Impact Explanation

**Direct Economic Impact:**
Every token swap with non-equal connector weights receives incorrect pricing. The mathematical error systematically inflates exponential calculations, with each term y^n/n! being replaced by y^n/(n-1)!, effectively multiplying each term by n. This causes users to receive incorrect token amounts in both buy and sell operations.

**Reserve Imbalance:**
Accumulated pricing errors across many transactions lead to gradual deviation from the intended Bancor curve dynamics. The protocol's reserve balances will drift from their theoretical values, potentially causing insolvency or excessive accumulation over time.

**Arbitrage Vulnerability:**
If external systems or other implementations use correct Bancor formulas, the predictable pricing discrepancy creates an arbitrage opportunity where attackers can systematically extract value from the protocol by exploiting the pricing difference.

**Scope:**
All users performing token conversions through the TokenConverter contract are affected. Given that non-equal weights (like 0.5 vs 0.005) are standard in production deployments, this affects the majority of token swap operations.

## Likelihood Explanation

**High Likelihood:**
- No special permissions required - any user can call `Buy()` or `Sell()`
- The bug is always active for swaps with non-equal connector weights (wf ≠ wt)
- Production configurations use non-equal weights as the standard case (e.g., 0.5 for native tokens, 0.005 for resource tokens)
- Every affected transaction automatically triggers the incorrect calculation
- No complex setup, timing requirements, or preconditions needed
- The error is deterministic and reproducible for every transaction

## Recommendation

Fix the factorial array initialization to match the test version by initializing with factorials 1! through 20! instead of 0! through 19!:

**Option 1:** Modify the static constructor to compute factorials starting from 1:
```csharp
static BancorHelper()
{
    Fact = Array.AsReadOnly(Enumerable.Range(1, 20).Select(x => DynFact(x)).ToArray());
}
```

**Option 2:** Use explicit initialization like the test version to ensure clarity and correctness.

After the fix, audit all past transactions to assess the magnitude of pricing errors and consider compensating affected users.

## Proof of Concept

A simple test can demonstrate the discrepancy:

1. Compare the production `Exp()` result with the mathematically correct exponential calculation for a sample input value (e.g., y = 0.1)
2. The production code will return a higher value due to using incorrect factorials
3. This error propagates through `GetReturnFromPaid()` and `GetAmountToPayFromReturn()` to produce incorrect swap amounts
4. Run identical pricing calculations using both the production and test versions of `BancorHelper` with the same connector balances, weights, and amounts - the results will differ systematically

The test version at `test/AElf.Contracts.TokenConverter.Tests/BancorHelper.cs` serves as the reference implementation demonstrating the correct factorial initialization.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L11-14)
```csharp
    static BancorHelper()
    {
        Fact = Array.AsReadOnly(Enumerable.Range(0, 20).Select(x => DynFact(x)).ToArray());
    }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L16-21)
```csharp
    private static long DynFact(long number)
    {
        var fact = number == 0 ? 1 : number;
        for (var i = number - 1; i >= 1; i--) fact *= i;
        return fact;
    }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L34-54)
```csharp
    public static long GetReturnFromPaid(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long paidAmount)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (paidAmount <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = paidAmount;
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);

        var x = bf / (bf + a);
        var y = wf / wt;
        return (long)(bt * (decimal.One - Exp(y * Ln(x))));
    }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L148-165)
```csharp
    private static decimal Exp(decimal y)
    {
        /*
        exp(y) = 1 + y + y^2/2 + x^3/3! + y^4/4! + y^5/5! + ...
        */

        var iteration = _LOOPS;
        decimal result = 1;
        while (iteration > 0)
        {
            //uint fatorial = Factorial(iteration);
            var fatorial = Fact[iteration - 1];
            result += Pow(y, (uint)iteration) / fatorial;
            iteration--;
        }

        return result;
    }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/BancorHelper.cs (L78-102)
```csharp
    private static readonly long[] Fact =
    {
        1L,
        1L * 2,
        1L * 2 * 3,
        1L * 2 * 3 * 4,
        1L * 2 * 3 * 4 * 5,
        1L * 2 * 3 * 4 * 5 * 6,
        1L * 2 * 3 * 4 * 5 * 6 * 7,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19 * 20
        //14197454024290336768L, //1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19 * 20 * 21,        // NOTE: Overflow during compilation
        //17196083355034583040L, //1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19 * 20 * 21 * 22    // NOTE: Overflow during compilation
    };
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-159)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
        Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[Buy]Can't find from connector.");
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());

        var amountToPayPlusFee = amountToPay.Add(fee);
        Assert(input.PayLimit == 0 || amountToPayPlusFee <= input.PayLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);

        // Transfer base token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = amountToPay
            });
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
        // Transfer bought token
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = input.Symbol,
                To = Context.Sender,
                Amount = input.Amount
            });

        Context.Fire(new TokenBought
        {
            Symbol = input.Symbol,
            BoughtAmount = input.Amount,
            BaseAmount = amountToPay,
            FeeAmount = fee
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-212)
```csharp
    public override Empty Sell(SellInput input)
    {
        var fromConnector = State.Connectors[input.Symbol];
        Assert(fromConnector != null, "[Sell]Can't find from connector.");
        Assert(fromConnector.IsPurchaseEnabled, "can't purchase");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[Sell]Can't find to connector.");
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );

        var fee = Convert.ToInt64(amountToReceive * GetFeeRate());

        if (Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName)) fee = 0;

        var amountToReceiveLessFee = amountToReceive.Sub(fee);
        Assert(input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);

        // Transfer base token
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
        // Transfer sold token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = input.Symbol,
                From = Context.Sender,
                To = Context.Self,
                Amount = input.Amount
            });
        Context.Fire(new TokenSold
        {
            Symbol = input.Symbol,
            SoldAmount = input.Amount,
            BaseAmount = amountToReceive,
            FeeAmount = fee
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L222-235)
```csharp
                Weight = "0.5",
                VirtualBalance = EconomicContractConstants.NativeTokenConnectorInitialVirtualBalance
            }
        };
        foreach (var resourceTokenSymbol in Context.Variables
                     .GetStringArray(EconomicContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(EconomicContractConstants.PayRentalSymbolListName)))
        {
            var resourceTokenConnector = new Connector
            {
                Symbol = resourceTokenSymbol,
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
```
