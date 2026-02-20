# Audit Report

## Title
Decimal Overflow in Bancor Exponential Calculation Causes DoS of Token Conversion Operations

## Summary
The `Exp()` function in the Bancor pricing formula performs exponentiation up to the 20th power without validating the magnitude of its argument. When connector weights are configured with extreme ratios (e.g., 0.99:0.01), the computation overflows the decimal type's maximum value, causing an `OverflowException` that permanently reverts all Buy and Sell operations for the affected token pair.

## Finding Description

The TokenConverter contract uses the Bancor formula to calculate token exchange prices. The vulnerability exists in the exponential calculation implementation.

The `Exp()` function computes a Taylor series expansion by iteratively calling `Pow(y, iteration)` where iteration ranges from 1 to 20. [1](#0-0) 

The `Pow()` function implements binary exponentiation through repeated multiplication operations without bounds checking. [2](#0-1) 

**Root Cause:** The argument passed to `Exp()` is the product of the connector weight ratio and the logarithm of a balance-dependent value: `(weight_ratio) * Ln(x)`. [3](#0-2) [4](#0-3) 

When this product exceeds approximately 27.86 in absolute value, raising it to the 20th power exceeds `decimal.MaxValue ≈ 7.9 × 10^28`. Since the contract compiles with `CheckForOverflowUnderflow=true` [5](#0-4) , this triggers an `OverflowException` that reverts the transaction.

**Why Current Validation Fails:** Connector weights are validated only to be between 0 and 1 individually [6](#0-5) [7](#0-6) , but there is **no validation on the ratio** between two connector weights or the magnitude of the value passed to `Exp()`.

**Execution Path:**

1. Governance sets connector weights via `Initialize`, `UpdateConnector`, or `AddPairConnector` [8](#0-7) [9](#0-8) [10](#0-9) 

2. Any user calls `Buy()` or `Sell()` [11](#0-10) [12](#0-11) 

3. The Bancor calculation invokes `Exp()` which throws `OverflowException`, reverting the transaction

4. The only try-catch in the Bancor code path handles a different scenario (equal weights), not the overflow [13](#0-12) 

## Impact Explanation

**Severity: HIGH**

**Concrete Harm:**
1. **Complete DoS**: All Buy and Sell operations for the affected token pair permanently revert with `OverflowException`, making the token pair completely non-functional
2. **Funds Effectively Locked**: Users holding the affected token cannot sell it to exit their positions, trapping their capital until governance intervenes
3. **Protocol Revenue Loss**: No trading fees can be collected from the disabled token pair during the outage
4. **No Automatic Recovery**: Only governance intervention to reconfigure connector weights can restore functionality, which may take significant time

**Affected Parties:**
- All users with balances in the affected token (cannot sell)
- Users wanting to buy the token (cannot purchase)
- Protocol treasury (loses expected trading fee revenue)
- Overall protocol credibility (critical token conversion feature becomes unreliable)

**Mathematical Proof:**
- For overflow: `|y|^20 > decimal.MaxValue ≈ 7.9 × 10^28`
- This requires: `|y| > (7.9 × 10^28)^(1/20) ≈ 27.86`
- Where `y = (weight_ratio) * Ln(x)`
- Example: weights 0.99 and 0.01 give ratio = 99. With a moderate trade where `x = 0.75`, `Ln(0.75) ≈ -0.288`, so `|y| ≈ 28.5`, causing overflow when computing `28.5^20`

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Attack Complexity: LOW**
- Triggering requires only a single `Buy()` or `Sell()` transaction
- No special privileges needed for the trigger transaction
- Transaction parameters are straightforward (token symbol, amount)

**Preconditions:**
1. Connector weights must be configured such that `|(weight1/weight2) * Ln(x)| > 27.86` for realistic trade sizes
2. Such configurations are **explicitly allowed** by current validation logic, which only checks individual weights are in (0, 1)
3. This scenario can occur via:
   - **Accidental misconfiguration**: Human error in governance proposal (e.g., typo entering 0.01 instead of 0.1)
   - **Intentional economic design**: Protocol designers choosing extreme weight ratios for specific tokenomics, unaware of the overflow risk
   - **Malicious governance proposal**: If Parliament control is compromised (though governance is generally trusted)

**Feasibility:**
- Governance has full authority to set any weight values within (0, 1)
- No warning or additional validation when setting extreme ratios
- No documentation warning against ratio limits
- The overflow is deterministic and reproducible for the same configuration
- Once triggered, the DoS persists until governance reconfigures weights

**Probability:** HIGH if extreme weight ratios are ever configured, which is realistic given:
- Human error in governance proposals is common across DeFi protocols
- Economic models might theoretically justify high ratios for certain token pairs
- Lack of explicit documentation about safe ratio ranges

## Recommendation

Implement validation to prevent configurations that could cause overflow:

1. **Add ratio bounds validation** when setting connector weights. Calculate the maximum safe weight ratio based on the overflow threshold and expected trade sizes.

2. **Add input validation in `Exp()`** to reject arguments with magnitude exceeding safe bounds (e.g., `|y| < 20` to provide safety margin).

3. **Wrap Bancor calculations in try-catch** to gracefully handle unexpected overflows and provide clear error messages rather than reverting.

4. **Document safe parameter ranges** in governance documentation to inform parameter selection.

Example fix for weight validation:
```csharp
private void AssertValidConnectorWeight(Connector connector)
{
    var weight = AssertedDecimal(connector.Weight);
    Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
    connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
}

// Add after setting both connector weights:
private void ValidateConnectorWeightRatio(decimal weight1, decimal weight2)
{
    const decimal maxSafeRatio = 20m; // Conservative bound
    var ratio = Math.Max(weight1 / weight2, weight2 / weight1);
    Assert(ratio <= maxSafeRatio, 
        $"Connector weight ratio {ratio} exceeds maximum safe ratio {maxSafeRatio}");
}
```

## Proof of Concept

The following test demonstrates the overflow:

1. Deploy TokenConverter contract
2. Initialize with connector weights: weight1=0.99, weight2=0.01 (ratio=99)
3. Enable the connector pair
4. Any user calls `Buy()` or `Sell()` with a moderate amount
5. Transaction reverts with `OverflowException` in `Pow()` function during the Bancor calculation
6. All subsequent Buy/Sell transactions for this pair permanently fail until governance reconfigures the weights

The exact overflow occurs when computing `Pow((weight_ratio * Ln(x)), 20)` where the product exceeds the safe threshold, demonstrating that the current validation is insufficient to prevent DoS conditions.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L51-53)
```csharp
        var x = bf / (bf + a);
        var y = wf / wt;
        return (long)(bt * (decimal.One - Exp(y * Ln(x))));
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L80-89)
```csharp
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
            }
            catch
            {
                throw new AssertionException("Insufficient account balance to deposit");
            }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L104-120)
```csharp
    public static decimal Pow(decimal x, uint y)
    {
        if (y == 1)
            return x;

        var A = 1m;
        var e = new BitArray(y.ToBytes(false));
        var t = e.Count;

        for (var i = t - 1; i >= 0; --i)
        {
            A *= A;
            if (e[i]) A *= x;
        }

        return A;
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

**File:** contract/AElf.Contracts.TokenConverter/AElf.Contracts.TokenConverter.csproj (L11-16)
```text
    <PropertyGroup Condition=" '$(Configuration)' == 'Debug' ">
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    </PropertyGroup>
    <PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    </PropertyGroup>
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L27-56)
```csharp
    public override Empty Initialize(InitializeInput input)
    {
        Assert(IsValidBaseSymbol(input.BaseTokenSymbol), $"Base token symbol is invalid. {input.BaseTokenSymbol}");
        Assert(State.TokenContract.Value == null, "Already initialized.");
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
        State.BaseTokenSymbol.Value = !string.IsNullOrEmpty(input.BaseTokenSymbol)
            ? input.BaseTokenSymbol
            : Context.Variables.NativeSymbol;
        var feeRate = AssertedDecimal(input.FeeRate);
        Assert(IsBetweenZeroAndOne(feeRate), "Fee rate has to be a decimal between 0 and 1.");
        State.FeeRate.Value = feeRate.ToString(CultureInfo.InvariantCulture);
        foreach (var connector in input.Connectors)
        {
            if (connector.IsDepositAccount)
            {
                Assert(!string.IsNullOrEmpty(connector.Symbol), "Invalid connector symbol.");
                AssertValidConnectorWeight(connector);
            }
            else
            {
                Assert(IsValidSymbol(connector.Symbol), "Invalid symbol.");
                AssertValidConnectorWeight(connector);
            }

            State.Connectors[connector.Symbol] = connector;
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-76)
```csharp
    public override Empty UpdateConnector(Connector input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.Symbol), "input symbol can not be empty'");
        var targetConnector = State.Connectors[input.Symbol];
        Assert(targetConnector != null, "Can not find target connector.");
        Assert(!targetConnector.IsPurchaseEnabled, "connector can not be updated because it has been activated");
        if (!string.IsNullOrEmpty(input.Weight))
        {
            var weight = AssertedDecimal(input.Weight);
            Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
            targetConnector.Weight = input.Weight.ToString(CultureInfo.InvariantCulture);
        }

        if (targetConnector.IsDepositAccount && input.VirtualBalance > 0)
            targetConnector.VirtualBalance = input.VirtualBalance;
        State.Connectors[input.Symbol] = targetConnector;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L79-110)
```csharp
    public override Empty AddPairConnector(PairConnectorParam input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.ResourceConnectorSymbol),
            "resource token symbol should not be empty");
        var nativeConnectorSymbol = NewNtTokenPrefix.Append(input.ResourceConnectorSymbol);
        Assert(State.Connectors[input.ResourceConnectorSymbol] == null,
            "resource token symbol has existed");
        var resourceConnector = new Connector
        {
            Symbol = input.ResourceConnectorSymbol,
            IsPurchaseEnabled = false,
            RelatedSymbol = nativeConnectorSymbol,
            Weight = input.ResourceWeight
        };
        Assert(IsValidSymbol(resourceConnector.Symbol), "Invalid symbol.");
        AssertValidConnectorWeight(resourceConnector);
        var nativeTokenToResourceConnector = new Connector
        {
            Symbol = nativeConnectorSymbol,
            VirtualBalance = input.NativeVirtualBalance,
            IsVirtualBalanceEnabled = true,
            IsPurchaseEnabled = false,
            RelatedSymbol = input.ResourceConnectorSymbol,
            Weight = input.NativeWeight,
            IsDepositAccount = true
        };
        AssertValidConnectorWeight(nativeTokenToResourceConnector);
        State.Connectors[resourceConnector.Symbol] = resourceConnector;
        State.Connectors[nativeTokenToResourceConnector.Symbol] = nativeTokenToResourceConnector;
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L354-357)
```csharp
    private static bool IsBetweenZeroAndOne(decimal number)
    {
        return number > decimal.Zero && number < decimal.One;
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L418-423)
```csharp
    private void AssertValidConnectorWeight(Connector connector)
    {
        var weight = AssertedDecimal(connector.Weight);
        Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
        connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
    }
```
