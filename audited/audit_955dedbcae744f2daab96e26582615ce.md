# Audit Report

## Title
Decimal Overflow in Bancor Price Calculation Causes DoS When Extreme Connector Weight Ratios Are Used

## Summary
The TokenConverter contract's Bancor price calculation functions lack bounds checking on connector weight ratios. When extreme weight ratios (>1000:1) are configured and users attempt moderate-sized trades (>30% of connector balance), the `Exp` function's binary exponentiation overflows `decimal.MaxValue`, causing `OverflowException` and permanent DoS of token conversion functionality with no recovery mechanism.

## Finding Description

The vulnerability exists in the interaction between the `Exp` and `Pow` functions used for Bancor price calculations.

The `Exp` function computes the exponential power series up to y^20, calling `Pow(y, iteration)` for each term. [1](#0-0) 

The `Pow` function uses binary exponentiation with repeated squaring operations that can overflow for large base values. [2](#0-1) 

**Root Cause:** The argument `y` passed to `Exp` is computed as `(weight_ratio) * Ln(balance_ratio)` in both Bancor formulas:

In `GetReturnFromPaid` (Sell operation): [3](#0-2) 

In `GetAmountToPayFromReturn` (Buy operation): [4](#0-3) 

Connector weights are only validated individually to be between 0 and 1: [5](#0-4) [6](#0-5) 

**However, there is NO validation on the RATIO between two connector weights.** If weights are 0.9999 and 0.0001, the ratio is 9,999.

The `Ln` function accepts values up to 2, returning maximum ~0.693: [7](#0-6) 

Therefore, `y = 9,999 × 0.693 ≈ 6,929` is a valid input to `Exp`, which causes overflow when computing y^8 or higher powers during binary exponentiation.

**Overflow Enforcement:** The TokenConverter project has `CheckForOverflowUnderflow` enabled, causing all arithmetic operations to throw `OverflowException` on overflow: [8](#0-7) 

## Impact Explanation

**Complete DoS of Token Conversion:**

Both `Buy` and `Sell` operations directly invoke the vulnerable Bancor calculations without exception handling:

Buy operation: [9](#0-8) 

Sell operation: [10](#0-9) 

When overflow occurs, transactions revert with `OverflowException`, making token conversion impossible.

**Permanent DoS - No Recovery Mechanism:**

Once connectors are activated, their weights CANNOT be updated: [11](#0-10) 

This makes the DoS irrecoverable without contract migration. Liquidity becomes permanently locked, and token exchange is impossible for affected connector pairs.

**Severity: HIGH** - Complete loss of core functionality (token conversion) with no recovery mechanism. While funds are not directly stolen, liquidity is permanently locked and the economic damage is severe.

## Likelihood Explanation

**Preconditions:**
1. Connector controller (Parliament governance) configures connector weights with extreme ratio (>1000:1)
2. Connectors are activated via `EnableConnector` [12](#0-11) 
3. User submits trade with amount >30% of connector balance

**Feasibility:**

**Weight Configuration:** Extreme ratios like 0.9999:0.0001 pass all validation checks. The `UpdateConnector` and `AddPairConnector` methods only verify controller authorization and individual weight bounds, with no ratio validation: [13](#0-12) 

This could occur through:
- Governance proposal typo (e.g., "0.0001" instead of "0.001")
- Poor understanding of ratio implications
- No pre-deployment validation for ratio safety

**Trade Triggering:** Once misconfigured, any user can trigger the DoS through normal trading. With a 10,000:1 weight ratio, a trade of ~34% of connector balance causes overflow.

**Attack Complexity:** LOW - No specialized knowledge required, triggered by regular user trades.

**Probability: MEDIUM-HIGH**
- Extreme weight ratios unlikely under careful governance but plausible with configuration errors
- No warning systems exist
- Once deployed, easily triggered
- Permanent damage (no fix possible for activated connectors)

## Recommendation

1. **Add Weight Ratio Validation:** Implement maximum ratio bounds between connector weights (e.g., max 100:1 ratio):

```csharp
private void AssertValidConnectorWeightRatio(decimal weight1, decimal weight2)
{
    const decimal MaxRatio = 100m;
    var ratio = Math.Max(weight1 / weight2, weight2 / weight1);
    Assert(ratio <= MaxRatio, 
        $"Connector weight ratio {ratio} exceeds maximum allowed ratio {MaxRatio}");
}
```

2. **Add Input Bounds to Exp Function:** Validate that the input to `Exp` is within safe bounds before computation:

```csharp
private static decimal Exp(decimal y)
{
    Assert(Math.Abs(y) <= 10m, "Exponential input exceeds safe bounds");
    // ... existing implementation
}
```

3. **Add Exception Handling:** Wrap Bancor calculations in try-catch blocks to gracefully handle overflow scenarios and provide informative error messages.

4. **Allow Emergency Weight Updates:** Consider adding an emergency mechanism to update connector weights even after activation, with appropriate governance controls.

## Proof of Concept

```csharp
[Fact]
public void Extreme_Weight_Ratio_Causes_Overflow_Test()
{
    // Setup connectors with extreme weight ratio (9999:1)
    var connector1 = new Connector
    {
        Symbol = "TOKEN1",
        Weight = "0.9999",  // 99.99%
        VirtualBalance = 1_000_000
    };
    
    var connector2 = new Connector
    {
        Symbol = "TOKEN2", 
        Weight = "0.0001",  // 0.01%
        VirtualBalance = 1_000_000
    };

    // User attempts to buy 340,000 tokens (34% of balance)
    // This should trigger overflow in Bancor calculation
    var exception = Should.Throw<OverflowException>(() => 
        BancorHelper.GetAmountToPayFromReturn(
            connector2.VirtualBalance, 
            decimal.Parse(connector2.Weight),
            connector1.VirtualBalance,
            decimal.Parse(connector1.Weight),
            340_000  // 34% of balance
        )
    );
    
    // Verify the overflow occurs in the Pow/Exp calculation
    exception.ShouldNotBeNull();
}
```

### Citations

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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L67-94)
```csharp
    public static long GetAmountToPayFromReturn(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long amountToReceive)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = amountToReceive;
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

        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
    }
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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L124-143)
```csharp
    private static decimal Ln(decimal a)
    {
        /*
        ln(a) = log(1-x) = - x - x^2/2 - x^3/3 - ...   (where |x| < 1)
            x: a = 1-x    =>   x = 1-a = 1 - 1.004 = -.004
        */
        var x = 1 - a;
        if (Math.Abs(x) >= 1)
            throw new InvalidValueException("must be 0 < a < 2");

        decimal result = 0;
        uint iteration = _LOOPS;
        while (iteration > 0)
        {
            result -= Pow(x, iteration) / iteration;
            iteration--;
        }

        return result;
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-301)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
    {
        var fromConnector = State.Connectors[input.TokenSymbol];
        Assert(fromConnector != null && !fromConnector.IsDepositAccount,
            "[EnableConnector]Can't find from connector.");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
        var needDeposit = GetNeededDeposit(input);
        if (needDeposit.NeedAmount > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = State.BaseTokenSymbol.Value,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = needDeposit.NeedAmount
                });

        if (input.AmountToTokenConvert > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = input.TokenSymbol,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = input.AmountToTokenConvert
                });

        State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;
        toConnector.IsPurchaseEnabled = true;
        fromConnector.IsPurchaseEnabled = true;
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

**File:** contract/AElf.Contracts.TokenConverter/AElf.Contracts.TokenConverter.csproj (L11-16)
```text
    <PropertyGroup Condition=" '$(Configuration)' == 'Debug' ">
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    </PropertyGroup>
    <PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    </PropertyGroup>
```
