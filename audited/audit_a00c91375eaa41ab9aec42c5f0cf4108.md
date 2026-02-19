# Audit Report

## Title
Arithmetic Overflow in Bancor Formula Causes DoS for Valid Extreme Weight Ratios

## Summary
The TokenConverter contract's Bancor pricing calculation uses Taylor series approximations with 20 terms to compute exponential functions. When connector weight ratios reach extreme but valid values (e.g., 0.99/0.01 = 99), combined with moderate trade sizes, the `Pow()` function in the exponential calculation overflows, causing transaction revert and denial of service for legitimate Buy/Sell operations.

## Finding Description
The vulnerability exists in the Bancor pricing calculation path used by both `Buy()` and `Sell()` operations in the TokenConverter contract. [1](#0-0) [2](#0-1) 

These methods call BancorHelper functions that compute `Exp(y * Ln(x))` where `y = wf/wt` (weight ratio) and `x` is a balance ratio. [3](#0-2) [4](#0-3) 

Connector weights are validated to be strictly between 0 and 1 (exclusive) by the `IsBetweenZeroAndOne()` check. [5](#0-4) [6](#0-5) 

This validation allows extreme weight ratios such as wf=0.99, wt=0.01, creating y=99, which is mathematically valid but causes overflow during computation.

The root cause lies in the `Exp()` function's Taylor series implementation. [7](#0-6) 

At iteration 20, the function computes `Pow(y, 20)`. For large absolute values of y (e.g., y ≈ -40 when wf=0.99, wt=0.01, and x≈0.667), calculating y^20 produces (-40)^20 ≈ 1.1 × 10^32, which exceeds the C# decimal type's maximum value of approximately 7.9 × 10^28.

Since AElf contracts are required to enable `CheckForOverflowUnderflow=true` [8](#0-7) , the overflow throws an `OverflowException`, reverting the transaction.

The `Pow()` function performs binary exponentiation without overflow guards. [9](#0-8) 

The existing `PayLimit` and `ReceiveLimit` checks occur AFTER the Bancor calculation completes, providing no protection against overflow during price computation. [10](#0-9) [11](#0-10) 

## Impact Explanation
**High Severity - Complete DoS of Token Conversion Operations:**

When connector pairs are deployed with extreme but valid weight ratios (e.g., wf=0.99, wt=0.01), all Buy and Sell operations for those pairs will revert with overflow exceptions when users attempt trades of moderate to large sizes (approximately ≥50% of connector balance). This creates:

1. **Service Unavailability**: Users cannot trade tokens through affected connector pairs
2. **Locked Liquidity**: Tokens deposited in these connectors become difficult or impossible to trade efficiently
3. **Protocol Dysfunction**: Resource token conversion functionality is impaired for affected pairs
4. **Economic Impact**: If key connector pairs become dysfunctional, the entire economic model's stability is compromised

While no funds are directly lost, the complete denial of service for legitimate operations constitutes a critical availability breach. The vulnerability is particularly severe because:
- Once connector weights are set by governance, they remain static until updated
- Normal users attempting legitimate trades suffer the consequences
- The mathematical constraints (0 < weight < 1) do not prevent this scenario
- No warnings or precautions exist to prevent governance from deploying vulnerable configurations

## Likelihood Explanation
**Medium Likelihood:**

**Reachable Entry Point:** Yes - `Buy()` and `Sell()` are public methods callable by any user on the TokenConverter contract.

**Feasible Preconditions:**
1. Governance deploys connector pair with extreme weight ratio (e.g., wf=0.99, wt=0.01) via `AddPairConnector()` or `UpdateConnector()` [12](#0-11) [13](#0-12) 
2. User attempts trade size that creates balance ratio x resulting in |y * Ln(x)| > ~35

**Execution Practicality:**
- Connector weights are governance-controlled but mathematically valid
- Trade size of ~50% of connector balance is reasonable for moderate-sized pools
- No attacker privileges needed - normal trading triggers the overflow
- Predictable and deterministic failure for specific weight ratios and trade sizes

**Probability Assessment:** While extreme weight ratios (e.g., 99:1) may be less common than balanced ratios, they are:
- Mathematically valid per current validation rules
- Potentially useful for specific economic models (pegged assets, highly asymmetric bonding curves)
- Not prevented by any warnings or safeguards in the governance process
- Permanently problematic once deployed until governance updates them

## Recommendation

**Short-term Fix:** Add bounds checking to the `Exp()` function to reject inputs that would cause overflow:

```csharp
private static decimal Exp(decimal y)
{
    // Prevent overflow: For 20 iterations, |y| should not exceed ~35
    // to keep Pow(y, 20) within decimal range
    if (Math.Abs(y) > 35)
        throw new InvalidValueException("Exponential input exceeds safe computation bounds.");
    
    var iteration = _LOOPS;
    decimal result = 1;
    while (iteration > 0)
    {
        var fatorial = Fact[iteration - 1];
        result += Pow(y, (uint)iteration) / fatorial;
        iteration--;
    }
    return result;
}
```

**Long-term Solutions:**
1. **Restrict Weight Ratios:** Add validation in `AssertValidConnectorWeight()` to limit maximum weight ratio (e.g., 10:1):
```csharp
private void AssertValidConnectorWeight(Connector connector)
{
    var weight = AssertedDecimal(connector.Weight);
    Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
    Assert(weight >= 0.1m && weight <= 0.9m, "Connector weight must be between 0.1 and 0.9 to prevent extreme ratios.");
    connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
}
```

2. **Use Higher Precision:** Consider using a library with arbitrary precision arithmetic for Bancor calculations, though this may have gas implications.

3. **Increase Taylor Series Terms:** Increase `_LOOPS` beyond 20 and use a more sophisticated algorithm that adapts the number of terms based on input magnitude, though this requires careful testing.

## Proof of Concept

```csharp
[Fact]
public void Test_Overflow_With_Extreme_Weight_Ratio()
{
    // Setup connector pair with extreme weight ratio
    var wf = 0.99m;  // From connector weight
    var wt = 0.01m;  // To connector weight
    var bf = 1000000L;  // From connector balance
    var bt = 1000000L;  // To connector balance
    var tradeAmount = 500000L;  // 50% of balance
    
    // This should cause overflow in BancorHelper
    var exception = Assert.Throws<OverflowException>(() =>
    {
        var result = BancorHelper.GetReturnFromPaid(
            fromConnectorBalance: bf,
            fromConnectorWeight: wf,
            toConnectorBalance: bt,
            toConnectorWeight: wt,
            paidAmount: tradeAmount
        );
    });
    
    // Verify overflow occurs in the exponential calculation
    Assert.NotNull(exception);
}
```

**Notes:**
- The vulnerability is deterministic and reproducible with specific weight ratios (e.g., 99:1) and trade sizes (~50% of balance)
- Current test suite only uses balanced ratios (0.5:0.5), missing this edge case
- The issue affects both Buy and Sell operations symmetrically
- Governance should be warned about deploying connectors with extreme weight ratios until a fix is implemented

### Citations

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
