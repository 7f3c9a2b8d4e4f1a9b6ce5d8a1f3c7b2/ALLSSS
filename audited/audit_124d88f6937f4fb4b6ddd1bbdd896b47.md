# Audit Report

## Title
Arithmetic Overflow in BancorHelper Exponential Calculations Causes Token Conversion DoS

## Summary
The `GetReturnFromPaid` function in `BancorHelper.cs` performs exponential calculations without upper bounds validation on input parameters, allowing arithmetic overflow when extreme connector weight ratios are combined with large trade amounts. This causes transaction reversion and denial of service for token conversion operations.

## Finding Description

The vulnerability exists in the Bancor formula calculation flow where input validation only checks for positive values with no upper bounds. [1](#0-0) 

When connector weights differ, the calculation uses exponential functions where `y = fromConnectorWeight / toConnectorWeight` can be very large if weight ratios are extreme. [2](#0-1) 

The `Exp` function uses a power series expansion that calls `Pow` for each term with iterations up to 20. [3](#0-2) 

The `Pow` function performs binary exponentiation through repeated squaring without overflow protection. [4](#0-3) 

**Root Cause:** When the argument to `Exp` has large magnitude (e.g., `y * Ln(x) ≈ -159`), calculating `Pow(y, 20)` causes decimal overflow. For example, with `y = -159.3`, the calculation of `159.3^20` (approximately 10^44) exceeds `decimal.MaxValue` (7.9 × 10^28), throwing an `OverflowException`.

**Why Existing Protections Fail:** Connector weights are validated to be between 0 and 1, [5](#0-4)  however this allows extreme ratios (e.g., wf=0.99, wt=0.01 yields ratio of 99), which when combined with large trade amounts relative to connector balance, produces overflow conditions.

**Execution Path:** The overflow occurs when users call the `Sell` function, [6](#0-5)  which calls `BancorHelper.GetReturnFromPaid` before any state changes or token transfers occur.

## Impact Explanation

**Operational Impact:** Denial of service for token conversion operations under specific conditions:

1. Users cannot sell resource tokens when trade amounts exceed approximately 4x the connector balance with extreme weight ratios
2. Transactions revert with `OverflowException` before any state changes or token transfers occur
3. The TokenConverter becomes partially unusable for large trades on connectors with extreme weight configurations

**Who is Affected:**
- Users attempting to sell large amounts of tokens from connectors with extreme weight ratios
- The protocol's token conversion functionality becomes unreliable

**Severity Justification:** This represents a **Medium severity** operational vulnerability because:
- It can render specific connector pairs unusable for large trades
- Governance could inadvertently create vulnerable configurations for legitimate reasons (e.g., bootstrapping liquidity)
- No workaround exists for affected trade sizes except selling in multiple smaller transactions
- While no funds are directly stolen, protocol availability is compromised

## Likelihood Explanation

**Attacker Capabilities:** Any user can trigger the overflow by calling the public `Sell` function with large amounts.

**Attack Complexity:** Low - requires only a single transaction calling `Sell` with amount > 4x connector balance.

**Feasibility Conditions:**
- Connector must have extreme weight ratio (e.g., 99:1 or higher)
- Trade amount must be large relative to `fromConnectorBalance`
- Example: wf=0.99, wt=0.01, paidAmount > 4 × fromConnectorBalance

**Realistic Scenario:**
The connector controller (governance) can set connector weights through the `UpdateConnector` function, [7](#0-6)  which validates that weights are between 0 and 1 but allows extreme ratios. Token supply values are typically in the range of 10^16 to 10^17, making the overflow conditions achievable with realistic connector balances.

**Probability:** Medium - requires governance to set extreme weight ratios (not malicious, but possible for legitimate reasons like bootstrapping liquidity or adjusting economic incentives).

## Recommendation

Add upper bounds validation in `GetReturnFromPaid` to prevent overflow conditions:

1. **Validate weight ratios:** Add a maximum allowed ratio between `fromConnectorWeight` and `toConnectorWeight` (e.g., max 10:1 ratio)

2. **Validate trade size:** Add validation that `paidAmount` does not exceed a safe multiple of `fromConnectorBalance` based on the weight ratio

3. **Add overflow protection:** Wrap exponential calculations in try-catch blocks to provide a more graceful failure with a descriptive error message

Example fix for validation:
```csharp
public static long GetReturnFromPaid(long fromConnectorBalance, decimal fromConnectorWeight,
    long toConnectorBalance, decimal toConnectorWeight, long paidAmount)
{
    if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
        throw new InvalidValueException("Connector balance needs to be a positive number.");
    
    if (paidAmount <= 0) 
        throw new InvalidValueException("Amount needs to be a positive number.");
    
    // Add upper bound validation
    var weightRatio = fromConnectorWeight / toConnectorWeight;
    if (weightRatio > 10 || weightRatio < 0.1m)
        throw new InvalidValueException("Connector weight ratio exceeds safe bounds.");
    
    var maxSafeAmount = fromConnectorBalance * 4;
    if (paidAmount > maxSafeAmount && weightRatio > 5)
        throw new InvalidValueException("Trade amount too large for connector weight ratio.");
    
    // ... rest of implementation
}
```

## Proof of Concept

```csharp
[Fact]
public void Sell_With_Extreme_Weights_And_Large_Amount_Should_Overflow()
{
    // Setup connectors with extreme weight ratio
    var fromConnectorWeight = 0.99m;  // Very high weight
    var toConnectorWeight = 0.01m;    // Very low weight
    var fromConnectorBalance = 100_000_000L;
    var toConnectorBalance = 100_000_000L;
    
    // Trade amount > 4x connector balance triggers overflow
    var paidAmount = 500_000_000L;  // 5x fromConnectorBalance
    
    // This should throw OverflowException
    Should.Throw<OverflowException>(() => 
        BancorHelper.GetReturnFromPaid(
            fromConnectorBalance, 
            fromConnectorWeight,
            toConnectorBalance, 
            toConnectorWeight, 
            paidAmount
        )
    );
}
```

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L37-40)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (paidAmount <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L51-53)
```csharp
        var x = bf / (bf + a);
        var y = wf / wt;
        return (long)(bt * (decimal.One - Exp(y * Ln(x))));
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-172)
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
