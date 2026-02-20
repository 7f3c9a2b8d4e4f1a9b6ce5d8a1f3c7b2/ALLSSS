# Audit Report

## Title
Arithmetic Overflow in BancorHelper Exponential Calculations Causes Token Conversion DoS

## Summary
The `GetReturnFromPaid` function in `BancorHelper.cs` performs exponential calculations without upper bounds validation on input parameters, allowing arithmetic overflow when extreme connector weight ratios are combined with large trade amounts. This causes transaction reversion and denial of service for token conversion operations.

## Finding Description

The vulnerability exists in the Bancor formula calculation where input validation only checks for positive values without upper bounds. [1](#0-0) 

When connector weights differ, the calculation uses exponential functions where the ratio `y = fromConnectorWeight / toConnectorWeight` can become very large with extreme weight configurations. [2](#0-1) 

The `Exp` function uses a power series expansion with up to 20 iterations, calling `Pow` for each term. [3](#0-2) 

The `Pow` function performs binary exponentiation through repeated squaring without overflow protection. [4](#0-3) 

**Root Cause:** When the argument to `Exp` has large magnitude (e.g., `y * Ln(x) ≈ -159`), calculating `Pow(y, 20)` causes decimal overflow. For example, with `y = -159.3`, the calculation of `159.3^20` (approximately 10^44) exceeds `decimal.MaxValue` (7.9 × 10^28), throwing an `OverflowException`.

**Why Existing Protections Fail:** Connector weights are validated to be between 0 and 1 (exclusive) [5](#0-4) , however this allows extreme ratios (e.g., wf=0.99, wt=0.01 yields ratio of 99:1), which when combined with large trade amounts relative to connector balance produces overflow conditions.

**Execution Path:** The overflow occurs when users call the `Sell` function [6](#0-5) , which calls `BancorHelper.GetReturnFromPaid` before any state changes or token transfers occur.

## Impact Explanation

**Operational Impact:** Denial of service for token conversion operations under specific conditions:

1. Users cannot sell resource tokens when trade amounts exceed approximately 4x the connector balance with extreme weight ratios
2. Transactions revert with `OverflowException` before any state changes or token transfers occur (confirmed by AElf's `CheckForOverflowUnderflow` requirement)
3. The TokenConverter becomes partially unusable for large trades on connectors with extreme weight configurations

**Who is Affected:**
- Users attempting to sell large amounts of tokens from connectors with extreme weight ratios
- The protocol's token conversion functionality becomes unreliable for affected connector pairs

**Severity Justification:** This represents a **Medium severity** operational vulnerability because:
- It can render specific connector pairs unusable for large trades
- Governance could inadvertently create vulnerable configurations for legitimate reasons (e.g., bootstrapping liquidity with asymmetric weights)
- No workaround exists for affected trade sizes except selling in multiple smaller transactions
- While no funds are directly stolen, protocol availability is compromised for critical conversion operations

## Likelihood Explanation

**Attacker Capabilities:** Any user can trigger the overflow by calling the public `Sell` function with large amounts - no special privileges required.

**Attack Complexity:** Low - requires only a single transaction calling `Sell` with amount > 4x connector balance on a connector pair with extreme weight ratio.

**Feasibility Conditions:**
- Connector must have extreme weight ratio (e.g., 99:1 or higher)
- Trade amount must be large relative to `fromConnectorBalance`
- Concrete example: wf=0.99, wt=0.01, paidAmount > 4 × fromConnectorBalance

**Realistic Scenario:**
The connector controller (governance) can set connector weights through the `UpdateConnector` function [7](#0-6) , which validates that weights are between 0 and 1 but explicitly allows extreme ratios. Such configurations could be set legitimately for economic bootstrapping or incentive adjustments.

**Probability:** Medium - requires governance to set extreme weight ratios (not malicious intent, but possible for legitimate economic reasons), after which any user can trigger the DoS with a large trade.

## Recommendation

Add upper bound validation to prevent overflow conditions:

1. **Short-term:** Add validation in `GetReturnFromPaid` to reject trades that would cause extreme exponent values:
   - Calculate `y * Ln(x)` magnitude before calling `Exp`
   - Reject if absolute value exceeds safe threshold (e.g., 50)

2. **Medium-term:** Add connector weight ratio limits during connector configuration:
   - In `UpdateConnector` and `AddPairConnector`, validate that weight ratios stay within reasonable bounds (e.g., max 10:1 ratio)
   - Or add explicit checks for the combined effect of weight ratio and trade size

3. **Long-term:** Consider using SafeMath-style checked arithmetic for the `Pow` function or switching to a more numerically stable exponential approximation for extreme inputs.

## Proof of Concept

```csharp
[Fact]
public async Task Sell_With_Extreme_Weights_Causes_Overflow()
{
    // Setup connector with extreme weight ratio
    await TokenConverterContractStub.AddPairConnector.SendAsync(new PairConnectorParam
    {
        ResourceConnectorSymbol = "TEST",
        ResourceWeight = "0.99",      // Very high weight
        NativeWeight = "0.01",         // Very low weight  
        NativeVirtualBalance = 1_000_000
    });
    
    await TokenConverterContractStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = "TEST",
        AmountToTokenConvert = 1_000_000
    });

    // User attempts to sell 5x the connector balance
    var sellResult = await TokenConverterContractStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = "TEST",
        Amount = 5_000_000  // 5x connector balance triggers overflow
    });

    // Transaction should fail with OverflowException
    sellResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    sellResult.TransactionResult.Error.ShouldContain("System.OverflowException");
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
