# Audit Report

## Title
Arithmetic Overflow in BancorHelper Exponential Calculations Causes Token Conversion DoS

## Summary
The `GetReturnFromPaid` function performs exponential calculations without upper bounds validation on connector weight ratios, allowing decimal arithmetic overflow when extreme weight configurations are combined with large trade amounts. This causes transaction reversion and denial of service for token conversion operations. [1](#0-0) 

## Finding Description

The vulnerability exists in the Bancor formula calculation flow where input validation only checks for positive values with no upper bounds on the magnitude of exponential calculations. [2](#0-1) 

When connector weights differ significantly, the calculation computes `y = fromConnectorWeight / toConnectorWeight`, which can produce extreme ratios. [3](#0-2) 

The `Exp` function uses a power series expansion that iterates up to 20 times, calling `Pow` for each term. [4](#0-3) 

The `Pow` function performs binary exponentiation through repeated squaring operations without overflow bounds checking. [5](#0-4) 

**Root Cause**: When the exponential argument has large magnitude (e.g., `y * Ln(x) ≈ -159`), calculating `Pow(-159, 20)` produces `159^20 ≈ 1.43 × 10^44`, which exceeds `decimal.MaxValue` (7.9 × 10^28), throwing an `OverflowException`.

**Why Existing Protections Fail**: Connector weights are validated to be between 0 and 1 (exclusive), [6](#0-5)  however this validation allows extreme ratios (e.g., wf=0.99, wt=0.01 yields ratio of 99). [7](#0-6) 

**Execution Path**: The overflow occurs when users call the public `Sell` function, [8](#0-7)  which invokes `BancorHelper.GetReturnFromPaid` before any state changes or token transfers occur.

## Impact Explanation

**Operational Impact**: Denial of service for token conversion operations under specific conditions:

1. Users cannot sell resource tokens when trade amounts exceed approximately 4× the connector balance with extreme weight ratios
2. Transactions revert with `OverflowException` before any state changes or token transfers occur
3. The TokenConverter becomes partially unusable for large trades on connectors with extreme weight configurations

**Who is Affected**:
- Users attempting to sell large amounts of tokens from connectors with extreme weight ratios
- The protocol's token conversion functionality becomes unreliable under these configurations

**Severity Justification**: Medium severity operational vulnerability because:
- It can render specific connector pairs unusable for large trades
- Governance could inadvertently create vulnerable configurations for legitimate economic reasons (e.g., bootstrapping liquidity, adjusting incentive structures)
- No workaround exists for affected trade sizes except splitting into multiple smaller transactions
- While no funds are directly stolen or lost, protocol availability and usability are compromised

## Likelihood Explanation

**Attacker Capabilities**: Any user can trigger the overflow by calling the public `Sell` function with sufficiently large amounts.

**Attack Complexity**: Low - requires only a single transaction calling `Sell` with amount > 4× connector balance.

**Feasibility Conditions**:
- Connector must have extreme weight ratio (e.g., 99:1 or higher)
- Trade amount must be large relative to `fromConnectorBalance`
- Example: wf=0.99, wt=0.01, paidAmount > 4 × fromConnectorBalance

**Realistic Scenario**: The connector controller (governance) can set connector weights through the `UpdateConnector` function, [9](#0-8)  which validates that weights are between 0 and 1 but explicitly allows extreme ratios. Token supply values are typically in the range of 10^16 to 10^17, making the overflow conditions achievable with realistic connector balances.

**Probability**: Medium - requires governance to set extreme weight ratios (not malicious, but possible for legitimate reasons like bootstrapping liquidity or adjusting economic incentives).

## Recommendation

Implement bounds checking on connector weight ratios and exponential calculation inputs:

1. **Add ratio validation**: In `UpdateConnector` and `AddPairConnector`, validate that the ratio between any two connector weights doesn't exceed a maximum threshold (e.g., 10:1).

2. **Add input bounds in GetReturnFromPaid**: Before calling `Exp`, validate that `|y * Ln(x)|` is within safe bounds (e.g., < 50) to prevent overflow in power calculations.

3. **Add safe exponentiation**: Wrap the `Pow` function's multiplication operations in try-catch blocks or add pre-computation checks to detect potential overflow before it occurs.

Example fix for ratio validation:
```csharp
private void AssertValidConnectorWeight(Connector connector)
{
    var weight = AssertedDecimal(connector.Weight);
    Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
    
    // Add maximum ratio check
    const decimal MaxRatio = 10m; // e.g., 10:1 maximum
    Assert(weight * MaxRatio > decimal.One / MaxRatio, 
        "Connector weight would create extreme ratio risk.");
    
    connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
}
```

## Proof of Concept

```csharp
[Fact]
public void GetReturnFromPaid_ExtremeWeightRatio_CausesOverflow()
{
    // Arrange: Set up connectors with extreme weight ratio (99:1)
    var fromBalance = 100_000_000L;  // 100 million
    var toBalance = 100_000_000L;
    var fromWeight = 0.99m;  // Very high weight
    var toWeight = 0.01m;    // Very low weight
    var paidAmount = 450_000_000L;  // 4.5x the from balance
    
    // Act & Assert: Should throw OverflowException
    Should.Throw<OverflowException>(() => 
        BancorHelper.GetReturnFromPaid(
            fromBalance, 
            fromWeight,
            toBalance, 
            toWeight, 
            paidAmount));
}
```

## Notes

This vulnerability demonstrates that while AElf's SafeMath system protects integer arithmetic operations, decimal operations rely on C# runtime overflow behavior. The existing test suite [10](#0-9)  only tests modest weight ratios (0.5 and 0.6) and does not cover extreme ratio scenarios. The validation framework correctly identifies this as a Medium severity issue due to its operational DoS impact without direct fund loss, combined with realistic likelihood under legitimate governance configurations.

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

**File:** test/AElf.Contracts.TokenConverter.Internal.Tests/BancorHelperTest.cs (L1-95)
```csharp
using Shouldly;
using Xunit;

namespace AElf.Contracts.TokenConverter;

public class BancorHelperTest
{
    //init connector
    private readonly Connector _elfConnector;

    private readonly Connector _writeConnector;

    public BancorHelperTest()
    {
        _writeConnector = new Connector
        {
            Symbol = "WRITE",
            VirtualBalance = 50_0000,
            Weight = "0.5",
            IsVirtualBalanceEnabled = false,
            IsPurchaseEnabled = true
        };

        _elfConnector = new Connector
        {
            Symbol = "ELF",
            VirtualBalance = 100_0000,
            Weight = "0.6",
            IsPurchaseEnabled = true,
            IsVirtualBalanceEnabled = false
        };
    }

    [Fact]
    public void Pow_Test()
    {
        var result1 = BancorHelper.Pow(1.5m, 1);
        result1.ShouldBe(1.5m);

        BancorHelper.Pow(1.5m, 2);
    }

    [Fact]
    public void GetAmountToPay_GetReturnFromPaid_Failed()
    {
        //fromConnectorBalance <= 0
        Should.Throw<InvalidValueException>(() => BancorHelper.GetAmountToPayFromReturn(0, 1000, 1000, 1000, 1000));
        //paidAmount <= 0
        Should.Throw<InvalidValueException>(() => BancorHelper.GetAmountToPayFromReturn(1000, 1000, 1000, 1000, 0));
        //toConnectorBalance <= 0
        Should.Throw<InvalidValueException>(() => BancorHelper.GetReturnFromPaid(1000, 1000, 0, 1000, 1000));
        //amountToReceive <= 0
        Should.Throw<InvalidValueException>(() => BancorHelper.GetReturnFromPaid(1000, 1000, 1000, 1000, 0));
    }

    [Theory]
    [InlineData(100L)]
    [InlineData(1000L)]
    [InlineData(10000L)]
    public void BuyResource_Test(long paidElf)
    {
        var resourceAmount1 = BuyOperation(paidElf);
        var resourceAmount2 = BuyOperation(paidElf);
        resourceAmount1.ShouldBeGreaterThanOrEqualTo(resourceAmount2);
    }

    [Theory]
    [InlineData(100L)]
    [InlineData(1000L)]
    [InlineData(10000L)]
    public void SellResource_Test(long paidRes)
    {
        var elfAmount1 = SellOperation(paidRes);
        var elfAmount2 = SellOperation(paidRes);
        elfAmount1.ShouldBeGreaterThanOrEqualTo(elfAmount2);
    }

    private long BuyOperation(long paidElf)
    {
        var getAmountToPayout = BancorHelper.GetAmountToPayFromReturn(
            _elfConnector.VirtualBalance, decimal.Parse(_elfConnector.Weight),
            _writeConnector.VirtualBalance, decimal.Parse(_writeConnector.Weight),
            paidElf);
        return getAmountToPayout;
    }

    private long SellOperation(long paidRes)
    {
        var getReturnFromPaid = BancorHelper.GetReturnFromPaid(
            _writeConnector.VirtualBalance, decimal.Parse(_writeConnector.Weight),
            _elfConnector.VirtualBalance, decimal.Parse(_elfConnector.Weight),
            paidRes);
        return getReturnFromPaid;
    }
}
```
