# Audit Report

## Title
Decimal Overflow in BancorHelper.Exp() Causes Permanent DoS of Token Conversion with Extreme Connector Weight Ratios

## Summary
The TokenConverter contract's Bancor formula implementation can permanently fail when connector weights have extreme but individually valid ratios (e.g., 0.99/0.01). The `Exp()` function computes high-degree polynomial terms that overflow `decimal.MaxValue`, causing all Buy/Sell transactions to revert with `OverflowException`. Since connector weights cannot be updated after enablement, this results in permanent DoS of the affected trading pair.

## Finding Description

The vulnerability exists in the exponential calculation used by the Bancor pricing formula. When a user calls `Buy()`, the contract invokes `BancorHelper.GetAmountToPayFromReturn()` to calculate the required payment. [1](#0-0) 

This function computes the weight ratio `y = wt / wf` and calls `Exp(y * Ln(x))`. [2](#0-1) 

Individual connector weights are validated to be strictly between 0 and 1 through the `AssertValidConnectorWeight()` method. [3](#0-2)  The validation uses `IsBetweenZeroAndOne()` which only checks individual weight bounds. [4](#0-3) 

However, **no validation exists on the weight ratio**. If governance sets `wt = 0.99` and `wf = 0.01`, then `y = 99`.

The `Ln()` function constrains its input to the range `(0, 2)` through an assertion. [5](#0-4) 

When a user buys approximately 50% of available supply, `x` approaches `2`, making `Ln(x) ≈ 0.693`. Thus `y * Ln(x) ≈ 99 × 0.693 ≈ 68.6`.

The `Exp()` function implements a 20-term Taylor series expansion. [6](#0-5)  Computing `Exp(68.6)` requires calculating `Pow(68.6, 16)` or higher powers. 

During binary exponentiation in the `Pow()` function, repeated squaring operations can produce intermediate values exceeding `decimal.MaxValue`. [7](#0-6)  Since `68.6^16 ≈ 2.4×10^29 > decimal.MaxValue ≈ 7.9×10^28`, the multiplication operation throws `OverflowException` (C# decimal type always throws on overflow).

Once connectors are enabled, they cannot be updated, making the DoS permanent. [8](#0-7)  This is confirmed by test cases. [9](#0-8) 

## Impact Explanation

**Operational Impact - High Severity:**

- **Complete DoS**: All `Buy()` and `Sell()` operations fail for the affected connector pair
- **Liquidity Locked**: Users cannot trade tokens through this pair, effectively locking liquidity
- **Universal Impact**: Affects all users attempting to trade, not just large transactions
- **Permanence**: The vulnerability cannot be fixed without contract redeployment since `UpdateConnector()` explicitly blocks updates when `IsPurchaseEnabled = true`
- **Protocol Integrity**: Non-functional trading pairs damage protocol reputation and user trust

The severity is high because:
- Token conversion is a core protocol function
- The issue affects availability of a critical service
- No recovery mechanism exists within the contract
- Both Buy and Sell operations are equally affected (they use inverse weight ratios in the same formula)

## Likelihood Explanation

**Likelihood: Medium**

**Preconditions:**
- Connector controller (governance) configures connector weights with extreme ratios
- Both weights individually satisfy validation (0 < weight < 1)
- Connectors are enabled for trading
- User attempts to trade amounts approaching 50% of reserves

**Feasibility Analysis:**
- **Governance Action Required**: The vulnerability requires governance to set extreme weight ratios. While governance typically uses moderate ratios, the lack of ratio-specific validation means extreme configurations are technically permitted.
- **No Malicious Intent Needed**: This can occur through innocent misconfiguration. Governance may review individual weights without considering their ratio.
- **User Trigger**: Any standard user transaction can trigger the overflow once weights are configured.
- **Testing Blind Spot**: The existing test suite only validates moderate weight ratios (0.5, 0.05). [10](#0-9) 

**Economic Context:**
- No special privileges required from users
- Standard transaction fees apply
- No economic disincentive to triggering the bug

The likelihood is medium rather than high because it requires governance misconfiguration, but it remains realistic due to the absence of ratio validation and testing gaps.

## Recommendation

Add validation for the weight ratio to prevent extreme configurations that could cause mathematical overflow:

```csharp
private void AssertValidConnectorWeightRatio(decimal weight1, decimal weight2)
{
    var ratio = Math.Max(weight1 / weight2, weight2 / weight1);
    Assert(ratio <= 10, "Connector weight ratio must not exceed 10:1 to prevent mathematical overflow.");
}
```

Call this validation in `Initialize()`, `AddPairConnector()`, and `UpdateConnector()` after validating individual weights. Additionally, consider implementing safer exponential calculation methods that handle large exponents without overflow, such as capping the exponent value or using logarithmic transformations.

## Proof of Concept

```csharp
[Fact]
public async Task ExtremeWeightRatio_Causes_Overflow_Test()
{
    // Initialize contract
    await DefaultStub.Initialize.SendAsync(new InitializeInput
    {
        FeeRate = "0.005"
    });
    
    var tokenSymbol = "EXTREME";
    await CreateTokenAsync(tokenSymbol);
    
    // Add connector pair with extreme weight ratio (0.99/0.01 = 99)
    var extremePairConnector = new PairConnectorParam
    {
        ResourceConnectorSymbol = tokenSymbol,
        ResourceWeight = "0.99",  // Extreme high weight
        NativeWeight = "0.01",    // Extreme low weight
        NativeVirtualBalance = 1_000_000_00000000
    };
    
    await ExecuteProposalForParliamentTransaction(
        TokenConverterContractAddress,
        nameof(TokenConverterContractImplContainer.TokenConverterContractImplStub.AddPairConnector),
        extremePairConnector);
    
    // Issue tokens and enable connector
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 100_000_000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    await DefaultStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 100_000_000
    });
    
    // Attempt to buy tokens - this should cause OverflowException
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = 50_000_000  // Buying ~50% of supply causes x to approach 2
    });
    
    // Verify transaction fails with overflow
    buyResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    buyResult.TransactionResult.Error.ShouldContain("Overflow");
}
```

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L64-64)
```csharp
        Assert(!targetConnector.IsPurchaseEnabled, "connector can not be updated because it has been activated");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L113-117)
```csharp
        for (var i = t - 1; i >= 0; --i)
        {
            A *= A;
            if (e[i]) A *= x;
        }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L131-132)
```csharp
        if (Math.Abs(x) >= 1)
            throw new InvalidValueException("must be 0 < a < 2");
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

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L426-431)
```csharp
            var updateRet = await ExecuteProposalForParliamentTransactionWithException(
                TokenConverterContractAddress,
                nameof(TokenConverterContractImplContainer.TokenConverterContractImplStub.UpdateConnector),
                resourceConnector);
            updateRet.Error.ShouldContain("onnector can not be updated because it has been activated");
        }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L493-502)
```csharp
    private PairConnectorParam GetLegalPairConnectorParam(string tokenSymbol, long nativeBalance = 1_0000_0000,
        string resourceWeight = "0.05", string nativeWeight = "0.05")
    {
        return new PairConnectorParam
        {
            ResourceConnectorSymbol = tokenSymbol,
            ResourceWeight = resourceWeight,
            NativeWeight = nativeWeight,
            NativeVirtualBalance = nativeBalance
        };
```
