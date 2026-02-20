# Audit Report

## Title
Arithmetic Overflow in Bancor Price Calculation Due to Unbounded Weight Ratios

## Summary
The `GetAmountToPayFromReturn` function in the TokenConverter contract computes exponential calculations without validating the ratio between connector weights. When connector pairs have highly unbalanced weights (e.g., 0.01 vs 0.5), large purchase amounts cause arithmetic overflow in the power calculation, rendering the connector pair unusable and creating a denial-of-service condition for token conversion operations.

## Finding Description

The vulnerability exists in the Bancor formula implementation used for token conversion pricing. When a user attempts to buy tokens via the `Buy` method, the contract calculates the required payment amount using `GetAmountToPayFromReturn`. [1](#0-0) 

This function computes the weight ratio `y = toConnectorWeight / fromConnectorWeight` without any bounds checking on the ratio magnitude: [2](#0-1) 

The exponential calculation `Exp(y * Ln(x))` uses a 20-term Taylor series expansion that requires computing high powers of the input: [3](#0-2) 

The `Pow` function uses binary exponentiation with repeated multiplication: [4](#0-3) 

**Exploitation Scenario:**

1. Governance calls `AddPairConnector` with unbalanced weights (e.g., ResourceWeight="0.01", NativeWeight="0.5") [5](#0-4) 

2. Both weights pass validation since they're individually between 0 and 1: [6](#0-5) 

3. Connector pair is created successfully

4. User attempts to buy a significant portion of the resource token supply (e.g., 45%)

5. The calculation produces: y = 0.5 / 0.01 = 50, and when x ≈ 1.82 (for 45% purchase), the Exp argument becomes approximately 50 × 0.598 ≈ 29.9

6. Computing Pow(29.9, 20) requires intermediate values exceeding decimal.MaxValue (≈ 7.9 × 10²⁸)

7. Since AElf contracts enforce overflow checking, an `OverflowException` is thrown

8. The entire Buy transaction fails, creating a DoS for this connector pair

**No validation exists on weight ratios** - only individual weight bounds are checked, allowing problematic configurations to be deployed.

## Impact Explanation

**High Severity - Operational Denial of Service:**

The vulnerability breaks the availability guarantee of the token conversion system. Connector pairs with weight ratios exceeding approximately 40-50:1 become unusable for legitimate large purchases (>40% of reserves), effectively fragmenting protocol liquidity.

**Specific impacts:**
- All `Buy` transactions for affected connectors fail with `OverflowException` when purchase amounts exceed the overflow threshold
- Users cannot swap tokens through affected pairs, disrupting token economics
- Governance may unknowingly deploy broken connectors since validation provides false security
- No mechanism exists to detect the issue until users attempt transactions
- Smaller purchases succeed while larger ones fail, creating confusing and inconsistent user experience
- Protocol reputation damage due to unexplained transaction failures

**No direct fund theft occurs**, but the complete operational disruption represents a critical availability failure.

## Likelihood Explanation

**Medium Likelihood:**

The vulnerability requires governance action to deploy misconfigured connectors, but this can occur through either malicious intent or accidental misconfiguration during normal operations.

**Preconditions:**
- ConnectorController (Parliament by default) must call `AddPairConnector` with unbalanced weights
- Both individual weights must be valid (between 0 and 1), but their ratio must be high

**Why this is realistic:**
- Weight ratios like 50:1 or 100:1 might appear economically reasonable for certain token pairs (e.g., high-value vs low-value tokens)
- Governance members lack tooling or warnings about ratio constraints
- No documentation specifies ratio limits
- The validation logic provides false confidence that checked weights are safe

**Evidence of missing safeguards:**
- Test cases only validate equal or similar weights (0.05/0.05, 0.6/0.5): [7](#0-6) 
- No overflow scenario testing exists in the BancorHelper tests: [8](#0-7) 

**Detection difficulty:**
- Issue not visible during connector creation
- Manifests only during user transactions
- Smaller purchases succeed, masking the problem initially

## Recommendation

Add validation in the `AddPairConnector` and `UpdateConnector` methods to enforce maximum weight ratio constraints:

```csharp
private void AssertValidWeightRatio(decimal resourceWeight, decimal nativeWeight)
{
    var ratio = Math.Max(resourceWeight / nativeWeight, nativeWeight / resourceWeight);
    Assert(ratio <= 10m, "Weight ratio must not exceed 10:1 to prevent overflow in price calculations.");
}
```

Call this validation in `AddPairConnector`:
```csharp
public override Empty AddPairConnector(PairConnectorParam input)
{
    AssertPerformedByConnectorController();
    // ... existing validation ...
    
    var resourceWeight = AssertedDecimal(input.ResourceWeight);
    var nativeWeight = AssertedDecimal(input.NativeWeight);
    AssertValidWeightRatio(resourceWeight, nativeWeight);
    
    // ... rest of method ...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Buy_With_Extreme_Weight_Ratio_Causes_Overflow()
{
    // Setup connector with extreme weight ratio
    var tokenSymbol = "EXTREME";
    await CreateTokenAsync(tokenSymbol, 1_000_000_00000000);
    
    var pairConnector = new PairConnectorParam
    {
        ResourceConnectorSymbol = tokenSymbol,
        ResourceWeight = "0.01",  // 1%
        NativeWeight = "0.5",      // 50% -> ratio is 50:1
        NativeVirtualBalance = 1_000_000_00000000
    };
    
    await ExecuteProposalForParliamentTransaction(
        TokenConverterContractAddress,
        nameof(TokenConverterContractImplContainer.TokenConverterContractImplStub.AddPairConnector),
        pairConnector);
    
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 1_000_000_00000000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    await DefaultStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 1_000_000_00000000
    });
    
    // Attempt to buy 45% of supply - this will overflow
    var largePurchaseAmount = 450_000_00000000; // 45%
    
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = largePurchaseAmount
    });
    
    // Verify overflow exception occurs
    buyResult.TransactionResult.Error.ShouldContain("Overflow");
}
```

## Notes

The vulnerability is confirmed through code analysis showing:
1. No ratio validation between connector weights exists beyond individual bounds checking
2. The mathematical calculation of Pow(29.9, 20) ≈ 3.26 × 10²⁹ exceeds decimal.MaxValue ≈ 7.9 × 10²⁸
3. AElf enforces overflow checking, causing transactions to revert rather than produce incorrect results
4. Test coverage only validates balanced weight scenarios, missing this edge case
5. The issue creates operational DoS rather than fund loss, but significantly impacts protocol availability

### Citations

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
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

**File:** test/AElf.Contracts.TokenConverter.Internal.Tests/BancorHelperTest.cs (L13-32)
```csharp
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
```
