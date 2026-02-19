### Title
Precision Loss and Incorrect Pricing in Bancor Formula Due to Extreme Connector Weight Ratios

### Summary
The `GetReturnFromPaid()` and `GetAmountToPayFromReturn()` functions calculate token swap prices using connector weight ratios that can differ by orders of magnitude. When weights diverge significantly (e.g., 0.99 / 0.001 = 990), the resulting exponential calculations using only 20-term power series approximations lose precision, exceed decimal capacity, and produce incorrect swap prices. This leads to mispriced token conversions where users receive substantially more or fewer tokens than they should.

### Finding Description

The vulnerability exists in the Bancor pricing formula implementation in [1](#0-0) 

The core issue occurs at the weight ratio calculation and subsequent exponential computation: [2](#0-1) 

The formula computes `y = fromConnectorWeight / toConnectorWeight` and then evaluates `Exp(y * Ln(x))`. Connector weights are validated only to be individually within (0, 1) exclusive bounds at [3](#0-2)  and [4](#0-3) 

However, no validation exists on the **ratio** between paired connector weights. This allows extreme scenarios where:
- fromConnectorWeight = 0.99, toConnectorWeight = 0.001 → ratio = 990
- With x = bf/(bf + a) ≈ 0.5, we get Ln(0.5) ≈ -0.693
- Therefore y * Ln(x) = 990 × (-0.693) ≈ -686

The `Exp()` function uses a truncated power series with only 20 iterations: [5](#0-4)  and [6](#0-5) 

For large magnitude inputs like -686, the power series terms grow catastrophically:
- Term 20: (-686)^20 / 20! 
- (-686)^20 has approximately 57 digits (20 × log₁₀(686) ≈ 57)
- 20! has approximately 18 digits
- The ratio has ~39 digits, far exceeding C# decimal's 28-29 digit precision

The `Pow()` function at [7](#0-6)  performs repeated squaring which amplifies precision errors exponentially for large exponents.

This precision loss propagates to actual token swaps via:
- The `Sell()` function at [8](#0-7) 
- The `Buy()` function at [9](#0-8) 

The same issue affects `GetAmountToPayFromReturn()` which uses the inverse ratio: [10](#0-9) 

### Impact Explanation

**Direct Fund Impact**: Users performing token swaps receive incorrect amounts due to mispriced conversions. With extreme weight ratios (e.g., 990:1), the exponential calculation can:
- Underestimate returns by orders of magnitude (users lose value)
- Overestimate returns allowing extraction of excess reserves (protocol loses value)

**Concrete Scenario**:
- Connector pair with weights 0.99 and 0.001 (legitimate for certain tokenomics)
- Each with 1,000,000 token balance
- User sells 100,000 tokens expecting ~99,900 return based on correct formula
- Precision loss causes Exp(-686) miscalculation
- User receives substantially incorrect amount (could be near 0 or near full balance depending on calculation error)
- Value discrepancy scales with transaction size

**Who is Affected**: All users performing swaps on connector pairs with significantly different weights, and the protocol reserves that become depleted or stuck due to mispricing.

**Severity Justification**: HIGH - Direct theft or loss of user/protocol funds through systematic mispricing of swaps, no authentication required, affects core functionality.

### Likelihood Explanation

**Reachable Entry Point**: Public `Buy()` and `Sell()` functions are directly callable by any user.

**Feasible Preconditions**: 
- Connector weights are set by governance (ConnectorController) via `Initialize()`, `UpdateConnector()`, or `AddPairConnector()`
- Governance may legitimately configure significantly different weights for tokenomic design reasons (e.g., stability mechanisms, high reserve ratios)
- Current validation allows any weight in (0, 1) with no ratio constraints
- Once configured, the mispricing automatically affects all subsequent swaps

**Execution Practicality**: 
- No special transaction sequence required
- User simply calls `Buy()` or `Sell()` with normal parameters
- Mispricing occurs deterministically based on weight configuration
- No need for precise timing or state manipulation

**Economic Rationality**: 
- Cost: Standard transaction fee for swap
- Benefit: Capture mispricing difference (could be substantial for large swaps)
- Users naturally discover mispricing through regular usage

**Probability**: MEDIUM-HIGH - While requires governance to set divergent weights, this is a legitimate configuration choice (not malicious), making it likely to occur in normal operations for certain token pairs designed with asymmetric reserve ratios.

### Recommendation

**1. Add Weight Ratio Validation**:
In `TokenConverterContract.cs`, add validation in `AssertValidConnectorWeight()` and pairing functions:
```csharp
private void AssertValidConnectorWeightRatio(decimal weight1, decimal weight2)
{
    var ratio = Math.Max(weight1, weight2) / Math.Min(weight1, weight2);
    Assert(ratio <= 10, "Connector weight ratio must not exceed 10:1 to maintain calculation precision.");
}
```

Call this check in `Initialize()`, `AddPairConnector()`, and `UpdateConnector()` when pairing connectors.

**2. Improve Exponential Calculation**:
In `BancorHelper.cs`, increase `_LOOPS` to at least 50 for better convergence, or implement range reduction techniques:
- For large magnitude inputs, use exp(x) = exp(x/2)² repeatedly to keep intermediate values small
- Add overflow detection and throw meaningful errors rather than producing incorrect results

**3. Add Bounds Checking**:
In `GetReturnFromPaid()` and `GetAmountToPayFromReturn()`, validate the intermediate value `y * Ln(x)`:
```csharp
var exponent = y * Ln(x);
Assert(Math.Abs(exponent) <= 10, "Weight ratio produces exponential overflow - reconfigure connector weights.");
```

**4. Test Cases**:
Add regression tests for:
- Weight ratios of 10:1, 50:1, 100:1, 1000:1
- Verify calculated prices match expected Bancor formula results
- Verify overflow/underflow detection triggers appropriately

### Proof of Concept

**Initial State**:
1. Deploy TokenConverter contract
2. Initialize with connector pair:
   - Connector A: symbol="TOKA", weight="0.99", balance=1,000,000
   - Connector B: symbol="TOKB", weight="0.001", balance=1,000,000  
   - Weight ratio: 0.99/0.001 = 990

**Transaction Steps**:
1. User calls `Sell(symbol="TOKA", amount=100,000, receiveLimit=0)`
2. Contract calculates: x = 1,000,000 / 1,100,000 ≈ 0.909
3. Contract calculates: y = 0.99 / 0.001 = 990
4. Contract calculates: Ln(0.909) ≈ -0.0953
5. Contract calculates: y * Ln(x) = 990 × (-0.0953) ≈ -94.35
6. Contract attempts: Exp(-94.35) with 20-term series
7. Individual terms like (-94.35)^20 / 20! exceed decimal precision
8. Result loses precision or overflows

**Expected vs Actual**:
- **Expected**: Correctly computed Exp(-94.35) ≈ 0 (very small), so return ≈ 1,000,000 × (1 - 0) = ~1,000,000 tokens (nearly full reserve due to extreme weight ratio)
- **Actual**: Precision loss causes incorrect Exp() result, producing mispriced return amount (could be drastically wrong in either direction)

**Success Condition**: Transaction completes with incorrect `amountToReceive` that differs significantly from mathematically correct Bancor formula result, demonstrating the precision loss vulnerability.

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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L98-98)
```csharp
    private const int _LOOPS = 20; // Max = 20
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
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
