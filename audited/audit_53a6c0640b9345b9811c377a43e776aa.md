### Title
Taylor Series Truncation in Exp Function Causes Convergence Failure for Large Exponents in Token Conversion

### Summary
The `Exp` function in BancorHelper uses only 20 iterations of the Taylor series expansion, which is insufficient for large exponents that can occur during token conversion operations. When connector weights are set to extreme ratios by governance and users attempt large trades, the exponent `y * ln(x)` can exceed the convergence range, causing the function to return wildly incorrect values that lead to transaction failures (DoS) or potential mispricing.

### Finding Description

The `Exp` function implements exponential calculation using a truncated Taylor series: [1](#0-0) 

The critical issue occurs in the `GetReturnFromPaid` function used during Sell operations: [2](#0-1) 

The exponent passed to `Exp` is `y * Ln(x)` where:
- `y = fromConnectorWeight / toConnectorWeight` (weight ratio)
- `x = fromConnectorBalance / (fromConnectorBalance + paidAmount)` 

**Root Cause**: Connector weights are only constrained to be between 0 and 1: [3](#0-2) 

This allows governance to create extreme weight ratios. For example, if ResourceWeight = 0.5 and NativeWeight = 0.01, then y = 50. When a user sells a large amount relative to the connector balance:
- If `fromConnectorBalance = 10,000,000` and `paidAmount = 90,000,000`, then `x = 0.1`
- `Ln(0.1) ≈ -2.303`
- Exponent: `50 * (-2.303) = -115.15`

For `exp(-115.15)`, the 20-term Taylor series does not converge. The true value is approximately `3.6e-51` (essentially zero), but the partial sum oscillates wildly between large positive and negative values because the terms grow until around `n = |exponent| = 115` before factorial dominance kicks in. Since we only sum to `n = 20`, we capture the oscillating growth phase but miss convergence.

The `Ln` function constraint only prevents |1-a| >= 1, not extreme exponents after weight multiplication: [4](#0-3) 

Production configuration shows extreme weight ratios are possible via governance: [5](#0-4) 

### Impact Explanation

**Primary Impact - Denial of Service**: When the `Exp` function returns an incorrect value (e.g., large positive number instead of ~0), the formula `Return = bt * (1 - Exp(...))` produces:
- Negative return values (causing transaction revert)
- Values exceeding connector balance (causing underflow/assertion failure)
- This renders Sell operations unusable for large trades when weight ratios are extreme

**Secondary Impact - Potential Mispricing**: In edge cases where the incorrect `Exp` value happens to fall in a valid range (0, 1) but is significantly wrong, users could receive incorrect amounts during token swaps. For example, if the true value should be 1e-30 but the function returns 0.1, the seller would receive only 90% of what they should instead of ~100%.

**Affected Users**: 
- Token sellers unable to execute large trades
- All users if governance misconfigures weights
- TokenConverter contract functionality degraded

**Severity Justification**: While direct fund theft is unlikely (most errors cause transaction failure), this creates operational DoS of a critical protocol component and potential for economic loss through mispricing.

### Likelihood Explanation

**Attacker Capabilities**: 
- Cannot directly manipulate weights (requires governance)
- Can accumulate large token amounts through trading or collaboration
- Can attempt large sell transactions

**Feasibility Conditions**:
1. Governance sets connector pairs with weight ratio > 10 via `AddPairConnector` or `UpdateConnector`
2. Sufficient token supply distributed to enable large sells
3. Connector balance reduced through prior trading activity

**Realistic Scenario**:
Given the production token supply of 500 million resource tokens and virtual balances: [6](#0-5) 

If governance configures a new connector pair with weights 0.5 and 0.05 (ratio of 10), and a user accumulates 50 million tokens to sell when connector has 5 million remaining, the exponent would be: `10 * ln(5M / 55M) ≈ 10 * (-2.4) = -24`, causing significant convergence error.

**Probability**: Medium-Low in default configuration (weights are equal), but Medium-High if governance creates connectors with extreme weight ratios for specialized token pairs.

### Recommendation

**Code-Level Mitigation**:
1. Add validation to prevent extreme weight ratios in connector creation:
```csharp
private void AssertValidConnectorWeight(Connector connector)
{
    var weight = AssertedDecimal(connector.Weight);
    Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
    
    // Add: Prevent extreme weight ratios by enforcing minimum weight
    Assert(weight >= 0.01m, "Connector weight must be at least 0.01 to prevent convergence issues.");
    
    connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
}
```

2. Increase `_LOOPS` to at least 50-100 iterations, or implement adaptive iteration count based on exponent magnitude:
```csharp
private static decimal Exp(decimal y)
{
    var maxIterations = Math.Max(50, (int)(Math.Abs(y) * 2)); // Adaptive
    var iteration = Math.Min(maxIterations, 100); // Cap at 100
    decimal result = 1;
    // ... rest of implementation
}
```

3. Add bounds checking before calling Exp to fail fast:
```csharp
var exponent = y * Ln(x);
Assert(Math.Abs(exponent) < 15, "Exponent too large for accurate calculation");
return (long)(bt * (decimal.One - Exp(exponent)));
```

**Test Cases**:
- Test Exp convergence for exponents: -50, -25, -10, 10, 25
- Test GetReturnFromPaid with extreme weight ratios (0.5/0.01) and large sell amounts
- Verify transaction failures occur gracefully with clear error messages
- Test round-trip: Buy then immediately Sell should return approximately original amount

### Proof of Concept

**Initial State**:
1. Governance creates connector pair via `AddPairConnector`:
   - ResourceWeight = "0.5"
   - NativeWeight = "0.05" 
   - ResourceSymbol = "EXTREME"
2. Users buy tokens, reducing connector balance to 5,000,000
3. Attacker accumulates 45,000,000 EXTREME tokens

**Attack Steps**:
1. Attacker calls `Sell` with:
   - Symbol = "EXTREME"
   - Amount = 45,000,000
   
**Calculation Flow**:
- fromConnector balance (bf) = 5,000,000
- toConnector balance (bt) = 50,000,000 (native deposit)
- y = 0.5 / 0.05 = 10
- x = 5,000,000 / 50,000,000 = 0.1
- Ln(0.1) ≈ -2.303
- Exponent = 10 * (-2.303) = -23.03
- Exp(-23.03) with 20 iterations returns incorrect value (should be ~1e-10)

**Expected Result**: Return ≈ 50,000,000 * (1 - 1e-10) ≈ 49,999,999 (seller gets nearly all base tokens)

**Actual Result**: Exp function returns wildly incorrect value, causing either:
- Transaction failure due to negative/overflow result
- Incorrect payout amount if value happens to be in valid range

**Success Condition**: Transaction fails or seller receives significantly incorrect amount, demonstrating convergence failure impact.

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L418-423)
```csharp
    private void AssertValidConnectorWeight(Connector connector)
    {
        var weight = AssertedDecimal(connector.Weight);
        Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
        connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L211-260)
```csharp
    private void InitializeTokenConverterContract()
    {
        State.TokenConverterContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName);
        var connectors = new List<Connector>
        {
            new()
            {
                Symbol = Context.Variables.NativeSymbol,
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
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
                VirtualBalance = EconomicContractConstants.ResourceTokenInitialVirtualBalance,
                RelatedSymbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsDepositAccount = false
            };
            var nativeTokenConnector = new Connector
            {
                Symbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
                VirtualBalance = EconomicContractConstants.NativeTokenToResourceBalance,
                RelatedSymbol = resourceTokenSymbol,
                IsDepositAccount = true
            };
            connectors.Add(resourceTokenConnector);
            connectors.Add(nativeTokenConnector);
        }

        State.TokenConverterContract.Initialize.Send(new InitializeInput
        {
            FeeRate = EconomicContractConstants.TokenConverterFeeRate,
            Connectors = { connectors },
            BaseTokenSymbol = Context.Variables.NativeSymbol
        });
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L10-20)
```csharp
    // Resource token related.
    public const long ResourceTokenTotalSupply = 500_000_000_00000000;

    public const int ResourceTokenDecimals = 8;

    //resource to sell
    public const long ResourceTokenInitialVirtualBalance = 100_000;

    public const string NativeTokenPrefix = "nt";

    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```
