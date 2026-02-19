### Title
Extreme Weight Ratios Cause Numerical Overflow and DoS in Bancor Price Calculation

### Summary
The Bancor formula implementation uses extreme weight ratios (up to 100x in production: 0.5/0.005) in exponentiation calculations without proper bounds checking or overflow protection. This causes transaction failures when users attempt to buy more than 50% of available connector balance, and produces incorrect prices due to numerical instability when approaching this limit, enabling price manipulation and denial of service.

### Finding Description

The vulnerability exists in the `GetAmountToPayFromReturn` method where weight ratios are used as exponents without validation: [1](#0-0) 

The calculation `x = bt / (bt - a)` where `bt` is `toConnectorBalance` and `a` is `amountToReceive` has no validation that `a < bt`. When `a > 0.5 * bt`, then `x > 2`, which violates the constraint of the `Ln` function: [2](#0-1) 

The `Ln` function explicitly requires `0 < a < 2`, throwing an exception when this constraint is violated.

Additionally, production configuration uses extreme weight ratios. The native token uses weight 0.5, while resource tokens use weight 0.005: [3](#0-2) [4](#0-3) 

This creates a weight ratio `y = wt / wf = 0.5 / 0.005 = 100` or its inverse `0.01`. With such extreme ratios, the exponential calculation `Exp(y * Ln(x))` produces astronomically large values. For example, when a user attempts to buy 49% of available balance with a 100x weight ratio:
- `x = 100/51 ≈ 1.96`
- `y * Ln(x) = 100 * Ln(1.96) ≈ 100 * 0.673 ≈ 67.3`
- `Exp(67.3) ≈ 10^29`, which exceeds `decimal.MaxValue` (≈ 7.9 × 10^28)

The `Exp` function uses only a 20-term Taylor series approximation without overflow protection: [5](#0-4) 

The `Buy` function calls this calculation without any try-catch or pre-validation: [6](#0-5) 

Weight validation only ensures individual weights are between 0 and 1, but does not limit their ratios: [7](#0-6) 

### Impact Explanation

**Direct Operational Impact**: Any user attempting to buy more than 50% of a connector's available balance will cause the transaction to fail with "must be 0 < a < 2" exception, creating a denial-of-service condition for that connector.

**Price Manipulation**: Users attempting to buy amounts between 40-50% of available balance experience numerical instability:
- With 100x weight ratios, the Taylor series approximation becomes wildly inaccurate
- Decimal overflow may occur, causing transaction failure
- If overflow doesn't occur, the truncated series produces incorrect prices that differ significantly from the true Bancor formula

**Economic Damage**: Attackers can exploit this in two ways:
1. **DoS Attack**: Repeatedly submit transactions buying >50% of small connector balances to block legitimate conversions
2. **Arbitrage**: Identify price points where numerical errors favor the attacker, extracting value through mispriced conversions

**Affected Systems**: All token connectors with significant weight disparities are vulnerable. In production, this affects conversions between native tokens (0.5 weight) and all resource tokens (0.005 weight), which are critical for transaction fee payments.

### Likelihood Explanation

**Attack Complexity**: LOW - The attack requires only a single `Buy` transaction with an amount exceeding 50% of the connector balance. No special privileges, complex setup, or sophisticated techniques are needed.

**Attacker Capabilities**: Any user with sufficient base tokens to attempt a large purchase can trigger this vulnerability. The attacker only needs to:
1. Query the current connector balance (publicly available)
2. Submit a Buy transaction with amount > 0.5 * balance

**Feasibility Conditions**: The vulnerability is immediately exploitable in production:
- Weight ratios of 100x are already configured
- No special contract state is required
- The attack works on any connector with available balance

**Economic Rationality**: Attackers pay only gas fees to cause DoS. For price manipulation, if incorrect pricing favors the attacker by even 1%, they can profit from arbitrage while only risking gas costs.

**Detection Difficulty**: The attack is difficult to prevent at the application layer since the issue is in the core pricing formula. Transaction monitoring would only detect exploitation after damage occurs.

### Recommendation

**Immediate Mitigation**:

1. Add explicit validation in `GetAmountToPayFromReturn` to ensure `amountToReceive < toConnectorBalance`:
```csharp
Assert(amountToReceive < toConnectorBalance, 
    "Amount to receive exceeds available balance");
```

2. Add a stricter limit to prevent numerical instability, e.g., `amountToReceive < 0.4 * toConnectorBalance` to ensure `x < 1.67`.

3. Add weight ratio bounds validation in `AssertValidConnectorWeight`:
```csharp
// When connectors form a pair, validate their ratio
var ratio = Math.Max(weight1, weight2) / Math.Min(weight1, weight2);
Assert(ratio <= 10, "Weight ratio between paired connectors must not exceed 10x");
```

**Long-term Solutions**:

1. Replace the Taylor series approximation with a more robust numerical library or higher precision arithmetic that can handle extreme values.

2. Implement overflow checking in the `Exp` function:
```csharp
private static decimal Exp(decimal y)
{
    Assert(Math.Abs(y) < 50, "Exponent too large for accurate calculation");
    // ... existing implementation
}
```

3. Add comprehensive test cases covering edge cases:
    - Amounts near 50% of balance
    - Extreme weight ratios (10x, 50x, 100x)
    - Overflow scenarios

### Proof of Concept

**Initial State**:
- Resource token connector (WRITE) with weight 0.005 and balance 100,000 tokens
- Native token connector (ntWRITE) with weight 0.005 and virtual balance 1,000,000
- When converting between resource and native via the base token (ELF with weight 0.5), effective ratio is 0.5/0.005 = 100x

**Attack Sequence**:

1. **DoS Attack**:
   - User queries connector balance: `GetPairConnector("WRITE")` returns balance 100,000
   - User submits `Buy(symbol="WRITE", amount=60000, payLimit=0)`
   - Calculation: `x = 100000/(100000-60000) = 2.5`
   - `Ln(2.5)` throws "must be 0 < a < 2"
   - Transaction fails, blocking this conversion path

2. **Numerical Instability**:
   - User submits `Buy(symbol="WRITE", amount=49000, payLimit=0)`
   - Calculation: `x = 100000/(100000-49000) ≈ 1.96`
   - With weight ratio 100: `Exp(100 * Ln(1.96)) = Exp(67.3) ≈ 10^29`
   - Exceeds `decimal.MaxValue`, causing overflow exception or incorrect result

**Expected Result**: Transaction should either complete with accurate Bancor pricing or reject with clear error about excessive amount.

**Actual Result**: Transaction fails with cryptic numerical error or produces incorrect price due to overflow/approximation errors.

**Success Condition**: Attacker successfully causes DoS or extracts value through mispriced conversions, costing only gas fees.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
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

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L222-223)
```csharp
                Weight = "0.5",
                VirtualBalance = EconomicContractConstants.NativeTokenConnectorInitialVirtualBalance
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L235-235)
```csharp
                Weight = "0.005",
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
