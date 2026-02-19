### Title
Arithmetic Overflow in BancorHelper Exponential Calculations Causes Token Conversion DoS

### Summary
The `GetReturnFromPaid` function in `BancorHelper.cs` lacks upper bounds validation on input parameters and intermediate calculations, allowing arithmetic overflow in the exponential helper functions when extreme connector weight ratios are combined with large trade amounts. This causes transaction reversion and denial of service for token conversion operations.

### Finding Description

The vulnerability exists in the Bancor formula calculation flow: [1](#0-0) 

The input validation only checks for positive values, with no upper bounds: [2](#0-1) 

When connector weights differ, the calculation uses exponential functions where `y = fromConnectorWeight / toConnectorWeight` can be very large if weight ratios are extreme: [3](#0-2) 

The `Exp` function uses a power series expansion that calls `Pow` for each term: [4](#0-3) 

The `Pow` function performs binary exponentiation through repeated squaring: [5](#0-4) 

**Root Cause:** When the argument to `Exp` has large magnitude (e.g., y * Ln(x) ≈ -159), calculating `Pow(y, 20)` causes decimal overflow. For example, with y = -159.3, the calculation of `159.3^20` (approximately 10^44) exceeds `decimal.MaxValue` (7.9 × 10^28), throwing an `OverflowException`.

**Why Existing Protections Fail:** Connector weights are validated to be between 0 and 1: [6](#0-5) 

However, this allows extreme ratios (e.g., wf=0.99, wt=0.01 yields ratio of 99), which when combined with large trade amounts relative to connector balance, produces overflow conditions.

**Execution Path:** The overflow occurs when users call the `Sell` function: [7](#0-6) 

### Impact Explanation

**Operational Impact:** Denial of service for token conversion operations under specific conditions:

1. Users cannot sell resource tokens when trade amounts exceed approximately 4x the connector balance with extreme weight ratios
2. Transactions revert with `OverflowException` before any state changes or token transfers occur
3. The TokenConverter becomes partially unusable for large trades on connectors with extreme weight configurations

**Who is Affected:**
- Users attempting to sell large amounts of tokens from connectors with extreme weight ratios
- The protocol's token conversion functionality becomes unreliable

**Severity Justification:** While no funds are directly stolen, this represents a **Medium severity** operational vulnerability because:
- It can render specific connector pairs unusable for large trades
- Governance could inadvertently create vulnerable configurations
- No workaround exists for affected trade sizes except selling in multiple smaller transactions

### Likelihood Explanation

**Attacker Capabilities:** Any user can trigger the overflow by calling the public `Sell` function with large amounts.

**Attack Complexity:** Low - requires only a single transaction calling `Sell` with amount > 4x connector balance.

**Feasibility Conditions:**
- Connector must have extreme weight ratio (e.g., 99:1 or higher)
- Trade amount must be large relative to `fromConnectorBalance`
- Example: wf=0.99, wt=0.01, paidAmount > 4 × fromConnectorBalance

**Realistic Scenario:**
Token supply values are typically in the range of 10^16 to 10^17 based on economic constants: [8](#0-7) 

With connector balances in this range and governance-controlled weight configurations, the overflow conditions are achievable.

**Probability:** Medium - requires governance to set extreme weight ratios (not malicious, but possible for legitimate reasons like bootstrapping liquidity).

### Recommendation

1. **Add upper bounds validation** in `GetReturnFromPaid`:
   - Validate that `fromConnectorWeight / toConnectorWeight` ratio is within safe bounds (e.g., < 100)
   - Validate that `paidAmount` relative to `fromConnectorBalance` is within safe bounds (e.g., < 1000x)
   - Add pre-calculation checks before calling `Exp` to ensure argument magnitude is within safe range

2. **Add safe arithmetic wrappers** around exponential calculations:
   - Wrap `Pow` function with magnitude checks before computation
   - Limit the number of iterations or use alternative calculation methods for extreme inputs

3. **Add invariant documentation** specifying safe parameter ranges for connector weights and trade amounts

4. **Add regression tests** covering edge cases:
   - Test with extreme weight ratios (e.g., 0.99/0.01)
   - Test with large trade amounts (e.g., 100x connector balance)
   - Verify graceful failure with clear error messages rather than arithmetic overflow

### Proof of Concept

**Initial State:**
- Connector A: weight = 0.99, balance = 1,000,000 tokens
- Connector B: weight = 0.01, balance = 1,000,000 tokens  
- User holds 5,000,000 tokens of Connector A

**Transaction Steps:**
1. User calls `Sell` with Symbol=ConnectorA, Amount=5,000,000
2. `GetReturnFromPaid` calculates:
   - y = 0.99 / 0.01 = 99
   - x = 1,000,000 / (1,000,000 + 5,000,000) = 0.167
   - Ln(0.167) ≈ -1.79
   - y × Ln(x) ≈ -177
3. `Exp(-177)` attempts to calculate `Pow(-177, 20)`
4. Intermediate calculation `177^20` ≈ 10^45 exceeds decimal.MaxValue

**Expected Result:** Token conversion succeeds and returns calculated amount

**Actual Result:** Transaction reverts with `OverflowException` during exponential calculation

**Success Condition:** Transaction reverts, confirming the DoS vulnerability exists for the specified parameters

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
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

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L11-11)
```csharp
    public const long ResourceTokenTotalSupply = 500_000_000_00000000;
```
