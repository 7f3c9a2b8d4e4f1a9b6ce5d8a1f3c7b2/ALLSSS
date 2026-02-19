# Audit Report

## Title
Extreme Weight Ratios Cause Numerical Overflow and DoS in Bancor Price Calculation

## Summary
The TokenConverter's Bancor formula implementation contains a critical flaw where extreme weight ratios (100x) combined with large purchase amounts (>50% of connector balance) cause transaction failures due to mathematical constraint violations in the `Ln` function. This creates a denial-of-service condition that blocks legitimate token conversions and affects the protocol's ability to process resource token purchases needed for transaction fees.

## Finding Description

The vulnerability exists in the `GetAmountToPayFromReturn` method where the calculation `x = bt / (bt - a)` lacks validation that the resulting value satisfies the `Ln` function's constraint of `0 < a < 2`. [1](#0-0) 

The `Ln` function explicitly enforces this constraint by throwing an `InvalidValueException` with message "must be 0 < a < 2" when violated. [2](#0-1) 

When a user attempts to buy more than 50% of the available connector balance, the calculation produces `x > 2` (since `x = bt / (bt - a)` and when `a > 0.5 * bt`, then `bt - a < 0.5 * bt`, making `x > 2`), which violates the `Ln` constraint and causes the transaction to fail.

The production configuration exacerbates this issue by using extreme weight ratios. The native token connector uses weight "0.5" [3](#0-2)  while resource token connectors use weight "0.005" [4](#0-3) , creating a 100x weight ratio.

The `Exp` function uses only a 20-term Taylor series approximation without overflow protection. [5](#0-4)  With extreme ratios, even amounts below 50% (e.g., 49%) can produce values like `y * Ln(x) = 100 * 0.673 = 67.3`, where `Exp(67.3) ≈ 10^29` exceeds `decimal.MaxValue` or produces inaccurate results due to insufficient Taylor series terms.

The `Buy` function calls this calculation directly without try-catch or pre-validation. [6](#0-5) 

Weight validation only ensures individual weights are between 0 and 1, but does not limit their ratios. [7](#0-6) 

## Impact Explanation

**Denial of Service**: Any user (malicious or legitimate) attempting to purchase more than 50% of a connector's available balance will experience transaction failure with the "must be 0 < a < 2" exception. This creates an artificial cap on purchase size that is not documented and prevents legitimate large-scale token conversions.

**Critical Protocol Functionality Affected**: Resource token conversions are essential for users to pay transaction fees. The DoS on these conversions can prevent users from acquiring the tokens needed to interact with the protocol, effectively blocking their participation.

**Numerical Instability**: For purchases between 40-50% of available balance with 100x weight ratios, the exponential calculations become numerically unstable, potentially causing overflow exceptions or producing incorrect prices that differ from the intended Bancor formula results.

**Economic Exploitation**: Attackers can identify connectors with low balances and repeatedly submit transactions to buy >50% of the balance, blocking all other users from converting through that connector until the attacker's transactions are processed or expire.

## Likelihood Explanation

**Attack Complexity: LOW** - The vulnerability requires only a single `Buy` transaction with an amount parameter exceeding 50% of the connector's current balance. No special privileges, complex multi-step operations, or sophisticated techniques are needed.

**Preconditions: Already Met in Production** - The vulnerable weight ratios (0.5 for native tokens, 0.005 for resource tokens) are already configured in the production deployment through the `InitializeTokenConverterContract` method, making this immediately exploitable.

**Attacker Capabilities: Minimal** - Any user with sufficient base tokens to attempt a large purchase can trigger this vulnerability. The attacker needs only to:
1. Query the current connector balance (publicly available via view methods)
2. Submit a `Buy` transaction with `input.Amount > GetSelfBalance(toConnector) / 2`

**Realistic Scenario**: Even legitimate whales or institutional users attempting large-scale conversions would trigger this issue unintentionally, making this not just an attack vector but also a usability problem affecting honest users.

**No Mitigations in Place**: The code contains no pre-validation checks, try-catch blocks, or alternative calculation paths to handle or prevent this condition.

## Recommendation

Implement the following mitigations:

1. **Add Pre-Validation**: Before calling `GetAmountToPayFromReturn`, validate that `amountToReceive < toConnectorBalance * max_safe_ratio` where `max_safe_ratio` is conservatively set based on the weight ratios (e.g., 0.4 for safety margin).

2. **Limit Weight Ratios**: Add validation in `AssertValidConnectorWeight` and `UpdateConnector` to ensure weight ratios between any two connected connectors do not exceed a safe threshold (e.g., 10x).

3. **Improve Numerical Stability**: Replace the 20-term Taylor series with a more robust implementation that either:
   - Uses more terms for large inputs
   - Implements range reduction techniques for large exponents
   - Uses built-in decimal logarithm/exponential functions if available

4. **Add Explicit Limit Documentation**: Document the maximum purchase size constraint in the contract interface and return a user-friendly error message when exceeded.

## Proof of Concept

```csharp
// Test demonstrating the DoS vulnerability
[Fact]
public async Task BuyMoreThan50Percent_CausesDoS()
{
    // Setup: Get a connector with known balance
    var connectorBalance = await GetConnectorBalance("RESOURCE_TOKEN");
    
    // Attempt to buy 51% of available balance
    var amountToBuy = (long)(connectorBalance * 0.51m);
    
    // This will throw "must be 0 < a < 2" exception
    var result = await TokenConverterStub.Buy.SendAsync(new BuyInput
    {
        Symbol = "RESOURCE_TOKEN",
        Amount = amountToBuy,
        PayLimit = 0  // No price limit
    });
    
    // Verify transaction fails with the mathematical constraint error
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("must be 0 < a < 2");
}
```

**Notes:**
- This vulnerability affects all connector pairs with significant weight disparities, which includes the production configuration of native tokens (0.5 weight) and resource tokens (0.005 weight).
- The 50% threshold is a mathematical consequence of the `Ln` function's constraint (`0 < a < 2`), not an intentional design limit.
- Even without malicious intent, legitimate users attempting large conversions will encounter this issue, representing a usability and availability problem beyond just a security concern.

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

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L222-222)
```csharp
                Weight = "0.5",
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L418-422)
```csharp
    private void AssertValidConnectorWeight(Connector connector)
    {
        var weight = AssertedDecimal(connector.Weight);
        Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
        connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
```
