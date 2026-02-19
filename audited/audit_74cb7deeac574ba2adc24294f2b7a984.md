### Title
Arithmetic Overflow in Bancor Formula with Extreme Weight Ratios Causes DoS of Token Conversion Operations

### Summary
The TokenConverter's Bancor pricing formula calculates exponential functions using weight ratios without bounds checking. When connector pairs are configured with extreme weight ratios (e.g., 0.001 and 0.999, yielding a 999:1 ratio), the exponential calculation overflows during large buy/sell operations, causing transaction reverts and complete denial-of-service for affected trading pairs.

### Finding Description

The vulnerability exists in the Bancor price calculation implementation: [1](#0-0) 

At line 92, the weight ratio `y = wt / wf` is calculated without bounds checking. This ratio is then used in the exponential function: [2](#0-1) 

The `Exp()` function computes `exp(y) = 1 + y + y²/2! + y³/3! + ... + y²⁰/20!` using 20 iterations. When `y * Ln(x)` is large (e.g., 692 for a 999:1 ratio with x approaching 2), calculating `Pow(692, 20)` exceeds `decimal.MaxValue` (~7.9×10²⁸), as 692²⁰ ≈ 10⁵⁶. [3](#0-2) 

The overflow occurs in the `Pow()` function at line 115-116, where repeated multiplications cause arithmetic overflow, triggering `System.OverflowException`.

**Entry Points:** [4](#0-3) [5](#0-4) 

**Insufficient Protection:**

The weight validation only checks that individual weights are between 0 and 1, but does not limit the ratio between paired connectors: [6](#0-5) [7](#0-6) 

Mathematical analysis shows that weight ratios exceeding ~40:1 cause overflow when users attempt to buy/sell amounts where `x = balance/(balance - amount)` approaches 2 (the maximum allowed by the `Ln()` constraint at line 131-132 of BancorHelper.cs).

### Impact Explanation

**Operational Impact - Complete DoS of Token Conversion:**
- All `Buy()` and `Sell()` transactions for affected connector pairs revert with `OverflowException`
- Users cannot purchase or sell tokens through the converter
- Liquidity becomes permanently locked in the connector pair until governance reconfigures the weights
- The `GetNeededDeposit()` view function also fails, preventing proper UI/frontend integration

**Affected Parties:**
- Token holders unable to trade through the converter
- Protocols relying on TokenConverter for automated price discovery
- Users needing to swap between native tokens and resource tokens

**Severity Justification:**
The vulnerability causes complete loss of functionality for affected trading pairs, equivalent to a critical operational failure. While it requires initial governance configuration of extreme ratios, such configurations are permitted by current validation logic and could be set intentionally for specific economic designs or accidentally without understanding the mathematical implications.

### Likelihood Explanation

**Preconditions:**
1. Governance (connector controller) configures a connector pair with weight ratio > ~40:1
2. Individual weights like 0.001 and 0.999 pass existing validation
3. Users attempt buy/sell operations with amounts approaching half the connector balance

**Attack Complexity:**
- **Low** - Once preconditions are met, any standard Buy/Sell transaction triggers the overflow
- No special permissions or sophisticated techniques required
- Transaction size determination is straightforward (approach balance/2)

**Feasibility Assessment:**
- Current validation explicitly allows weights between 0 and 1 (exclusive)
- Example from codebase shows weights as low as 0.005 are used in production: [8](#0-7) 

- No documentation or warnings about ratio limits exist in the code
- Governance could configure extreme ratios for legitimate economic reasons (e.g., heavily favoring one token) without realizing the mathematical consequences

**Probability:**
**Medium** - Requires governance action but within allowed parameter space. The lack of ratio validation means this is a latent bug that could manifest if:
- Economic design calls for asymmetric connector weights
- Governance updates weights incrementally, creating extreme ratios over time
- Migration or rebalancing operations temporarily create extreme configurations

### Recommendation

**1. Add Weight Ratio Validation:**

Add a check in `AssertValidConnectorWeight()` and connector initialization/update functions to validate that weight ratios between paired connectors remain within safe bounds:

```csharp
private void AssertValidConnectorPairRatio(Connector fromConnector, Connector toConnector)
{
    var fromWeight = AssertedDecimal(fromConnector.Weight);
    var toWeight = AssertedDecimal(toConnector.Weight);
    var ratio = Math.Max(fromWeight / toWeight, toWeight / fromWeight);
    Assert(ratio <= 20m, "Weight ratio between connected pairs must not exceed 20:1 to prevent arithmetic overflow.");
}
```

Apply this check in:
- `Initialize()` when adding initial connectors
- `UpdateConnector()` when modifying weights
- `AddPairConnector()` when creating new pairs

**2. Add Overflow Protection in Exp():**

Add early termination or bounds checking in the exponential calculation:

```csharp
private static decimal Exp(decimal y)
{
    Assert(Math.Abs(y) < 20m, "Exponential argument too large, risk of overflow");
    // ... existing implementation
}
```

**3. Add Regression Tests:**

Create test cases validating:
- Rejection of connector pairs with ratios > 20:1
- Successful operations with ratios near the limit
- Proper error messages for invalid configurations

### Proof of Concept

**Initial State:**
1. Governance configures connector pair with extreme weights:
   - ResourceConnector.Weight = "0.001" (wf)
   - NativeConnector.Weight = "0.999" (wt)
   - Both values pass individual validation (0 < weight < 1)

2. Connector balances initialized:
   - fromConnectorBalance = 1,000,000 tokens
   - toConnectorBalance = 1,000,000 tokens

**Exploitation Steps:**

1. User calls `Buy()` attempting to purchase 400,000 tokens (40% of balance)

2. Calculation flow:
   - `x = bt / (bt - a) = 1,000,000 / 600,000 ≈ 1.667`
   - `y = wt / wf = 0.999 / 0.001 = 999`
   - `Ln(1.667) ≈ 0.511`
   - `y * Ln(x) = 999 * 0.511 ≈ 510.5`

3. In `Exp(510.5)`, at iteration 15:
   - `Pow(510.5, 15) ≈ 10^40` exceeds `decimal.MaxValue`
   - `System.OverflowException` thrown

4. Transaction reverts, user cannot complete purchase

**Expected vs Actual Result:**
- **Expected**: Transaction completes with calculated amount to pay
- **Actual**: Transaction reverts with overflow exception, Buy operation permanently disabled for this connector pair

**Success Condition:**
The vulnerability is triggered when attempting to buy/sell with weight ratios exceeding ~40:1 and transaction amounts approaching 50% of connector balance, resulting in consistent transaction failures.

### Citations

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-123)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
        Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[Buy]Can't find from connector.");
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
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

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L230-249)
```csharp
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
```
