### Title
Incorrect Factorial Array Initialization in Exp() Causes Systematic Bancor Pricing Errors

### Summary
The `Exp()` function in `BancorHelper.cs` uses an incorrectly initialized factorial array that contains factorials 0! through 19! instead of 1! through 20!. This causes the exponential calculation to use wrong factorial values (e.g., using 1! instead of 2! for the y²/2! term), resulting in systematically inflated exponential results that corrupt Bancor pricing formulas in all token swap operations with non-equal connector weights.

### Finding Description

The root cause is an off-by-one error between factorial array initialization and usage: [1](#0-0) 

The static constructor initializes `Fact` with indices 0-19 containing values 0!, 1!, 2!, ..., 19! respectively. [2](#0-1) 

In the `Exp()` function, when computing the term y^n/n! for the exponential series, the code accesses `Fact[iteration - 1]`. When `iteration = n`, this retrieves `Fact[n-1] = (n-1)!` instead of the required `n!`.

**Incorrect calculation:**
- iteration=2: y²/Fact[1] = y²/1! = y² (should be y²/2! = y²/2)
- iteration=3: y³/Fact[2] = y³/2! = y³/2 (should be y³/3! = y³/6)
- iteration=20: y²⁰/Fact[19] = y²⁰/19! (should be y²⁰/20!)

**Comparison with test version:** [3](#0-2) 

The test version explicitly initializes the array with 1!, 2!, 3!, ..., 20!, making the same indexing pattern `Fact[iteration - 1]` retrieve the correct factorial values.

**Affected operations:** [4](#0-3) [5](#0-4) 

Both `Buy()` and `Sell()` operations use `BancorHelper.GetAmountToPayFromReturn()` and `BancorHelper.GetReturnFromPaid()`, which call the buggy `Exp()` function when connector weights differ. [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Economic Impact:**
- Every token swap with non-equal connector weights (wf ≠ wt) uses the incorrect exponential calculation
- The error magnitude increases with transaction size and weight ratio differences
- For exp(0.1), error is ~0.5%; for exp(0.2), error is ~1.7%
- Users systematically receive incorrect token amounts (either more or less depending on swap direction)

**Arbitrage Vulnerability:**
- If external systems use correct Bancor implementations, price discrepancies enable arbitrage
- Attackers can exploit the predictable pricing error to drain reserves over multiple transactions

**Reserve Imbalance:**
- Accumulated pricing errors across many swaps lead to gradual reserve depletion or accumulation
- Protocol's economic balance deviates from intended Bancor curve dynamics

**Affected Users:**
- All users performing token conversions through the TokenConverter contract
- Both buy and sell operations are affected
- Impact scales with trading volume and price volatility

### Likelihood Explanation

**Attacker Capabilities:**
- No special permissions required - any user can call `Buy()` or `Sell()`
- Attack is completely passive - simply using the contract as intended triggers the bug

**Attack Complexity:**
- Extremely low - the bug is always active for all non-equal-weight swaps
- No complex setup or timing requirements
- Mathematical error is deterministic and predictable

**Feasibility Conditions:**
- Connector weights must differ (wf ≠ wt) to trigger `Exp()` calls
- Based on test configurations, typical weights range from 0.005 to 0.5, making this the common case
- Every transaction with differing weights is affected

**Detection Constraints:**
- Pricing errors may appear as normal market fluctuations initially
- Requires mathematical analysis to detect the systematic bias
- Users may not notice small percentage errors per transaction

**Probability:** HIGH - The vulnerability is always present and affects the majority of token swap operations in normal usage.

### Recommendation

**Fix the factorial array initialization** to match the test version:

Replace the dynamic initialization:
```csharp
Fact = Array.AsReadOnly(Enumerable.Range(0, 20).Select(x => DynFact(x)).ToArray());
```

With explicit initialization computing factorials 1! through 20!:
```csharp
Fact = Array.AsReadOnly(Enumerable.Range(1, 20).Select(x => DynFact(x)).ToArray());
```

Or use the explicit array literal approach from the test version.

**Add unit tests** comparing contract and test BancorHelper outputs to prevent regression:
- Test `Exp()` function directly with known values
- Verify exp(0.1) ≈ 1.10517, exp(0.2) ≈ 1.22140
- Test `GetReturnFromPaid()` and `GetAmountToPayFromReturn()` match expected Bancor formulas
- Add property-based tests verifying pricing formulas remain consistent across versions

**Validate existing reserves** after deployment to check for accumulated imbalances from the bug.

### Proof of Concept

**Initial State:**
- TokenConverter contract deployed with default connector configuration
- Two connectors with weights wf=0.5, wt=0.6 (non-equal)
- Connector balances: fromBalance=1,000,000, toBalance=1,000,000

**Attack Steps:**

1. User calls `Sell()` with amount=10,000 tokens of resource token
2. Contract calculates: `amountToReceive = BancorHelper.GetReturnFromPaid(1000000, 0.5, 1000000, 0.6, 10000)`
3. This calls `Exp((0.5/0.6) * Ln(1000000/1010000))`
4. The argument to Exp() ≈ -0.0082
5. **Buggy calculation**: Uses wrong factorials, returns incorrect value
6. User receives systematically wrong token amount

**Expected Result:** 
Correct Bancor formula: Return = (1 - (1000000/1010000)^(0.5/0.6)) * 1000000 ≈ 8,264 tokens

**Actual Result:**
Buggy exponential causes deviation from correct Bancor pricing by 0.5-2% depending on transaction parameters.

**Success Condition:**
- Compare return values from contract version vs test version of BancorHelper
- Mathematical proof: Exp() uses (n-1)! instead of n! for all terms except y¹/1!
- Demonstrates systematic pricing error affecting all swaps with non-equal weights

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L11-14)
```csharp
    static BancorHelper()
    {
        Fact = Array.AsReadOnly(Enumerable.Range(0, 20).Select(x => DynFact(x)).ToArray());
    }
```

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

**File:** test/AElf.Contracts.TokenConverter.Tests/BancorHelper.cs (L78-102)
```csharp
    private static readonly long[] Fact =
    {
        1L,
        1L * 2,
        1L * 2 * 3,
        1L * 2 * 3 * 4,
        1L * 2 * 3 * 4 * 5,
        1L * 2 * 3 * 4 * 5 * 6,
        1L * 2 * 3 * 4 * 5 * 6 * 7,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19,
        1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19 * 20
        //14197454024290336768L, //1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19 * 20 * 21,        // NOTE: Overflow during compilation
        //17196083355034583040L, //1L * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9 * 10 * 11 * 12 * 13 * 14 * 15 * 16 * 17 * 18 * 19 * 20 * 21 * 22    // NOTE: Overflow during compilation
    };
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-124)
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
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());
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
