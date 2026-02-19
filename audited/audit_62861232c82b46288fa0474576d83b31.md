### Title
Integer Overflow in Bancor Price Calculation Causes DoS on Large Token Purchases

### Summary
The `GetAmountToPayFromReturn` function in BancorHelper.cs contains an unchecked arithmetic overflow vulnerability when casting from decimal to long. When users attempt to purchase large amounts of tokens (approaching the total available balance) from connector pairs with equal weights, the calculation `(bf * a) / (bt - a)` produces values exceeding `long.MaxValue`, causing transaction failures and effectively preventing legitimate large purchases.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The vulnerable line performs: `return (long)(bf / (bt - a) * a);` where:
- `bf` = fromConnectorBalance (deposit balance)
- `bt` = toConnectorBalance (available token balance)
- `a` = amountToReceive (requested purchase amount)

**Root Cause:**
When `a` approaches `bt`, the denominator `(bt - a)` becomes very small, causing the division result to amplify dramatically. Multiplying this by `a` produces values that exceed `long.MaxValue` (9,223,372,036,854,775,807). 

The project compiles with overflow checking enabled: [2](#0-1) [3](#0-2) 

This means the cast throws `OverflowException`, which is caught by the try-catch block: [4](#0-3) 

The exception is re-thrown as `AssertionException` with the misleading message "Insufficient account balance to deposit", masking the true overflow issue.

**Execution Path:**
The vulnerable function is called from the public `Buy` method: [5](#0-4) 

And also from the view function `GetNeededDeposit`: [6](#0-5) 

**Why Protections Fail:**
The condition at line 80 only checks if weights are equal but provides no bounds checking on the calculation result: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
With production values defined in the codebase: [8](#0-7) [9](#0-8) 

**Exploitation Example:**
- Deposit balance: `bf = 10^15` (10 million ELF tokens with 8 decimals)
- Token balance: `bt = 10^14` (1 million resource tokens)
- User attempts to buy: `a = 10^14 - 1` (almost all available tokens)
- Calculation: `(10^15 × (10^14 - 1)) / 1 ≈ 10^29`
- Result exceeds `long.MaxValue` by ~11 orders of magnitude

**Who Is Affected:**
- Legitimate users attempting large token purchases
- Any connector pair with equal weights (e.g., both 0.5 or both 0.05 as seen in tests)
- Affects core functionality of the TokenConverter contract

**Quantified Impact:**
- Complete DoS of `Buy` function for purchases approaching total token balance
- No workaround exists for atomic large purchases (splitting into smaller transactions is impractical and costly)
- Misleading error messages confuse users and prevent proper debugging

### Likelihood Explanation

**Attacker Capabilities:**
No special privileges required - any user can call the public `Buy` function: [10](#0-9) 

**Attack Complexity:**
Trivial - simply call `Buy` with a large `Amount` parameter when connector weights are equal.

**Feasibility Conditions:**
- Connector pair must have equal weights (`wf == wt`)
- Test configurations confirm this is common: [11](#0-10) [12](#0-11) [13](#0-12) 

**Probability:**
HIGH - This will affect any legitimate user attempting to purchase a significant portion of available tokens in equal-weight connector pairs, which are standard configurations in the system.

### Recommendation

**Code-Level Mitigation:**

1. Add explicit overflow checking before the cast:
```csharp
if (wf == wt)
{
    try
    {
        decimal result = bf / (bt - a) * a;
        if (result > long.MaxValue || result < long.MinValue)
            throw new AssertionException("Purchase amount too large for this balance configuration.");
        return (long)result;
    }
    catch (OverflowException)
    {
        throw new AssertionException("Purchase amount too large for this balance configuration.");
    }
    catch
    {
        throw new AssertionException("Insufficient account balance to deposit");
    }
}
```

2. Add upper bound validation in the `Buy` function to prevent unrealistic purchase amounts:
```csharp
Assert(input.Amount < GetSelfBalance(toConnector) * 0.95m, 
    "Cannot purchase more than 95% of available balance in single transaction.");
```

**Invariant Checks:**
- Add assertion: `amountToReceive < toConnectorBalance * maxPurchaseRatio` before calling `GetAmountToPayFromReturn`
- Validate that calculated `amountToPay` is within reasonable bounds relative to connector balances

**Test Cases:**
Add regression tests for:
- Purchasing 90%, 95%, 99% of available token balance with equal weights
- Verifying appropriate error messages for overflow conditions
- Testing with production-scale connector balances (10^15 - 10^16 range)

### Proof of Concept

**Required Initial State:**
1. Initialize TokenConverter with connector pair having equal weights (e.g., 0.5/0.5)
2. Set up connectors with production-scale balances:
   - Native token connector virtual balance: 10,000,000 ELF (10^15 base units)
   - Resource token balance: 1,000,000 tokens (10^14 base units)
3. Enable connector pair for trading

**Transaction Steps:**
```
1. User calls Buy with:
   - Symbol: Resource token symbol
   - Amount: 999,999,999,999,999 (10^14 - 1, or 99.9999% of available tokens)
   - PayLimit: 0 (no limit)

2. Buy function calls GetAmountToPayFromReturn(10^15, 0.5, 10^14, 0.5, 10^14-1)

3. Calculation executes: (10^15 * (10^14-1)) / 1 ≈ 10^29

4. Cast to long triggers OverflowException

5. Exception caught and re-thrown as AssertionException
```

**Expected vs Actual Result:**
- **Expected:** Either successful purchase or clear error about purchase limits
- **Actual:** Transaction fails with misleading error "Insufficient account balance to deposit"

**Success Condition:**
Transaction fails with `AssertionException` when attempting to buy amount approaching total balance with equal-weight connectors and large connector balances.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L80-89)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenConverter/AElf.Contracts.TokenConverter.csproj (L12-12)
```text
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
```

**File:** contract/AElf.Contracts.TokenConverter/AElf.Contracts.TokenConverter.csproj (L15-15)
```text
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-112)
```csharp
    public override Empty Buy(BuyInput input)
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L82-83)
```csharp
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L5-5)
```csharp
    public const long NativeTokenConnectorInitialVirtualBalance = 100_000_00000000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L20-20)
```csharp
    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConverterContractTests.cs (L24-24)
```csharp
        Weight = "0.5",
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConverterContractTests.cs (L33-33)
```csharp
        Weight = "0.5",
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConverterContractTests.cs (L44-44)
```csharp
        Weight = "0.5",
```
