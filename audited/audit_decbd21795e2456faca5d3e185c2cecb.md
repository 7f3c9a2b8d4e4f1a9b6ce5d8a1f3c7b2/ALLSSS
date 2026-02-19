### Title
Delegation vs User Fee Charging Asymmetry Causes Inconsistent Token Selection for Same Transaction Type

### Summary
The `ChargeFirstSufficientToken` function implements asymmetric fee charging logic between delegation and direct user paths. When fee charging fails, users have a primary token fallback mechanism (lines 732-742) that delegates lack, causing the same transaction type to be charged from different tokens depending on whether delegation is used. This creates unpredictable fee behavior and potential unfairness when token market values diverge from configured fee ratios. [1](#0-0) [2](#0-1) 

### Finding Description

The root cause is an asymmetric fallback mechanism in `ChargeFirstSufficientToken`:

**Delegation Path (lines 714-720):**
- Calls `TryToChargeDelegateBaseFee` and returns immediately
- No additional fallback logic
- When charging fails, uses whatever token was found by the delegate fee function (or null) [1](#0-0) 

**User Path (lines 722-742):**
- Calls `TryToChargeUserBaseFee`
- Lines 732-742 implement a primary token fallback: when charging fails (`!chargeResult`), it overrides the symbol, existingBalance, and existingAllowance to use the primary token
- This fallback is explicitly commented as "For user, if charge failed and delegation is null, priority charge primary token" [3](#0-2) 

When `ChargeBaseFee` receives a failed result, it still adds partial payments to the bill based on the returned symbol and existingBalance: [4](#0-3) 

Additionally, `TryToChargeUserBaseFee` has a "symbolWithAnything" fallback that returns any token with balance > 0 even when insufficient, while `TryToChargeDelegateBaseFee` lacks this fallback and only returns tokens meeting delegation requirements with sufficient balance. [5](#0-4) 

### Impact Explanation

**Successful Transactions - Different Token Selection:**

For a method fee configuration of `{TSA: 10, ELF: 100}`:
- User with balances `TSA: 5, ELF: 200` → charges 100 ELF (sufficient ELF found)
- Delegate with balances `TSA: 200, ELF: 50` → charges 10 TSA (sufficient TSA found first, meets delegation requirements)

Both transactions succeed but pay in different tokens for the same transaction type.

**Failed Transactions - Different Partial Payments:**

For a method fee configuration of `{TSA: 100, ELF: 10}` with ELF as primary token:
- User with balances `TSA: 50, ELF: 8` → primary token fallback causes 8 ELF to be charged
- Delegate with same balances → charges 50 TSA or different amount (no primary fallback)

**Concrete Harms:**
1. **Economic Unfairness**: If market prices diverge from configured fee ratios (e.g., TSA becomes more valuable than the 10:1 ratio suggests), users paying in TSA lose more value than those paying in ELF
2. **Strategic Exploitation**: Users can choose between direct payment or delegation based on which token they prefer to spend, gaming the fee system
3. **Unpredictability**: Contract developers and users cannot reliably predict which token will be charged
4. **Inconsistent Treatment**: Violates the principle that identical transactions should incur identical fees

This affects all users and delegates making transactions with multi-token fee configurations (common in AElf).

### Likelihood Explanation

**Attacker Capabilities Required:**
- None beyond normal user actions
- Simply having varied token balances triggers the asymmetry
- No special permissions or manipulation needed

**Attack Complexity:**
- Low - happens automatically based on token balance distribution
- Users naturally hold varied amounts of different tokens
- Multi-token fee configurations are standard in AElf

**Feasibility Conditions:**
- Method fees must include multiple tokens (standard practice)
- Users must have imbalanced token holdings (extremely common)
- Delegation feature must be available (it is)

**Probability:**
- HIGH - occurs on every transaction where users lack sufficient balance in the first checked token
- The primary token fallback (line 732-742) always activates when user fee charging fails
- No configuration or governance action can disable this asymmetry

The code path is deterministic and always active. Every user with insufficient first-token balance but sufficient primary token balance will experience the asymmetry.

### Recommendation

**Immediate Fix:**

Unify the fee charging logic by either:

**Option 1 - Apply primary token fallback to both paths:**
```csharp
// After line 719, before return:
if (!chargeResult)
{
    var primaryTokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
    if (symbolToAmountMap.ContainsKey(primaryTokenSymbol))
    {
        symbol = primaryTokenSymbol;
        existingBalance = GetBalance(fromAddress, symbol);
        existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
    }
}
```

**Option 2 - Remove primary token fallback from user path (lines 732-742):**

Remove the asymmetric fallback entirely so both paths behave identically, selecting tokens based solely on the order in the fee map and available balances.

**Invariant to Enforce:**

Add assertion: For any given method fee configuration and similar balance scenarios, user direct payment and delegation payment should select the same token (or fail consistently).

**Test Cases:**

1. Test case where User and Delegate have identical balances with multi-token fees - verify same token charged
2. Test case where both paths fail - verify consistent partial payment behavior
3. Test case with primary token having higher balance than fee-map-first token - verify consistent selection
4. Regression test ensuring delegation and direct payment treat token selection identically

### Proof of Concept

**Initial State:**
- Method fee configuration: `{TSA: 100, ELF: 10}`
- Primary token: ELF
- User A balance: `TSA: 50, ELF: 8`
- User B sets delegation to Delegatee with balance: `TSA: 50, ELF: 8`, unlimited delegation

**Transaction Steps:**

1. User A calls method directly (no delegation)
   - `TryToChargeUserBaseFee` checks TSA (50 < 100), checks ELF (8 < 10)
   - Returns false with symbolWithAnything = TSA
   - Primary token fallback (lines 732-742) overrides: symbol = ELF, existingBalance = 8
   - `ChargeBaseFee` adds ELF: 8 to bill
   - Transaction fails, User A pays **8 ELF**

2. User B calls same method via delegation
   - `TryToChargeDelegateBaseFee` checks tokens against delegation limits and balance
   - Returns false with symbol = TSA or ELF (whichever met delegation check)
   - No primary token fallback
   - `ChargeBaseFee` adds TSA: 50 or ELF: 8 to bill (not guaranteed to be ELF)
   - Transaction fails, User B pays **50 TSA** (or different amount/token)

**Expected Result:** Both users should pay the same token for the same transaction type with identical balances.

**Actual Result:** Different tokens/amounts charged due to asymmetric fallback logic.

**Success Condition:** The asymmetry is demonstrated when the two charging paths produce different `symbolToChargeBaseFee` values for identical balance scenarios, violating fee consistency.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L343-356)
```csharp
        if (!ChargeFirstSufficientToken(methodFeeMap, fromAddress, out var symbolToChargeBaseFee,
                out var amountToChargeBaseFee, out var existingBalance, out var existingAllowance,
                transactionFeeFreeAllowancesMap,
                delegations))
        {
            Context.LogDebug(() => "Failed to charge first sufficient token.");
            if (symbolToChargeBaseFee != null)
            {
                bill.FeesMap.Add(symbolToChargeBaseFee, existingBalance);
                allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, existingAllowance);
            } // If symbol == 

            return false;
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L714-720)
```csharp
        if (delegations != null)
        {
            //from address -> delegatee
            chargeResult = TryToChargeDelegateBaseFee(symbolToAmountMap, fromAddress, transactionFeeFreeAllowancesMap,
                delegations, out amount, out symbol, out existingBalance, out existingAllowance);
            return chargeResult;
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L722-742)
```csharp
        chargeResult = TryToChargeUserBaseFee(symbolToAmountMap, fromAddress, transactionFeeFreeAllowancesMap,
            out amount, out symbol, out existingBalance, out existingAllowance);

        if (symbol != null)
        {
            existingBalance = GetBalance(fromAddress, symbol);
            existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
            amount = symbolToAmountMap[symbol];
        }

        //For user, if charge failed and delegation is null, priority charge primary token
        if (!chargeResult)
        {
            var primaryTokenSymbol = GetPrimaryTokenSymbol(new Empty()).Value;
            if (symbolToAmountMap.ContainsKey(primaryTokenSymbol))
            {
                symbol = primaryTokenSymbol;
                existingBalance = GetBalance(fromAddress, symbol);
                existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
            }
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L798-802)
```csharp
        if (symbolWithEnoughBalancePlusAllowance == null && symbolWithEnoughBalance == null)
        {
            symbolOfValidBalance = symbolWithAnything;

            return false;
```
