### Title
Rounding Error Exploitation in TokenConverter Allows Fee Avoidance and Underpayment Through Repeated Small Purchases

### Summary
The `GetAmountToPayFromReturn` function casts decimal calculations to `long`, truncating fractional values. Attackers can exploit this by purchasing tokens in many small increments rather than bulk purchases, accumulating rounding losses that benefit them. Additionally, the fee calculation truncates to zero for sufficiently small purchases, allowing complete fee avoidance.

### Finding Description

The vulnerability exists in the Bancor price calculation and fee computation logic: [1](#0-0) [2](#0-1) 

Both the simplified formula (line 84, when connector weights are equal) and the full Bancor formula (line 93) cast the result to `long`, discarding any fractional part. In production, resource token pairs use equal weights of 0.005: [3](#0-2) 

This triggers the simplified formula where `amountToPay = (long)(bf / (bt - a) * a)`. Each truncation loses the fractional cost.

The Buy function compounds this issue with fee calculation: [4](#0-3) 

The fee is computed as `Convert.ToInt64(amountToPay * GetFeeRate())` where `GetFeeRate()` returns 0.005. When `amountToPay * 0.005 < 1`, the fee truncates to zero and `HandleFee` is never called, allowing complete fee avoidance.

There is no minimum purchase amount enforcement - only a check that `amountToReceive > 0`: [5](#0-4) 

While balances are updated after each transaction: [6](#0-5) 

This does not prevent exploitation because the attacker benefits from the accumulated truncation losses across all transactions.

### Impact Explanation

**Direct Financial Loss to Protocol:**
- **Rounding Loss**: For a purchase of 1,000 tokens done as 1,000 individual 1-token purchases vs. one bulk purchase:
  - Bulk: `amountToPay = (long)(1,000,000 / 999,000 * 1,000) = 1,001`
  - Individual: Each costs `(long)(balance / (balance-1) * 1) = 1`, total = 1,000
  - **Loss: 1 token per 1,000 purchased (0.1%)**

- **Fee Avoidance**: With fee rate 0.005, any `amountToPay < 200` results in zero fees:
  - Bulk purchase of 1,000 tokens: `fee = (long)(1,001 * 0.005) = 5`
  - 1,000 individual purchases: Each `fee = (long)(1 * 0.005) = 0`, **total fee = 0**
  - **Loss: 100% of expected fees (5 tokens)**

Combined, an attacker purchasing 1,000 tokens saves 6 tokens (0.6% underpayment). With larger amounts or higher token values, losses scale proportionally. The protocol loses both base tokens and fee revenue that should fund Treasury donations and token burns.

**Affected Parties:**
- TokenConverter contract (direct loss of funds)
- Treasury contract (loses fee donations)
- All token holders (inflationary impact from avoided burns)

### Likelihood Explanation

**High Likelihood of Exploitation:**

- **Reachable Entry Point**: `Buy` is a public function callable by any address
- **Zero Authorization Required**: No special permissions needed
- **Feasible Preconditions**: 
  - Production connectors use equal weights (0.005), enabling simplified formula
  - No minimum purchase amount enforced
  - Attacker only needs approval for base tokens

- **Execution Practicality**: 
  - Simple repeated calls to `Buy` with `amount = 1` (or any small value where `amountToPay < 200` for fee avoidance)
  - Each transaction is independent and valid
  - No rate limiting or anti-spam measures

- **Economic Rationality**: 
  - Profitability depends on: savings from rounding/fees > transaction gas costs
  - With low gas fees or high token values, this becomes profitable
  - Fee avoidance alone (100% of fees) may justify the attack
  - Can be executed by bots to maximize efficiency

**Detection Difficulty**: The attack appears as normal trading activity - just many small purchases rather than one large one. No anomalous access patterns or failed transactions.

### Recommendation

**Immediate Mitigations:**

1. **Enforce Minimum Purchase Amount** in the Buy function:
```csharp
public override Empty Buy(BuyInput input)
{
    const long MinimumPurchaseAmount = 100_00000000; // 100 tokens with 8 decimals
    Assert(input.Amount >= MinimumPurchaseAmount, "Purchase amount below minimum");
    // ... rest of function
}
```

2. **Round Up Instead of Truncating** in GetAmountToPayFromReturn:
```csharp
// Replace (long) casts with ceiling to always round up
return (long)Math.Ceiling(bf / (bt - a) * a); // for equal weights
return (long)Math.Ceiling(bf * (Exp(y * Ln(x)) - decimal.One)); // for unequal weights
```

3. **Enforce Minimum Fee** regardless of calculation:
```csharp
var calculatedFee = Convert.ToInt64(amountToPay * GetFeeRate());
var fee = Math.Max(calculatedFee, MinimumFeeAmount); // e.g., 1 token minimum
```

**Long-term Improvements:**

4. Add rate limiting per address to prevent spam attacks
5. Implement comprehensive test coverage for rounding edge cases
6. Add monitoring/alerts for unusual patterns of small purchases
7. Consider using higher precision arithmetic (e.g., BigDecimal) before final truncation

**Test Cases to Add:**
- Test that 1000 purchases of 1 token cost >= 1 purchase of 1000 tokens
- Test that fees are always collected for any non-zero purchase
- Test boundary conditions where truncation matters most
- Fuzz testing with various purchase amounts and connector balances

### Proof of Concept

**Initial State:**
- fromConnectorBalance: 1,000,000 tokens
- toConnectorBalance: 1,000,000 tokens  
- fromConnectorWeight: 0.005
- toConnectorWeight: 0.005
- Fee rate: 0.005 (0.5%)

**Attack Sequence:**

1. **Attacker wants to buy 1,000 tokens total**

2. **Legitimate Bulk Purchase (Expected Behavior):**
   - Call `Buy(symbol, amount=1000, payLimit=0)`
   - `amountToPay = GetAmountToPayFromReturn(1000000, 0.005, 1000000, 0.005, 1000)`
   - Calculation: `(long)(1000000 / (1000000 - 1000) * 1000) = (long)(1001.001...) = 1001`
   - Fee: `(long)(1001 * 0.005) = (long)(5.005) = 5`
   - **Total Cost: 1001 + 5 = 1006 tokens**

3. **Exploit: 1,000 Individual Purchases:**
   - For i = 1 to 1000:
     - Call `Buy(symbol, amount=1, payLimit=0)`
     - First: `amountToPay = (long)(1000000 / 999999 * 1) = 1`
     - Fee: `(long)(1 * 0.005) = 0`
     - Balance updates: fromBalance += 1, toBalance -= 1
     - Subsequent calls follow same pattern with slightly increasing balances
   - **Total Cost: ~1,000 tokens (1 per call) + 0 fees = 1,000 tokens**

4. **Result:**
   - Expected: Pay 1,006 tokens
   - Actual: Pay 1,000 tokens
   - **Attacker saves: 6 tokens (0.6% underpayment)**
   - **Protocol loses: 6 tokens + prevents 2.5 tokens to Treasury + 2.5 tokens burned**

**Success Condition:** 
The sum of costs from 1,000 individual purchases is less than the cost of one bulk purchase of 1,000 tokens, demonstrating exploitable rounding errors and fee avoidance.

### Notes

This vulnerability is particularly severe because it combines two issues:
1. Cumulative rounding errors from decimal-to-long truncation
2. Complete fee avoidance for small purchases

The production configuration with equal weights (0.005) for resource token pairs makes this highly exploitable, as it triggers the simplified formula where rounding losses are most predictable. The lack of minimum purchase amounts and the fee structure create a clear economic incentive for attackers to split large purchases into many small ones.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L73-73)
```csharp
        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L80-84)
```csharp
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-130)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());

        var amountToPayPlusFee = amountToPay.Add(fee);
        Assert(input.PayLimit == 0 || amountToPayPlusFee <= input.PayLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L141-141)
```csharp
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
```
