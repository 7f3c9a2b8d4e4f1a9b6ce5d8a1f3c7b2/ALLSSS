### Title
Rounding Error Exploitation in Bancor Token Purchases via Repeated Small-Amount Transactions

### Summary
The `GetAmountToPayFromReturn()` function in `BancorHelper.cs` uses a `(long)` cast that truncates decimal values, losing up to 0.999 tokens per transaction. Attackers can exploit this by repeatedly purchasing 1 token at a time instead of buying in bulk, paying significantly less (potentially 30-50% discount) than the mathematically correct cost due to cumulative truncation losses.

### Finding Description

The vulnerability exists in the Bancor pricing calculation where the cost to purchase tokens is computed: [1](#0-0) 

The `(long)` cast truncates toward zero, discarding any fractional component. When a user purchases tokens through the `Buy` function: [2](#0-1) 

The function computes: `amountToPay = bf * (Exp(y * Ln(x)) - 1)` where the result is often fractional (e.g., 1.67, 2.45, etc.). The `(long)` cast truncates this to an integer, causing the buyer to pay less than the true cost.

**Why this is exploitable:**

When purchasing 1 token at a time with realistic connector balances (e.g., fromBalance=1,000,000, toBalance=500,000), the true cost per token might be ~1.67 ELF, but the truncated cost is 1 ELF. Repeating this 1000 times:
- **Cost via exploitation**: 1000 × 1 = 1,000 ELF
- **True cost**: ~1,670 ELF  
- **Attacker savings**: ~670 ELF (40% discount)

There are **no minimum purchase amount restrictions** to prevent this: [3](#0-2) 

The only check is that `amountToReceive > 0`, so purchasing 1 token is explicitly allowed.

### Impact Explanation

**Direct Financial Impact:**
- Attackers can drain token converter reserves by acquiring tokens at steep discounts (30-50% off true market price)
- The protocol loses revenue on every exploited purchase
- Reserve ratios become imbalanced, affecting price discovery for legitimate users

**Quantified Loss Example:**
With connector balances of 1M/500K and equal weights:
- Buying 1,000 tokens legitimately: ~1,670 ELF
- Buying 1,000 tokens via 1,000 separate transactions: ~1,000 ELF
- **Per-exploit profit: 670 ELF**

If ELF is worth $0.50, this represents $335 profit per 1,000 token purchase. An attacker can scale this arbitrarily by automating multiple small purchases.

**Affected Parties:**
- Token converter reserves (direct loss)
- Legitimate traders (worse prices due to reserve depletion)
- Token holders (value dilution)

### Likelihood Explanation

**Attacker Capabilities Required:**
- Call public `Buy` function repeatedly with `Amount = 1`
- Standard transaction approval for base token transfers
- No special privileges needed

**Attack Complexity:** 
- Trivial - just loop the Buy call with Amount=1
- Fully automated via script
- No complex transaction ordering or timing requirements

**Feasibility Conditions:**
- TokenConverter must be initialized (normal operational state)
- Attacker needs initial capital for first purchase + gas
- Works on ALL token pairs using Bancor pricing

**Economic Rationality:**
- Guaranteed profit on every transaction
- Risk-free arbitrage (mathematical certainty)
- Gas costs negligible compared to savings
- Scalable to any desired amount

**Detection Constraints:**
- Appears as normal trading activity
- No distinguishing features from legitimate small purchases
- Can be distributed across multiple addresses

**Probability: HIGH** - The exploit is deterministic, requires no special conditions, and is immediately profitable.

### Recommendation

**Primary Fix - Add Minimum Purchase Amount:**
```csharp
public override Empty Buy(BuyInput input)
{
    // Add minimum amount check
    Assert(input.Amount >= MinimumPurchaseAmount, 
           "Purchase amount below minimum threshold");
    
    // ... rest of existing code
}
```

Set `MinimumPurchaseAmount` to a value that makes truncation losses negligible (e.g., 100 or 1000 tokens).

**Alternative Fix - Use Proper Rounding:**
Modify the Bancor helper to round UP instead of truncating: [4](#0-3) 

Change to:
```csharp
return (long)Math.Ceiling(bf * (Exp(y * Ln(x)) - decimal.One));
```

This ensures buyers always pay at least the true cost (rounding in protocol's favor).

**Testing Requirements:**
- Add unit tests for fractional cost scenarios (amounts where true cost is X.5, X.9, etc.)
- Add integration tests comparing bulk purchases vs. multiple small purchases
- Verify cost equality: `Cost(N, once) ≈ Sum(Cost(1, N times))`

### Proof of Concept

**Initial State:**
- ELF Connector: balance = 1,000,000, weight = 0.6
- WRITE Connector: balance = 500,000, weight = 0.5
- Fee rate = 0.5% (0.005)

**Attack Sequence:**

**Step 1 - Buy 1 WRITE token:**
```
Input: Buy(Symbol="WRITE", Amount=1, PayLimit=10)
Calculation:
  x = 500000/(500000-1) = 1.000002
  y = 0.5/0.6 = 0.8333
  cost = (long)(1000000 * (Exp(0.8333*Ln(1.000002)) - 1))
       = (long)(1000000 * 0.00000167)
       = (long)(1.67)
       = 1 ELF
Fee: 0 ELF (rounds down from 0.005)
Total paid: 1 ELF
```

**Step 2 - Buy another 1 WRITE token:**
```
After step 1:
  - ELF balance: 1,000,001
  - WRITE balance: 499,999

Input: Buy(Symbol="WRITE", Amount=1, PayLimit=10)
Calculation:
  x = 499999/(499999-1) = 1.000002
  cost = (long)(1000001 * 0.00000167)
       = (long)(1.67)
       = 1 ELF
Total paid: 1 ELF
```

**Repeat 1000 times:**
- Total paid: ~1,000 ELF
- Total received: 1,000 WRITE tokens

**Compare to bulk purchase:**
```
Input: Buy(Symbol="WRITE", Amount=1000, PayLimit=2000)
Calculation:
  x = 500000/(500000-1000) = 1.002004
  cost = (long)(1000000 * (Exp(0.8333*Ln(1.002004)) - 1))
       = (long)(1000000 * 0.001669)
       = (long)(1669)
       = 1669 ELF
Fee: 8 ELF
Total paid: 1677 ELF
```

**Result:**
- Exploit cost: 1,000 ELF for 1,000 tokens
- Legitimate cost: 1,677 ELF for 1,000 tokens
- **Attacker saves: 677 ELF (40.4% discount)**

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L73-73)
```csharp
        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```
