# Audit Report

## Title
Rounding Error Exploitation in TokenConverter Allows Fee Avoidance and Underpayment Through Repeated Small Purchases

## Summary
The TokenConverter contract's `GetAmountToPayFromReturn` function truncates decimal calculations to `long`, discarding fractional token amounts. When combined with fee calculation truncation, this allows attackers to underpay for tokens by making many small purchases instead of one large purchase, avoiding fees entirely and accumulating rounding losses that benefit the attacker at the protocol's expense.

## Finding Description

The vulnerability exists in the Bancor pricing formula implementation where decimal-to-long casting causes precision loss. [1](#0-0) 

When connector weights are equal (which occurs in production for all resource token pairs), [2](#0-1) [3](#0-2)  the simplified formula truncates the mathematically correct payment amount. Each individual purchase loses the fractional cost to rounding.

The `Buy` function compounds this with fee truncation: [4](#0-3) 

When `amountToPay * 0.005 < 1.0`, the fee truncates to zero: [5](#0-4) 

This means for any purchase where `amountToPay < 200`, fees are completely avoided. There is no minimum purchase amount enforcement beyond the implicit requirement that `input.Amount > 0`.

**Attack Execution:**
1. Attacker wants to buy 1,000 tokens
2. Instead of one bulk purchase costing 1,001 + 5 fee = 1,006 tokens
3. Attacker makes 1,000 individual 1-token purchases, each costing 1 token with 0 fee
4. Total cost: 1,000 tokens (savings of 6 tokens = 0.6%)

Balances are updated after each transaction, [6](#0-5)  but this doesn't prevent exploitation because the attacker benefits from accumulated truncation losses across all transactions.

## Impact Explanation

**Direct Financial Loss:**
- **Rounding Loss:** 0.1% underpayment per the mathematical example (1 token saved per 1,000 purchased)
- **Fee Avoidance:** 100% of fees avoided when `amountToPay < 200` (5 tokens saved in the example)
- **Combined Loss:** 0.6% total underpayment for the example scenario

**Affected Parties:**
1. **TokenConverter contract:** Receives less payment than mathematically correct
2. **Treasury contract:** Loses 50% of fees that should be donated [7](#0-6) 
3. **All token holders:** Inflationary impact from 50% of fees that should be burned [8](#0-7) 

The losses scale proportionally with purchase volume and token values. This breaks the protocol's core pricing invariant that users should pay the correct Bancor formula price plus configured fees.

## Likelihood Explanation

**High Likelihood due to:**

1. **Accessibility:** `Buy` is a public function with no authorization requirements [9](#0-8) 

2. **Preconditions Met:** Production configuration uses equal connector weights (0.005) [10](#0-9)  and fee rate of 0.005 [11](#0-10) 

3. **No Protections:** No minimum purchase amount, no minimum fee requirement, no rate limiting

4. **Economic Viability:** Fee avoidance alone (100% savings) may justify the attack. With low gas fees or high token values, the combined savings become profitable. Bots can automate execution efficiently.

5. **Detection Difficulty:** Appears as normal trading activity—just many small legitimate purchases rather than one large purchase.

## Recommendation

Implement the following protections:

1. **Minimum Purchase Amount:** Enforce a minimum `input.Amount` that ensures `amountToPay >= 200` to prevent fee avoidance
2. **Minimum Fee:** Always charge at least 1 token as fee, or enforce fee floor: `fee = Math.Max(1, Convert.ToInt64(amountToPay * GetFeeRate()))`
3. **Better Rounding:** Consider using banker's rounding or always rounding up for amounts owed to the protocol
4. **Purchase Limits:** Implement rate limiting or increasing fees for rapid repeated small purchases

Example fix for minimum fee:
```csharp
var fee = Math.Max(1, Convert.ToInt64(amountToPay * GetFeeRate()));
// Always charge at least 1 token fee to prevent complete fee avoidance
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize TokenConverter with production configuration (0.005 weights, 0.005 fee rate)
2. Set up initial balances of 1,000,000 for both connectors
3. Execute bulk purchase of 1,000 tokens and record total cost
4. Reset state and execute 1,000 individual 1-token purchases
5. Assert that individual purchases cost less than bulk purchase
6. Verify fees were zero for individual purchases but non-zero for bulk

The test would prove that splitting purchases into small increments allows users to underpay by 0.6% in the example scenario, violating the protocol's fair pricing guarantee.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L80-84)
```csharp
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L235-245)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-112)
```csharp
    public override Empty Buy(BuyInput input)
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L124-124)
```csharp
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L130-130)
```csharp
        if (fee > 0) HandleFee(fee);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L141-141)
```csharp
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L216-217)
```csharp
        var donateFee = fee.Div(2);
        var burnFee = fee.Sub(donateFee);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L252-257)
```csharp
        State.TokenContract.Burn.Send(
            new BurnInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                Amount = burnFee
            });
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L8-8)
```csharp
    public const string TokenConverterFeeRate = "0.005";
```
