# Audit Report

## Title
Rounding Error Exploitation in TokenConverter Allows Fee Avoidance and Underpayment Through Repeated Small Purchases

## Summary
The TokenConverter contract's Bancor pricing implementation truncates decimal calculations to `long`, discarding fractional token amounts. Combined with fee calculation truncation, this allows attackers to systematically underpay by splitting large purchases into many small transactions, completely avoiding fees and accumulating rounding losses that benefit the attacker at the protocol's expense.

## Finding Description

The vulnerability exists in the Bancor formula implementation where decimal-to-long casting causes systematic precision loss. When connector weights are equal (the production configuration for all resource token pairs), the simplified Bancor formula truncates fractional payment amounts on every calculation. [1](#0-0) 

The production economic contract configures equal connector weights of 0.005 for both resource and native token connectors: [2](#0-1) [3](#0-2) 

The `Buy` function compounds this issue with fee calculation truncation: [4](#0-3) 

With the configured fee rate of 0.005 (0.5%): [5](#0-4) 

When `amountToPay * 0.005 < 1.0`, the fee truncates to zero. Fees are only charged when greater than zero: [6](#0-5) 

This means any purchase where `amountToPay < 200` completely avoids the 0.5% fee. There is no minimum purchase amount validation in the `Buy` function or the `BuyInput` protobuf definition—only the implicit requirement that `input.Amount > 0`.

**Attack Execution:**
1. Attacker wants to acquire 1,000 tokens
2. Instead of one purchase (cost: ~1,111 tokens + 5 fee = 1,116 total)
3. Attacker makes many small purchases where each `amountToPay < 200`
4. Each small purchase: pays 0 fee, loses fractional amounts to rounding (benefiting attacker)
5. Total cost: significantly less than the mathematically correct amount

While balances update after each transaction, this doesn't prevent exploitation—the attacker benefits from accumulated truncation losses across all transactions, where each `floor(x_i)` is less than the correct proportional cost. [7](#0-6) 

## Impact Explanation

**Direct Financial Losses:**

1. **Complete Fee Avoidance:** When `amountToPay < 200`, 100% of the 0.5% protocol fee is avoided
2. **Accumulated Rounding Losses:** Each transaction truncates fractional payment amounts, systematically underpaying the protocol
3. **Treasury Revenue Loss:** The fee handling mechanism splits collected fees 50/50 between Treasury donation and token burning: [8](#0-7) 

When fees are avoided, the Treasury receives no donations.

4. **Token Supply Inflation:** The other 50% of fees should be burned to reduce token supply: [9](#0-8) 

When fees are avoided, these burns don't occur, creating inflationary pressure on all token holders.

**Affected Parties:**
- **TokenConverter contract:** Receives systematically less payment than the Bancor formula specifies
- **Treasury contract:** Loses 50% of fee donations
- **All token holders:** Suffer from reduced token burns (inflation)
- **Protocol integrity:** Bancor pricing invariant violated

The losses scale with trading volume. This breaks the protocol's core economic guarantee that users must pay the correct Bancor-determined price plus configured fees.

## Likelihood Explanation

**High Likelihood:**

1. **Public Access:** The `Buy` function is publicly accessible with no authorization requirements: [10](#0-9) 

2. **Production Configuration Vulnerable:** The live deployment uses equal connector weights (0.005) and fee rate (0.005), creating the exact conditions for exploitation.

3. **No Protective Mechanisms:**
   - No minimum purchase amount enforcement
   - No minimum fee requirement  
   - No rate limiting on repeated small purchases
   - No detection of split-purchase patterns

4. **Economic Incentive:** Fee avoidance alone provides 100% savings on the 0.5% fee. For large trading volumes or high-value tokens, the accumulated savings from both fee avoidance and rounding errors become substantial.

5. **Automation-Friendly:** Bots can easily execute the attack pattern (many small purchases) without manual intervention.

6. **Detection Difficulty:** The attack appears as normal trading activity—just many small legitimate purchases rather than one large purchase.

## Recommendation

**Immediate Fixes:**

1. **Implement Minimum Purchase Amount:**
```csharp
public override Empty Buy(BuyInput input)
{
    const long MinimumPurchaseAmount = 10; // Adjust based on economics
    Assert(input.Amount >= MinimumPurchaseAmount, 
           $"Purchase amount must be at least {MinimumPurchaseAmount}");
    // ... rest of function
}
```

2. **Enforce Minimum Fee:**
```csharp
var fee = Convert.ToInt64(amountToPay * GetFeeRate());
const long MinimumFee = 1;
if (fee == 0 && amountToPay > 0)
    fee = MinimumFee;
```

3. **Consider Higher-Precision Arithmetic:** Use a library that supports fixed-point decimal arithmetic for financial calculations to avoid truncation losses entirely.

**Long-term Solutions:**

1. Implement rate limiting for repeated small purchases from the same address
2. Add economic disincentives for split purchases (e.g., slightly higher effective fee rates for smaller purchases)
3. Review all decimal-to-long conversions across the codebase for similar precision loss vulnerabilities

## Proof of Concept

```csharp
[Fact]
public async Task RoundingExploitation_FeeAvoidance_Test()
{
    // Setup: Initialize TokenConverter with production config
    // Fee rate = 0.005, Equal weights = 0.005
    
    var buyAmount = 1000L;
    
    // Scenario 1: Single large purchase
    var largePurchaseResult = await TokenConverterStub.Buy.SendAsync(new BuyInput
    {
        Symbol = ResourceTokenSymbol,
        Amount = buyAmount,
        PayLimit = 0
    });
    var largePurchaseCost = /* extract from event */;
    var largePurchaseFee = /* extract from event */;
    
    // Scenario 2: Many small purchases (199 base cost each to avoid fee)
    var totalSmallPurchaseCost = 0L;
    var totalSmallPurchaseFee = 0L;
    
    for (int i = 0; i < buyAmount; i++)
    {
        var smallPurchaseResult = await TokenConverterStub.Buy.SendAsync(new BuyInput
        {
            Symbol = ResourceTokenSymbol,
            Amount = 1,
            PayLimit = 0
        });
        totalSmallPurchaseCost += /* extract cost from event */;
        totalSmallPurchaseFee += /* extract fee from event */;
    }
    
    // Verify fee avoidance
    Assert.True(largePurchaseFee > 0, "Large purchase should have fee");
    Assert.Equal(0L, totalSmallPurchaseFee); // Small purchases avoid all fees
    
    // Verify underpayment
    Assert.True(totalSmallPurchaseCost < largePurchaseCost, 
                "Split purchases should cost less due to rounding");
    
    var savings = (largePurchaseCost + largePurchaseFee) - 
                  (totalSmallPurchaseCost + totalSmallPurchaseFee);
    Assert.True(savings > 0, "Attacker saves money by splitting purchase");
}
```

## Notes

This vulnerability represents a fundamental flaw in the Bancor pricing implementation. The combination of:
1. Decimal-to-long truncation in price calculations
2. Fee truncation to zero for small amounts
3. No minimum purchase amount enforcement
4. Equal connector weights in production (triggering the simplified, truncation-prone formula)

Creates a systematic way for users to underpay the protocol. While the per-transaction savings may seem small, the attack scales with trading volume and can be fully automated. The lack of any protective mechanisms makes this immediately exploitable in the live deployment.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L80-84)
```csharp
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L235-235)
```csharp
                Weight = "0.005",
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L245-245)
```csharp
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
