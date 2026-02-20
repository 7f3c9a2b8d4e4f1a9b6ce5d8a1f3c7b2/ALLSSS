# Audit Report

## Title
Rounding Error Exploitation in TokenConverter Allows Fee Avoidance and Underpayment Through Repeated Small Purchases

## Summary
The TokenConverter contract's Bancor pricing formula implementation truncates decimal calculations to `long`, discarding fractional token amounts. Combined with fee calculation truncation, this enables attackers to underpay for tokens by splitting large purchases into many small transactions, completely avoiding fees and accumulating rounding losses at the protocol's expense.

## Finding Description

The vulnerability exists in the Bancor formula implementation where decimal-to-long casting causes precision loss. [1](#0-0) 

When connector weights are equal (the simplified formula branch), the mathematically correct payment amount is truncated downward on each purchase, benefiting the buyer.

The `Buy` function compounds this issue with fee truncation. [2](#0-1) 

The fee calculation uses `Convert.ToInt64(amountToPay * GetFeeRate())`, which truncates to zero when `amountToPay * feeRate < 1.0`. For a typical fee rate of 0.005 (0.5%), any purchase where `amountToPay < 200` will have zero fees, since the fee skips execution when `fee <= 0`.

**Attack Execution:**
1. Attacker wants to buy 1,000 resource tokens
2. Instead of one bulk purchase (cost ≈ 1,001 base tokens + 5 fee = 1,006 total)
3. Attacker makes 1,000 individual 1-token purchases, each costing 1 base token with 0 fee
4. Total cost: 1,000 base tokens (6 token savings ≈ 0.6%)

The `Buy` function is publicly accessible with no authorization checks, and there is no minimum purchase amount enforcement beyond the implicit `input.Amount > 0` requirement. [3](#0-2) 

Balance updates occur after each transaction [4](#0-3) , but this doesn't prevent exploitation because truncation losses accumulate in the attacker's favor across all transactions.

## Impact Explanation

**Direct Financial Loss:**

1. **Rounding Loss:** Each small purchase truncates the exact payment downward. When buying 1 token repeatedly from large reserves, `amountToPay = fromBalance / (toBalance - 1) ≈ 1.00001` truncates to exactly 1, losing the fractional cost.

2. **Fee Avoidance:** 100% of fees avoided when `amountToPay < 200` (for 0.5% fee rate). The attacker saves all fee costs by keeping purchases small.

3. **Combined Impact:** For the example scenario, 0.6% underpayment (1 token rounding loss + 5 token fee avoidance out of 1,006 expected payment).

**Affected Parties:**

- **TokenConverter contract:** Receives less base token payment than mathematically correct from the Bancor formula
- **Treasury contract:** Loses 50% of fees that should be donated [5](#0-4) 
- **All token holders:** Experience inflationary impact from 50% of fees that should be burned [6](#0-5) 

The losses scale proportionally with trading volume. This breaks the protocol's core pricing invariant that users must pay the correct Bancor formula price plus configured fees.

## Likelihood Explanation

**High Likelihood:**

1. **Accessibility:** The `Buy` function is public with no authorization requirements [7](#0-6) 

2. **No Protections:** No minimum purchase amount, no minimum fee requirement, no rate limiting, no transaction size checks

3. **Economic Viability:** Fee avoidance alone (100% fee savings) justifies the attack when transaction costs are low. With automated bots, attackers can efficiently execute hundreds or thousands of small purchases.

4. **Detection Difficulty:** Individual small purchases appear as normal trading activity, making the attack pattern difficult to distinguish from legitimate users.

5. **Realistic Preconditions:** The simplified Bancor formula is used when connector weights are equal, which is a standard configuration. Fee rates between 0.1% and 1% are typical, all making purchases under 100-1000 tokens fee-free.

## Recommendation

Implement minimum purchase amount enforcement and minimum fee requirements:

```csharp
public override Empty Buy(BuyInput input)
{
    // Add minimum purchase check
    Assert(input.Amount >= MinimumPurchaseAmount, "Purchase amount below minimum");
    
    var toConnector = State.Connectors[input.Symbol];
    Assert(toConnector != null, "[Buy]Can't find to connector.");
    // ... existing checks ...
    
    var amountToPay = BancorHelper.GetAmountToPayFromReturn(
        GetSelfBalance(fromConnector), GetWeight(fromConnector),
        GetSelfBalance(toConnector), GetWeight(toConnector),
        input.Amount);
    var fee = Convert.ToInt64(amountToPay * GetFeeRate());
    
    // Enforce minimum fee (e.g., 1 token)
    if (fee == 0 && amountToPay >= MinimumAmountForFee)
        fee = 1;
    
    // ... rest of function
}
```

Alternatively, use higher-precision arithmetic (decimal) for intermediate calculations and only convert to `long` for the final token transfers, or implement accumulated rounding error tracking.

## Proof of Concept

```csharp
[Fact]
public async Task RoundingExploitation_FeesAvoidedThroughSmallPurchases()
{
    // Setup: Initialize TokenConverter with equal weights and 0.5% fee
    // fromConnectorBalance = 1,000,000, toConnectorBalance = 1,000,000
    
    var targetTokensToBuy = 1000L;
    
    // Scenario 1: Bulk purchase (expected behavior)
    var bulkAmountToPay = BancorHelper.GetAmountToPayFromReturn(
        1000000L, 0.005m, 1000000L, 0.005m, targetTokensToBuy);
    var bulkFee = Convert.ToInt64(bulkAmountToPay * 0.005m);
    var bulkTotalCost = bulkAmountToPay + bulkFee;
    // bulkAmountToPay ≈ 1001, bulkFee = 5, bulkTotalCost = 1006
    
    // Scenario 2: Many small purchases (exploit)
    long totalPaidSmall = 0;
    long totalFeeSmall = 0;
    long fromBalance = 1000000L;
    long toBalance = 1000000L;
    
    for (int i = 0; i < targetTokensToBuy; i++)
    {
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            fromBalance, 0.005m, toBalance, 0.005m, 1L);
        var fee = Convert.ToInt64(amountToPay * 0.005m);
        
        totalPaidSmall += amountToPay;
        totalFeeSmall += fee;
        
        fromBalance += amountToPay;
        toBalance -= 1;
    }
    
    // Assert: Small purchases cost less than bulk
    Assert.True(totalPaidSmall + totalFeeSmall < bulkTotalCost);
    // Assert: Most/all fees avoided
    Assert.True(totalFeeSmall < bulkFee);
    // Attacker saves: bulkTotalCost - (totalPaidSmall + totalFeeSmall)
}
```

This test demonstrates that splitting a large purchase into many small transactions results in lower total payment due to accumulated rounding truncation and fee avoidance.

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-116)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L214-241)
```csharp
    private void HandleFee(long fee)
    {
        var donateFee = fee.Div(2);
        var burnFee = fee.Sub(donateFee);

        // Donate 0.5% fees to Treasury
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = donateFee
            });
        if (State.DividendPoolContract.Value == null)
            State.DividendPoolContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
        State.TokenContract.Approve.Send(new ApproveInput
        {
            Symbol = State.BaseTokenSymbol.Value,
            Spender = State.DividendPoolContract.Value,
            Amount = donateFee
        });
        State.DividendPoolContract.Donate.Send(new DonateInput
        {
            Symbol = State.BaseTokenSymbol.Value,
            Amount = donateFee
        });
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L243-257)
```csharp
        // Transfer to self contract then burn
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = burnFee
            });
        State.TokenContract.Burn.Send(
            new BurnInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                Amount = burnFee
            });
```
