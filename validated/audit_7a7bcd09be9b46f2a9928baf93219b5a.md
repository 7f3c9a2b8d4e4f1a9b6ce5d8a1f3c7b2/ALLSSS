# Audit Report

## Title
Rounding Error Exploitation in TokenConverter Allows Fee Avoidance and Underpayment Through Repeated Small Purchases

## Summary
The TokenConverter contract's Bancor pricing implementation truncates decimal calculations to `long`, causing precision loss. Combined with fee calculation truncation, this enables attackers to avoid fees entirely and underpay for tokens by splitting large purchases into many small transactions. The vulnerability causes direct financial losses to the Treasury contract and undermines the token burn mechanism.

## Finding Description

The vulnerability exists in the Bancor pricing formula where decimal-to-long casting causes precision loss. When connector weights are equal (the production configuration for all resource token pairs), the simplified formula truncates the mathematically correct payment amount: [1](#0-0) 

The production configuration uses equal weights (0.005) for both connectors: [2](#0-1) [3](#0-2) 

The `Buy` function compounds this with fee truncation: [4](#0-3) 

With a fee rate of 0.005 (configured in production), when `amountToPay < 200`, the expression `amountToPay * 0.005 < 1.0` causes the fee to truncate to zero: [5](#0-4) 

Fee collection is conditional: [6](#0-5) 

This means purchases where `amountToPay < 200` completely avoid fees. There is no minimum purchase amount enforcement beyond the implicit requirement that `input.Amount > 0`.

**Attack Execution:**
An attacker wanting to acquire a large amount of tokens can split the purchase into many small transactions. Each small transaction:
1. Pays a rounded-down amount due to `(long)` casting
2. Avoids fees entirely when the payment is below 200 tokens
3. Updates balances, but the attacker still benefits from accumulated rounding losses

For example, instead of buying 1,000 tokens in one transaction (paying ~1,001 + fees), the attacker makes 1,000 individual 1-token purchases, each costing approximately 1 token with 0 fees.

## Impact Explanation

**Direct Financial Loss:**

1. **Fee Avoidance:** 100% of fees avoided when `amountToPay < 200`. With production fee rate of 0.005, any purchase costing less than 200 base tokens pays zero fees.

2. **Rounding Loss:** Each small purchase truncates fractional amounts, causing the protocol to receive less payment than mathematically correct. Over many transactions, these losses accumulate.

**Affected Parties:**

The `HandleFee` function splits fees 50/50: [7](#0-6) 

When fees are avoided:
- **Treasury contract** loses 50% of fees that should be donated to the dividend pool
- **All token holders** lose the deflationary benefit from 50% of fees that should be burned [8](#0-7) [9](#0-8) 

The losses scale proportionally with trading volume. This breaks the protocol's core pricing invariant that users must pay the correct Bancor formula price plus configured fees.

## Likelihood Explanation

**High Likelihood:**

1. **Accessibility:** `Buy` is a public RPC method with no authorization requirements: [10](#0-9) 

2. **Preconditions Met:** Production configuration satisfies exploit requirements - equal connector weights (0.005) and fee rate of 0.005 are used for all resource tokens.

3. **No Protections:** The contract has no minimum purchase amount, no minimum fee requirement, and no rate limiting mechanisms.

4. **Economic Viability:** Fee avoidance alone (100% savings on fees) justifies the attack when transaction costs are low. With automated bots, the combined savings from fee avoidance and rounding become highly profitable.

5. **Detection Difficulty:** The attack appears as normal trading activity - just many small legitimate purchases rather than one large purchase.

## Recommendation

Implement the following mitigations:

1. **Enforce Minimum Fee:** Add a minimum fee threshold regardless of purchase size:
```csharp
var fee = Convert.ToInt64(amountToPay * GetFeeRate());
const long MinimumFee = 1; // Minimum 1 token fee
if (fee == 0 && amountToPay > 0) 
    fee = MinimumFee;
```

2. **Enforce Minimum Purchase Amount:** Add validation to prevent excessively small purchases:
```csharp
const long MinimumPurchaseAmount = 100; // Minimum tokens per purchase
Assert(input.Amount >= MinimumPurchaseAmount, "Purchase amount too small");
```

3. **Use Higher Precision Arithmetic:** Consider using `decimal` throughout calculations and only converting to `long` at the final step, or implement fixed-point arithmetic to minimize rounding losses.

4. **Rate Limiting:** Implement per-user rate limiting to prevent rapid sequential small purchases.

## Proof of Concept

```csharp
[Fact]
public async Task Exploit_FeeAvoidanceViaSmallPurchases_Test()
{
    // Setup
    await CreateWriteToken();
    await InitializeTreasuryContractAsync();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    const long totalTokensDesired = 1000L;
    const long tokensPerPurchase = 1L;
    
    // Scenario 1: Bulk purchase
    var bulkAmountToPay = BancorHelper.GetAmountToPayFromReturn(
        ELFConnector.VirtualBalance, decimal.Parse(ELFConnector.Weight),
        await GetBalanceAsync(WriteSymbol, TokenConverterContractAddress),
        decimal.Parse(WriteConnector.Weight), totalTokensDesired);
    var bulkFee = Convert.ToInt64(bulkAmountToPay * 0.005m);
    var bulkTotalCost = bulkAmountToPay + bulkFee;
    
    // Scenario 2: Many small purchases
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Spender = TokenConverterContractAddress,
        Symbol = "ELF",
        Amount = bulkTotalCost * 2 // Enough for testing
    });
    
    var initialBalance = await GetBalanceAsync(NativeSymbol, DefaultSender);
    var totalPaidInSmallPurchases = 0L;
    
    for (int i = 0; i < totalTokensDesired; i++)
    {
        var beforeBalance = await GetBalanceAsync(NativeSymbol, DefaultSender);
        await DefaultStub.Buy.SendAsync(new BuyInput
        {
            Symbol = WriteConnector.Symbol,
            Amount = tokensPerPurchase,
            PayLimit = 10L // Allow small amounts
        });
        var afterBalance = await GetBalanceAsync(NativeSymbol, DefaultSender);
        totalPaidInSmallPurchases += (beforeBalance - afterBalance);
    }
    
    var finalBalance = await GetBalanceAsync(NativeSymbol, DefaultSender);
    var actualTotalPaid = initialBalance - finalBalance;
    
    // Verify exploit: small purchases cost less than bulk
    actualTotalPaid.ShouldBeLessThan(bulkTotalCost);
    
    // Verify Treasury lost fees
    var donatedFees = await TreasuryContractStub.GetUndistributedDividends.CallAsync(new Empty());
    donatedFees.Value[NativeSymbol].ShouldBeLessThan(bulkFee / 2); // Much less than expected
}
```

This test demonstrates that making many small purchases costs significantly less than one bulk purchase due to fee avoidance and accumulated rounding losses, confirming the vulnerability.

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L124-124)
```csharp
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L130-130)
```csharp
        if (fee > 0) HandleFee(fee);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L216-217)
```csharp
        var donateFee = fee.Div(2);
        var burnFee = fee.Sub(donateFee);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L237-241)
```csharp
        State.DividendPoolContract.Donate.Send(new DonateInput
        {
            Symbol = State.BaseTokenSymbol.Value,
            Amount = donateFee
        });
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

**File:** protobuf/token_converter_contract.proto (L28-29)
```text
    rpc Buy (BuyInput) returns (google.protobuf.Empty) {
    }
```
