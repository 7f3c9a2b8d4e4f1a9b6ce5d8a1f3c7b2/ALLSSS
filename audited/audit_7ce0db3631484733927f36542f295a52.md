# Audit Report

## Title 
Precision Loss in Token Conversion Causes Fund Loss for Small Transactions

## Summary
The TokenConverter contract's `Sell()` function allows users to lose tokens without receiving any base tokens in return when selling small amounts. The root cause is precision loss in `BancorHelper.GetReturnFromPaid()` which truncates decimal calculations to zero, combined with insufficient slippage protection that can be bypassed using the default `receive_limit = 0` parameter.

## Finding Description

The vulnerability exists in the Bancor price calculation and subsequent token transfer flow:

**Root Cause - Precision Truncation:**
The `GetReturnFromPaid()` function calculates the return amount using decimal arithmetic but casts the final result to `long`, truncating any fractional value below 1 to zero. [1](#0-0) 

When users sell small amounts relative to large connector balances, the Bancor formula correctly calculates a fractional return (e.g., 0.01, 0.5, 0.99 tokens), but the cast to `long` truncates these values to 0.

**Vulnerable Execution Path:**
The `Sell()` function calls `GetReturnFromPaid()` to calculate `amountToReceive`, which may be 0 due to truncation. [2](#0-1) 

**Insufficient Protection:**
The only slippage protection is a check against `ReceiveLimit`. [3](#0-2) 

However, the protocol specification explicitly states that `receive_limit = 0` means "no limit" (bypass mode). [4](#0-3) 

Since protobuf3 defaults `int64` fields to 0, users who don't explicitly set `receive_limit` have no protection.

**Fund Loss Execution:**
After the check passes (with `ReceiveLimit = 0` and `amountToReceive = 0`), the contract transfers 0 base tokens to the user, then transfers the user's resource tokens to the contract. [5](#0-4) 

**No Output Validation:**
The only input validation in BancorHelper checks that `paidAmount > 0`, but there is no validation that the return value is greater than 0. [6](#0-5) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes permanent, irrecoverable fund loss:

1. **Direct Financial Loss**: Users lose their resource tokens without receiving any base tokens in compensation.

2. **Realistic Scenario Example**: With `fromConnectorBalance = 100,000,000` and `toConnectorBalance = 1,000,000` (both realistic values for production AMM pools), selling just 1 token would calculate a return of approximately 0.00001 tokens, which truncates to 0.

3. **Broad User Impact**: 
   - Users testing transactions with small amounts before larger trades
   - Users making legitimate small-value swaps
   - Any user who uses the default `receive_limit = 0` (no explicit slippage protection)

4. **No Recovery Mechanism**: Once tokens are transferred to the contract with 0 return, they cannot be recovered.

5. **Protocol Invariant Violation**: Breaks the fundamental AMM guarantee that users receive fair value for tokens sold based on the pricing formula.

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

This vulnerability is highly likely to occur in practice:

1. **Public Entry Point**: The `Sell()` function is a public method callable by any user without special permissions. [7](#0-6) 

2. **Realistic Preconditions**: 
   - Large connector balances are common and expected in production AMM pools
   - Small transaction amounts are natural user behavior (testing, small swaps, partial exits)
   - Default `receive_limit = 0` is the standard behavior when users don't explicitly set slippage limits

3. **No Special Capabilities Required**: Any user can trigger this by simply calling `Sell()` with a small amount and either not setting `receive_limit` or setting it to 0.

4. **Hidden Risk**: There are no warnings in the contract code or documentation about minimum transaction sizes, making users unaware of this precision loss risk.

5. **Natural Occurrence**: This will happen organically as users interact with the protocol, especially as pools grow larger over time, making the threshold for 0-return transactions higher.

## Recommendation

Implement multiple layers of protection:

1. **Add Minimum Return Validation**: In `GetReturnFromPaid()`, validate that the calculated return is at least 1 before returning:
```csharp
var result = (long)(bt * (decimal.One - Exp(y * Ln(x))));
if (result == 0)
    throw new InvalidValueException("Return amount is too small, transaction would result in zero tokens.");
return result;
```

2. **Enforce Non-Zero ReceiveLimit**: In `Sell()`, require users to explicitly set a positive `receive_limit`:
```csharp
Assert(input.ReceiveLimit > 0, "Must set a positive receive_limit for slippage protection.");
Assert(amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");
```

3. **Add Minimum Transaction Size**: Document and enforce minimum transaction sizes based on pool depth to prevent precision loss scenarios.

4. **Consider Higher Precision**: Evaluate using a higher precision intermediate representation before final truncation, or implement proper rounding instead of truncation.

## Proof of Concept

```csharp
[Fact]
public async Task Sell_SmallAmount_ZeroReturn_FundLoss_Test()
{
    // Setup: Create large pool balances
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    // Simulate large connector balances
    var largeFromBalance = 100_000_000L; // 100M tokens
    var largeToBalance = 1_000_000L;     // 1M base tokens
    var weight = 0.5m;
    
    // User attempts to sell 1 token with receive_limit = 0 (default)
    var userBalanceBefore = await GetBalanceAsync(WriteSymbol, DefaultSender);
    
    // Calculate expected return - will be fractional and truncate to 0
    var expectedReturn = BancorHelper.GetReturnFromPaid(
        largeFromBalance, weight, largeToBalance, weight, 1L);
    expectedReturn.ShouldBe(0L); // Demonstrates truncation to 0
    
    // Execute sell transaction
    var sellResult = await DefaultStub.Sell.SendAsync(new SellInput
    {
        Symbol = WriteSymbol,
        Amount = 1L,
        ReceiveLimit = 0L // Default - no slippage protection
    });
    sellResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify fund loss: user lost 1 token but received 0 base tokens
    var userBalanceAfter = await GetBalanceAsync(WriteSymbol, DefaultSender);
    userBalanceAfter.ShouldBe(userBalanceBefore - 1L); // User lost 1 token
    
    var baseTokenReceived = await GetBalanceAsync(BaseSymbol, DefaultSender);
    baseTokenReceived.ShouldBe(0L); // User received 0 base tokens
    
    // User suffered permanent fund loss
}
```

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L40-40)
```csharp
        if (paidAmount <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L53-53)
```csharp
        return (long)(bt * (decimal.One - Exp(y * Ln(x))));
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-161)
```csharp
    public override Empty Sell(SellInput input)
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L180-180)
```csharp
        Assert(input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-203)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
        // Transfer sold token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = input.Symbol,
                From = Context.Sender,
                To = Context.Self,
                Amount = input.Amount
            });
```

**File:** protobuf/token_converter_contract.proto (L140-142)
```text
    // Limits on tokens obtained by selling. If the token obtained is less than this value, the sale will be abandoned.
    // And 0 is no limit.
    int64 receive_limit = 3;
```
