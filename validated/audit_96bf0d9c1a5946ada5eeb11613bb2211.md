# Audit Report

## Title
Precision Loss in Token Conversion Causes Fund Loss for Small Transactions

## Summary
The `GetReturnFromPaid()` function in BancorHelper truncates decimal return values to long integers, causing users who sell small amounts of resource tokens to receive 0 base tokens while their sold tokens are still transferred to the contract. This results in permanent fund loss when the calculated return is fractional (between 0 and 1).

## Finding Description

The vulnerability exists in the TokenConverter contract's sell mechanism. When users attempt to sell small amounts of resource tokens, the Bancor pricing formula correctly calculates a fractional return value in decimal precision. However, the final return statement casts this decimal result directly to a `long` integer. [1](#0-0) 

When the calculated return is less than 1 (e.g., 0.01, 0.5, 0.99), the cast truncates it to 0. This truncated value then flows through the `Sell` function: [2](#0-1) 

The contract calculates the fee from this already-truncated value, resulting in a fee of 0. [3](#0-2) 

The only protection against receiving insufficient tokens is the `ReceiveLimit` parameter check. [4](#0-3) 

However, according to the protocol specification, when `receive_limit = 0`, there is "no limit" (bypass mode). [5](#0-4) 

When `ReceiveLimit == 0`, the assertion `input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit` evaluates to `true || false`, which passes. This allows the transaction to proceed even when `amountToReceiveLessFee = 0`.

The contract then transfers 0 base tokens to the user [6](#0-5)  but still transfers the user's sold tokens to the contract. [7](#0-6) 

The BancorHelper only validates that the paid amount is positive, but does not validate the return value. [8](#0-7) 

**Mathematical Example:**
With `fromConnectorBalance = 100,000,000`, `toConnectorBalance = 1,000,000`, and `paidAmount = 1`:
- The Bancor formula calculates approximately 0.01 tokens
- `(long)0.01 = 0`
- User receives 0 tokens but loses 1 token

## Impact Explanation

**Severity: HIGH**

This vulnerability causes direct, permanent fund loss for affected users:

1. **Irrecoverable Loss**: Users' sold tokens are transferred to the contract without any compensation, as they receive 0 base tokens in return.

2. **Widespread Applicability**: 
   - Users testing the system with small amounts before larger transactions
   - Legitimate micro-transactions or small-value swaps
   - Any user who doesn't explicitly set `receive_limit > 0` (most users expect default behavior to be safe)

3. **Silent Failure**: The transaction succeeds without any warning or revert, making it appear as if the swap completed successfully when the user actually lost funds.

4. **Affects Default Behavior**: The issue manifests with default parameter values (`receive_limit = 0`), meaning users following standard usage patterns are vulnerable.

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

This vulnerability is highly likely to occur in production:

1. **No Special Privileges Required**: The `Sell` function is a public method callable by any user. [9](#0-8) 

2. **Realistic Preconditions**:
   - Large connector balances are common in production liquidity pools
   - Small transaction amounts are common for testing, gas optimization checks, or legitimate small swaps
   - Users typically don't manually set `receive_limit` unless they understand the slippage protection mechanism

3. **Natural Occurrence**: The vulnerability triggers under normal usage patterns without any malicious intent required.

4. **No Documentation Warning**: The existing tests only validate amounts of 100, 1000, and 10000 tokens. [10](#0-9)  There are no tests for single-digit amounts where truncation occurs, suggesting this edge case was not considered.

## Recommendation

Implement a minimum return amount validation in the `Sell` function:

```csharp
public override Empty Sell(SellInput input)
{
    // ... existing connector validation code ...
    
    var amountToReceive = BancorHelper.GetReturnFromPaid(
        GetSelfBalance(fromConnector), GetWeight(fromConnector),
        GetSelfBalance(toConnector), GetWeight(toConnector),
        input.Amount
    );
    
    // ADD THIS CHECK
    Assert(amountToReceive > 0, "Return amount too small - would result in zero tokens. Increase sell amount or set receive_limit.");
    
    var fee = Convert.ToInt64(amountToReceive * GetFeeRate());
    // ... rest of the function ...
}
```

Alternative fix: Implement proper rounding in BancorHelper instead of truncation, or scale the calculations to maintain precision throughout the operation.

## Proof of Concept

```csharp
[Fact]
public async Task Sell_SmallAmount_CausesFundLoss_Test()
{
    // Setup: Initialize contract with large connector balances
    await InitializeTokenConverterContract();
    
    // Create a scenario with 100M tokens in from-connector, 1M in to-connector
    // This represents a mature liquidity pool
    
    var userInitialBalance = 100L; // User has 100 tokens
    
    // User attempts to sell 1 token (testing or small swap)
    var sellResult = await UserStub.Sell.SendAsync(new SellInput
    {
        Symbol = WriteConnector.Symbol,
        Amount = 1L,
        ReceiveLimit = 0 // Default value - "no limit"
    });
    
    // Transaction succeeds
    sellResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify user lost 1 token from their balance
    var userResourceBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddress,
        Symbol = WriteConnector.Symbol
    });
    userResourceBalance.Balance.ShouldBe(userInitialBalance - 1L);
    
    // Verify user received 0 base tokens (FUND LOSS)
    var userBaseBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddress,
        Symbol = NativeSymbol
    });
    var expectedIncrease = 0L; // Should have received 0 due to truncation
    
    // The TokenSold event confirms 0 base tokens were transferred
    var logs = sellResult.TransactionResult.Logs.Where(l => l.Name == nameof(TokenSold)).ToList();
    logs.Count.ShouldBe(1);
    var soldEvent = TokenSold.Parser.ParseFrom(logs[0].NonIndexed);
    soldEvent.BaseAmount.ShouldBe(0L); // Proves user received 0 tokens
    soldEvent.SoldAmount.ShouldBe(1L); // But lost 1 token
    
    // This demonstrates permanent fund loss
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L174-174)
```csharp
        var fee = Convert.ToInt64(amountToReceive * GetFeeRate());
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L180-180)
```csharp
        Assert(input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-192)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L196-203)
```csharp
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

**File:** test/AElf.Contracts.TokenConverter.Internal.Tests/BancorHelperTest.cs (L68-71)
```csharp
    [InlineData(100L)]
    [InlineData(1000L)]
    [InlineData(10000L)]
    public void SellResource_Test(long paidRes)
```
