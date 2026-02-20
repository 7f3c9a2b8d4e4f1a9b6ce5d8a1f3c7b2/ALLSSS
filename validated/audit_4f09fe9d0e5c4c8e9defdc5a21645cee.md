# Audit Report

## Title
Precision Loss in Token Conversion Causes Fund Loss for Small Transactions

## Summary
The `GetReturnFromPaid()` function in BancorHelper truncates decimal return values to long integers, causing users who sell small amounts of resource tokens to receive 0 base tokens while their sold tokens are still transferred to the contract. This results in permanent fund loss when the calculated return is fractional (between 0 and 1).

## Finding Description

The vulnerability exists in the TokenConverter contract's sell mechanism. When users attempt to sell small amounts of resource tokens, the Bancor pricing formula correctly calculates a fractional return value in decimal precision. However, the final return statement casts this decimal result directly to a `long` integer, truncating any value less than 1 to 0. [1](#0-0) 

When the calculated return is less than 1 (e.g., 0.01, 0.5, 0.99), the cast truncates it to 0. This truncated value then flows through the `Sell` function where it calculates `amountToReceive = 0`. [2](#0-1) 

The contract calculates the fee from this already-truncated value, resulting in a fee of 0. [3](#0-2) 

The only protection against receiving insufficient tokens is the `ReceiveLimit` parameter check. [4](#0-3) 

However, according to the protocol specification, when `receive_limit = 0`, there is "no limit" (bypass mode). [5](#0-4) 

When `ReceiveLimit == 0`, the assertion evaluates to `0 == 0 || 0 >= 0`, which is `true`, allowing the transaction to proceed even when `amountToReceiveLessFee = 0`.

The contract then transfers 0 base tokens to the user but still transfers the user's sold tokens to the contract. [6](#0-5) 

The BancorHelper only validates that the paid amount is positive, but does not validate the return value. [7](#0-6) 

**Mathematical Example:**
With `fromConnectorBalance = 100,000,000`, `toConnectorBalance = 1,000,000`, and `paidAmount = 1`:
- The Bancor formula calculates: `1,000,000 / (100,000,000 + 1) * 1 ≈ 0.00999999`
- `(long)0.00999999 = 0`
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

1. **No Special Privileges Required**: The `Sell` function is a public method callable by any user. [8](#0-7) 

2. **Realistic Preconditions**:
   - Large connector balances are common in production liquidity pools
   - Small transaction amounts are common for testing, gas optimization checks, or legitimate small swaps
   - Users typically don't manually set `receive_limit` unless they understand the slippage protection mechanism

3. **Natural Occurrence**: The vulnerability triggers under normal usage patterns without any malicious intent required.

4. **No Documentation Warning**: The existing tests only validate amounts of 100, 1000, and 10000 tokens, with no tests for single-digit amounts where truncation occurs. [9](#0-8) 

## Recommendation

Add validation to ensure the return amount is non-zero before proceeding with the transaction:

1. In `BancorHelper.GetReturnFromPaid()`, add a check after calculating the return value to ensure it rounds to at least 1.

2. In `TokenConverterContract.Sell()`, add an explicit assertion that `amountToReceive > 0` before the `ReceiveLimit` check.

3. Update the `ReceiveLimit` validation logic to reject transactions where `amountToReceiveLessFee == 0`, even when `ReceiveLimit == 0`.

## Proof of Concept

```csharp
[Fact]
public async Task Sell_Small_Amount_Results_In_Zero_Return_Test()
{
    // Setup: Create connector with large balances
    var fromConnectorBalance = 100_000_000L; // 100M
    var toConnectorBalance = 1_000_000L;     // 1M
    
    // Calculate return for selling 1 token
    var amountToReceive = BancorHelper.GetReturnFromPaid(
        fromConnectorBalance, 
        0.5m,  // fromConnectorWeight
        toConnectorBalance, 
        0.5m,  // toConnectorWeight
        1L     // paidAmount = 1
    );
    
    // Verify truncation bug: decimal 0.01 becomes long 0
    amountToReceive.ShouldBe(0L);
    
    // Attempt to sell with ReceiveLimit = 0 (no limit)
    var sellResult = await DefaultStub.Sell.SendAsync(new SellInput
    {
        Symbol = "WRITE",
        Amount = 1L,
        ReceiveLimit = 0L  // Default "no limit" mode
    });
    
    // Transaction succeeds despite zero return
    sellResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // User lost 1 token but received 0 base tokens
    var userBalance = await GetBalanceAsync("WRITE", DefaultSender);
    userBalance.ShouldBe(-1L); // Lost 1 token
}
```

## Notes

This vulnerability violates the fundamental invariant of token swaps: users should never lose tokens without receiving fair value in return. The combination of decimal-to-long truncation and the `ReceiveLimit = 0` bypass creates a silent fund loss scenario that affects any user making small transactions with default parameters.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L40-40)
```csharp
        if (paidAmount <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L47-53)
```csharp
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);

        var x = bf / (bf + a);
        var y = wf / wt;
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

**File:** test/AElf.Contracts.TokenConverter.Internal.Tests/BancorHelperTest.cs (L56-76)
```csharp
    [Theory]
    [InlineData(100L)]
    [InlineData(1000L)]
    [InlineData(10000L)]
    public void BuyResource_Test(long paidElf)
    {
        var resourceAmount1 = BuyOperation(paidElf);
        var resourceAmount2 = BuyOperation(paidElf);
        resourceAmount1.ShouldBeGreaterThanOrEqualTo(resourceAmount2);
    }

    [Theory]
    [InlineData(100L)]
    [InlineData(1000L)]
    [InlineData(10000L)]
    public void SellResource_Test(long paidRes)
    {
        var elfAmount1 = SellOperation(paidRes);
        var elfAmount2 = SellOperation(paidRes);
        elfAmount1.ShouldBeGreaterThanOrEqualTo(elfAmount2);
    }
```
