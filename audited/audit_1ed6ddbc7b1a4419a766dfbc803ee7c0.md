### Title
Precision Loss in Token Conversion Causes Fund Loss for Small Transactions

### Summary
The `GetReturnFromPaid()` function in BancorHelper.cs truncates decimal return values to long integers, causing users who sell small amounts of resource tokens to receive 0 base tokens while their sold tokens are still transferred to the contract. This results in permanent fund loss when the calculated return is fractional (between 0 and 1).

### Finding Description

The root cause is located in the return statement of `GetReturnFromPaid()`: [1](#0-0) 

When `paidAmount` is small relative to `fromConnectorBalance`, the Bancor formula correctly calculates a fractional return value. However, the cast to `long` truncates any value less than 1 to 0. 

The mathematical behavior described in the question is correct: when x approaches 1 (small paidAmount), Ln(x) approaches 0, causing the return value to approach 0. However, the issue isn't a "math domain error" - the formula works correctly. The vulnerability is the **precision loss from type casting**.

The vulnerable execution path in the `Sell` function: [2](#0-1) 

After calculating `amountToReceive` (which may be 0 due to truncation), the contract proceeds with transfers: [3](#0-2) 

The only protection is the `ReceiveLimit` check: [4](#0-3) 

However, according to the protocol specification, `receive_limit = 0` means "no limit" (bypass mode): [5](#0-4) 

When users don't set `receive_limit` or explicitly set it to 0, they have no protection against receiving 0 tokens while losing their sold tokens.

The only validation in BancorHelper checks that `paidAmount > 0`, but doesn't validate the return value: [6](#0-5) 

### Impact Explanation

**Direct Fund Loss:**
- Users selling small amounts relative to connector balances will receive 0 base tokens
- Their resource tokens are permanently transferred to the contract without compensation
- Example: With fromConnectorBalance = 100,000,000 and toConnectorBalance = 1,000,000, selling 1 token calculates a return of ~0.01 tokens, which truncates to 0

**Affected Users:**
- Users testing with small amounts before larger transactions
- Users making legitimate small-value swaps
- Any user who doesn't manually set `receive_limit > 0`

**Severity: HIGH**
- Permanent, irrecoverable fund loss
- Affects default contract behavior (receive_limit defaults to 0)
- No warning or revert when receiving 0 tokens

### Likelihood Explanation

**Reachable Entry Point:**
The `Sell` function is a public method callable by any user: [7](#0-6) 

**Feasible Preconditions:**
- Large connector balances (common in production)
- User attempts small transaction (common for testing or small swaps)
- User doesn't set receive_limit (default behavior)

**Execution Practicality:**
No special capabilities needed. User simply calls Sell with:
- `amount` = small value (e.g., 1-10 tokens)
- `receive_limit` = 0 (default/bypass)

**Probability: MEDIUM-HIGH**
- Occurs naturally with normal usage patterns
- Users unaware of precision loss risk
- Default parameter values are vulnerable
- No UI/documentation warning about minimum transaction amounts

### Recommendation

**Immediate Fix:**
Add a minimum return validation in the `Sell` function before line 180:
```csharp
Assert(amountToReceive > 0, "Calculated return is too small. Increase sell amount or set appropriate receive_limit.");
```

**Enhanced Protection:**
1. Add validation in `GetReturnFromPaid()` to ensure non-zero returns:
```csharp
var result = (long)(bt * (decimal.One - Exp(y * Ln(x))));
Assert(result > 0, "Calculated return rounds to zero. Transaction amount too small.");
return result;
```

2. Consider using a higher precision intermediate representation (e.g., multiply by 10^8 before casting, then divide after) to preserve fractional token amounts.

3. Document minimum transaction amounts based on connector balance ratios.

**Test Cases:**
Add regression tests for:
- Sell transactions where calculated return is 0 < x < 1
- Various connector balance ratios with minimum amounts
- Verify transactions revert rather than returning 0

### Proof of Concept

**Initial State:**
- Resource token connector balance: 100,000,000 tokens
- Base token connector balance: 1,000,000 tokens  
- Connector weights: both 0.5 (so y = 1)
- User holds 10 resource tokens

**Transaction Steps:**
1. User calls `Sell(symbol: "RESOURCE", amount: 1, receive_limit: 0)`
2. `GetReturnFromPaid` calculates:
   - x = 100,000,000 / 100,000,001 ≈ 0.99999999
   - Ln(0.99999999) ≈ -0.00000001
   - Exp(-0.00000001) ≈ 0.99999999
   - Return = 1,000,000 × (1 - 0.99999999) = 0.01
   - Cast to long: (long)(0.01) = 0
3. `amountToReceive` = 0
4. `ReceiveLimit` check passes (0 == 0 is true)
5. Contract transfers 0 base tokens to user
6. Contract takes 1 resource token from user

**Expected Result:** Transaction should revert with error indicating amount too small

**Actual Result:** Transaction succeeds. User loses 1 resource token and receives 0 base tokens.

**Success Condition:** User's resource token balance decreases by 1, base token balance unchanged (loss of funds).

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
