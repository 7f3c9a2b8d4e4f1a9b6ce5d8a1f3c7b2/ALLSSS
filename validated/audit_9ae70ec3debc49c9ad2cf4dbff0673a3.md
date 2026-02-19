# Audit Report

## Title 
Incorrect Use of TotalSupply Instead of Supply in GetNeededDeposit Causes Inflated Deposit Requirements

## Summary
The `GetNeededDeposit` function incorrectly uses `tokenInfo.TotalSupply` instead of `tokenInfo.Supply` when calculating tokens in external circulation. Since `TotalSupply` represents the maximum issuable amount (immutable) while `Supply` represents actual circulating tokens (decreases on burn), this causes the function to systematically overcount external tokens whenever tokens are burned or remain unissued, forcing users to deposit significantly more base tokens than necessary when enabling connectors.

## Finding Description

The vulnerability exists in the `GetNeededDeposit` function where it calculates tokens in external circulation using `TotalSupply` instead of `Supply`. [1](#0-0) 

The TokenInfo structure defines two distinct fields: `supply` (current circulating supply) and `total_supply` (maximum issuable amount). [2](#0-1) 

When tokens are burned, only `Supply` decreases while `TotalSupply` remains constant. [3](#0-2) 

The TokenConverter contract burns tokens through `HandleFee` on every Buy/Sell operation. [4](#0-3) 

The inflated `amountOutOfTokenConvert` is then passed to the Bancor formula to calculate the required deposit. [5](#0-4) 

This calculated deposit amount is enforced when users call `EnableConnector`. [6](#0-5) 

## Impact Explanation

**Economic Impact:** Users enabling connectors must deposit excessive base tokens proportional to `(TotalSupply - Supply)`. This gap grows continuously as:
1. Tokens are burned via `HandleFee` on every Buy/Sell transaction
2. Tokens remain unissued (common with gradual issuance schedules)

**Quantified Example:** 
- Token with TotalSupply = 1,000,000, Supply = 600,000 (400,000 burned/unissued)
- Contract balance = 300,000, AmountToTokenConvert = 200,000
- Wrong calculation: 1,000,000 - 300,000 - 200,000 = 500,000 tokens external
- Correct calculation: 600,000 - 300,000 - 200,000 = 100,000 tokens external
- **Result: 5x excessive deposit requirement**

**Who is Affected:** Any user attempting to enable connectors for tokens where `Supply < TotalSupply`, which includes the base token ELF itself due to fee burning.

**Severity:** Can make connector enablement prohibitively expensive, effectively preventing token listings and locking excess capital with no benefit to the protocol.

## Likelihood Explanation

**Automatic Trigger:** This is not an active attack but a systemic calculation error that triggers automatically whenever `Supply < TotalSupply`, which occurs in two common scenarios:

1. **Token Burns:** Every Buy/Sell transaction burns tokens via `HandleFee`, decreasing `Supply` while `TotalSupply` remains constant
2. **Gradual Issuance:** Many tokens intentionally maintain high `TotalSupply` with gradual issuance, leaving a gap between `TotalSupply` and `Supply`

**Attack Complexity:** None required - the vulnerability triggers during normal protocol operations. No special privileges needed.

**Feasibility:** Extremely high probability. The condition `Supply < TotalSupply` is common and persists throughout the token's lifecycle.

**Detection:** Users may notice unusually high deposit requirements but likely attribute it to the Bancor pricing model rather than identifying it as a calculation error.

## Recommendation

Replace `tokenInfo.TotalSupply` with `tokenInfo.Supply` in the `GetNeededDeposit` calculation:

```csharp
// Current (incorrect):
var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;

// Fixed:
var amountOutOfTokenConvert = tokenInfo.Supply - balance - input.AmountToTokenConvert;
```

Additionally, consider updating line 79 if `IsVirtualBalanceEnabled` uses `TotalSupply`:

```csharp
// If virtual balance is enabled, use Supply instead of TotalSupply
var tb = toConnector.IsVirtualBalanceEnabled
    ? toConnector.VirtualBalance.Add(tokenInfo.Supply)
    : tokenInfo.Supply;
```

This ensures the calculation accurately reflects tokens actually in circulation rather than the theoretical maximum.

## Proof of Concept

The vulnerability can be demonstrated by examining the state after token burns:

1. Create a token with TotalSupply = 10,000
2. Issue 10,000 tokens (Supply = 10,000)
3. Burn 4,000 tokens (Supply = 6,000, TotalSupply still = 10,000)
4. Add the token to TokenConverter with 3,000 tokens in the contract
5. Call `GetNeededDeposit` with AmountToTokenConvert = 2,000
6. Observe: amountOutOfTokenConvert = 10,000 - 3,000 - 2,000 = 5,000
7. Expected: amountOutOfTokenConvert should be 6,000 - 3,000 - 2,000 = 1,000
8. Result: Deposit requirement is 5x higher than necessary

The test demonstrates that `GetNeededDeposit` incorrectly counts 4,000 burned tokens as if they still exist, inflating the deposit requirement by exactly the burn amount.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L73-73)
```csharp
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L81-83)
```csharp
            needDeposit =
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
```

**File:** protobuf/token_contract.proto (L255-258)
```text
    // The current supply of the token.
    int64 supply = 3;
    // The total supply of the token.
    int64 total_supply = 4;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L328-328)
```csharp
        tokenInfo.Supply = tokenInfo.Supply.Sub(amount);
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L276-285)
```csharp
        var needDeposit = GetNeededDeposit(input);
        if (needDeposit.NeedAmount > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = State.BaseTokenSymbol.Value,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = needDeposit.NeedAmount
                });
```
