# Audit Report

## Title
Incorrect Use of TotalSupply Instead of Supply in GetNeededDeposit Causes Inflated Deposit Requirements

## Summary
The `GetNeededDeposit` function incorrectly uses `tokenInfo.TotalSupply` instead of `tokenInfo.Supply` to calculate tokens in external circulation. Since `TotalSupply` remains constant while `Supply` decreases when tokens are burned, this causes deposit requirements to be inflated by the amount of burned or unissued tokens, forcing users to deposit excessive base tokens when enabling connectors.

## Finding Description
The vulnerability exists in the `GetNeededDeposit` function where `amountOutOfTokenConvert` is calculated as: [1](#0-0) 

The core issue is that `TotalSupply` and `Supply` represent fundamentally different values in the token system:

- `TotalSupply` is set at token creation and represents the maximum issuable amount [2](#0-1) 

- `Supply` represents actual circulating tokens and increases on issuance [3](#0-2)  and decreases on burn [4](#0-3) 

When tokens are burned, only `Supply` decreases while `TotalSupply` remains constant. The TokenConverter itself burns tokens through the `HandleFee` function on every Buy/Sell operation [5](#0-4) 

The inflated `amountOutOfTokenConvert` value is then used in the Bancor formula to calculate the required deposit [6](#0-5) 

This deposit amount is enforced when users call `EnableConnector` [7](#0-6) 

The function should calculate tokens in external circulation as `Supply - balance - AmountToTokenConvert` because only `Supply` tokens actually exist. Using `TotalSupply` incorrectly counts burned and never-issued tokens as being "in external circulation" when they don't exist anywhere.

## Impact Explanation
**Economic Harm**: Users enabling connectors must deposit `(TotalSupply - Supply)` more base tokens than economically necessary. This overcount grows as tokens are burned through fee mechanisms or remain unissued.

**Quantified Example**: For a token with `TotalSupply = 1,000`, `Supply = 600` (400 burned/unissued), contract `balance = 300`, and `AmountToTokenConvert = 200`:
- Current (wrong): `1000 - 300 - 200 = 500` tokens external → high deposit required
- Correct: `600 - 300 - 200 = 100` tokens external → 5x lower deposit required

**Affected Users**: Any user enabling a connector for tokens where `Supply < TotalSupply`, including:
- Tokens with burn mechanisms (especially ELF, which burns fees via `HandleFee`)
- Tokens with gradual issuance schedules
- Any token where the issuer hasn't issued up to `TotalSupply`

**Severity**: If the `(TotalSupply - Supply)` gap is large enough, deposit requirements become prohibitively expensive, effectively preventing token listings and locking excess capital unnecessarily.

## Likelihood Explanation
**Trigger Conditions**: The issue manifests automatically whenever `Supply < TotalSupply`, which occurs in two common scenarios:
1. Tokens are burned via `HandleFee` during every Buy/Sell transaction
2. Tokens remain unissued (issuer hasn't issued up to `TotalSupply`)

**No Privileges Required**: `EnableConnector` is publicly callable with no authorization checks [8](#0-7)  Any user enabling a connector is affected.

**High Probability**: The gap widens naturally through normal protocol operations:
- Every Buy/Sell transaction burns tokens via the fee mechanism
- Many tokens intentionally use gradual issuance models with high initial `TotalSupply`
- ELF itself (the base token) has burns, making this issue systemic

**Detection Difficulty**: Users may notice high deposit requirements but likely attribute them to Bancor pricing rather than a calculation error.

## Recommendation
Change line 73 in `TokenConvert_Views.cs` from:
```csharp
var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
```

To:
```csharp
var amountOutOfTokenConvert = tokenInfo.Supply - balance - input.AmountToTokenConvert;
```

This ensures the calculation accurately reflects actual circulating tokens rather than theoretical maximum supply. Similarly, line 79 should also use `Supply` instead of `TotalSupply` for consistency.

## Proof of Concept
```csharp
[Fact]
public async Task GetNeededDeposit_Inflated_By_Burned_Tokens_Test()
{
    // Setup: Create token with TotalSupply = 100_0000_0000
    var tokenSymbol = "BURN";
    await CreateTokenAsync(tokenSymbol, totalSupply: 100_0000_0000);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue only 60_0000_0000 tokens (Supply = 60_0000_0000)
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 60_0000_0000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Burn 10_0000_0000 tokens (Supply now = 50_0000_0000)
    await TokenContractStub.Burn.SendAsync(new BurnInput
    {
        Amount = 10_0000_0000,
        Symbol = tokenSymbol
    });
    
    // Calculate deposit with AmountToTokenConvert = 40_0000_0000
    var depositInfo = await DefaultStub.GetNeededDeposit.CallAsync(
        new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = 40_0000_0000
        });
    
    // With current bug: amountOutOfTokenConvert = 100_0000_0000 - 0 - 40_0000_0000 = 60_0000_0000
    // Correct would be: amountOutOfTokenConvert = 50_0000_0000 - 0 - 40_0000_0000 = 10_0000_0000
    // Result: Deposit is inflated by 6x due to counting 50_0000_0000 burned/unissued tokens
    
    depositInfo.AmountOutOfTokenConvert.ShouldBe(60_0000_0000); // Current buggy behavior
    // Should be: 10_0000_0000
}
```

**Notes**

The vulnerability is confirmed through code analysis showing:
1. The semantic difference between `TotalSupply` (constant maximum) and `Supply` (actual circulating amount)
2. Automatic burn operations via `HandleFee` that decrease `Supply` but not `TotalSupply`
3. Direct usage of the inflated value in Bancor deposit calculations
4. No authorization checks preventing any user from being affected

While existing test cases expect the current (buggy) behavior, this doesn't validate correctness—it merely shows the tests were written to match the implementation. The logic error is clear: counting non-existent tokens (burned or never issued) as "in external circulation" is economically incorrect and harms users through excessive deposit requirements.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L72-72)
```csharp
            TotalSupply = input.TotalSupply,
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L164-164)
```csharp
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-300)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
    {
        var fromConnector = State.Connectors[input.TokenSymbol];
        Assert(fromConnector != null && !fromConnector.IsDepositAccount,
            "[EnableConnector]Can't find from connector.");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
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

        if (input.AmountToTokenConvert > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = input.TokenSymbol,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = input.AmountToTokenConvert
                });

        State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;
        toConnector.IsPurchaseEnabled = true;
        fromConnector.IsPurchaseEnabled = true;
        return new Empty();
```
