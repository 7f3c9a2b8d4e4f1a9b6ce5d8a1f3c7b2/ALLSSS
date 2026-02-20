# Audit Report

## Title
Missing Symbol Validation in TokenHolder CreateScheme Allows Creation of Unusable Profit Schemes

## Summary
The `CreateScheme` function in TokenHolderContract does not validate that `input.Symbol` is non-empty, properly formatted, or corresponds to a valid token. This allows creation of profit schemes with invalid symbols that will cause all subsequent `RegisterForProfits` and `Withdraw` calls to fail when they attempt to lock/unlock tokens, resulting in operational denial-of-service and wasted gas fees for users.

## Finding Description
The `CreateScheme` function directly stores the user-provided symbol without any validation. [1](#0-0) 

The function accepts `input.Symbol` and stores it in state without checking if the symbol is empty, properly formatted, or corresponds to an existing token. This breaks the security guarantee that schemes should only be created with valid, usable token symbols.

When users later call `RegisterForProfits`, the function retrieves the scheme and uses `scheme.Symbol` to lock tokens. [2](#0-1) 

The `Lock` method in the MultiToken contract performs strict symbol validation. [3](#0-2) 

The validation enforces multiple checks: non-empty/non-whitespace symbols and calls `AssertValidToken` which validates both symbol format and token existence. [4](#0-3) 

The symbol format validation uses a strict regex pattern and checks token existence in state. [5](#0-4) [6](#0-5) 

The `Withdraw` function is also affected, as it uses `scheme.Symbol` for both getting the locked amount and unlocking. [7](#0-6) 

**Attack Scenarios:**
1. **Empty/Whitespace Symbol**: Creating scheme with `""` or `"   "` will fail at Lock's whitespace check
2. **Invalid Format**: Creating scheme with `"INVALID@#$"` will fail at regex validation  
3. **Non-Existent Token**: Creating scheme with `"NOTEXIST"` (valid format) will fail at token existence check

All three scenarios result in the same impact: users attempting to `RegisterForProfits` will experience transaction revert, wasting gas fees.

## Impact Explanation
**Operational Impact - Medium Severity:**

1. **Denial of Service**: Any user who calls `RegisterForProfits` on a scheme with an invalid symbol will experience transaction failure with error messages like "Invalid symbol" or "Token is not found", rendering the entire profit scheme unusable for all participants.

2. **Gas Waste**: Users attempting to register for profits will consume gas fees for failed transactions, with no way to recover these costs. Each failed attempt costs the full transaction gas.

3. **User Experience Degradation**: Users cannot determine if a scheme is valid before attempting registration. The scheme appears valid in state (returned by `GetScheme`), but fails only upon interaction, leading to confusion and loss of trust.

4. **Griefing Vector**: Malicious actors can create schemes with invalid symbols and promote them off-chain (e.g., social media, dApp interfaces), causing legitimate users to waste resources. The attack cost is minimal (one CreateScheme transaction), but affects all subsequent users attempting to participate.

5. **Permanent Unusability**: Once created with an invalid symbol, a scheme cannot be fixed. There is no update mechanism, so the scheme and any contributed profits become permanently locked in an unusable state.

The scheme creator themselves is also affected since their scheme becomes permanently unusable, but the primary concern is unsuspecting third-party users who waste gas attempting to interact with broken schemes.

## Likelihood Explanation
**High Likelihood:**

1. **No Access Control**: `CreateScheme` is a public function with no authorization checks - any address can create schemes. [8](#0-7) 

2. **Easy to Execute**: The attack requires a single transaction with an empty string, malformed symbol (e.g., `"INVALID@#$"`), or non-existent token name as the symbol parameter. No special permissions or complex setup required.

3. **Accidental Creation**: Beyond malicious intent, developers or users may accidentally create broken schemes through typos or configuration errors. For example, typing `"ELF1"` instead of `"ELF"`, or `"APPP"` instead of `"APP"`. The lack of validation means these mistakes are not caught at creation time.

4. **No Detection Mechanism**: The contract provides no way to validate a scheme's symbol before attempting to register. Users must submit a transaction to discover if a scheme is usable, forcing them to waste gas to test validity.

5. **Realistic Scenarios**:
   - **Honest mistake**: User types wrong symbol during scheme creation
   - **Malicious griefing**: Attacker creates scheme with invalid symbol and promotes it via social channels
   - **Token not yet created**: User creates scheme before token exists, expecting to use it later
   - **Test/Development errors**: Developers testing with placeholder symbols that make it to production

The combination of public access, zero validation, and no recovery mechanism makes this vulnerability highly likely to occur in real-world usage.

## Recommendation
Add symbol validation in the `CreateScheme` function before storing the scheme. The validation should:

1. Check that the symbol is not empty or whitespace
2. Validate the symbol format using the same regex pattern as the MultiToken contract
3. Verify that a token with the given symbol exists in the TokenContract

Recommended fix:
```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation
    Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid symbol: cannot be empty or whitespace.");
    
    if (State.TokenContract.Value == null)
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
    
    // Verify token exists
    var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput { Symbol = input.Symbol });
    Assert(tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.Symbol), 
        $"Token with symbol {input.Symbol} does not exist.");
    
    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
    {
        Manager = Context.Sender,
        IsReleaseAllBalanceEveryTimeByDefault = true,
        CanRemoveBeneficiaryDirectly = true
    });

    State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
    {
        Symbol = input.Symbol,
        MinimumLockMinutes = input.MinimumLockMinutes,
        AutoDistributeThreshold = { input.AutoDistributeThreshold }
    };

    return new Empty();
}
```

## Proof of Concept
```csharp
[Fact]
public async Task CreateScheme_With_Invalid_Symbol_Causes_RegisterForProfits_To_Fail()
{
    // Create scheme with invalid empty symbol
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "" // Invalid empty symbol
    });

    // Verify scheme was created
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    scheme.Symbol.ShouldBe("");

    // Attempt to register for profits - should fail
    var registerResult = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            Amount = 100,
            SchemeManager = Starter
        });
    
    // Verify transaction failed due to symbol validation in Lock
    registerResult.TransactionResult.Error.ShouldContain("Invalid input symbol");
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-165)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
    {
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
        var scheme = GetValidScheme(input.SchemeManager);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L220-236)
```csharp
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;

        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");

        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-207)
```csharp
    public override Empty Lock(LockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Lock behaviour should be initialed by origin address.");

        var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
        if (allowance >= input.Amount)
            State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
        AssertValidToken(input.Symbol, input.Amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L18-21)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L33-39)
```csharp
    private TokenInfo AssertValidToken(string symbol, long amount)
    {
        AssertValidSymbolAndAmount(symbol, amount);
        var tokenInfo = GetTokenInfo(symbol);
        Assert(tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.Symbol), $"Token is not found. {symbol}");
        return tokenInfo;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```

**File:** protobuf/token_holder_contract.proto (L19-21)
```text
    // Create a scheme for distributing bonus.
    rpc CreateScheme (CreateTokenHolderProfitSchemeInput) returns (google.protobuf.Empty) {
    }
```
