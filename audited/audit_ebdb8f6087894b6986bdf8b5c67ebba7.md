### Title
Missing Symbol Validation in TokenHolder CreateScheme Allows Creation of Unusable Profit Schemes

### Summary
The `CreateScheme` function in TokenHolderContract does not validate that `input.Symbol` is non-empty or corresponds to a valid token. This allows creation of profit schemes with invalid symbols that will cause all subsequent `RegisterForProfits` calls to fail when they attempt to lock tokens, resulting in operational denial-of-service and wasted gas fees for users attempting to participate in these schemes.

### Finding Description
The `CreateScheme` function directly stores the user-provided symbol without any validation: [1](#0-0) 

The function accepts `input.Symbol` and stores it in state at line 29 without checking if the symbol is empty, properly formatted, or corresponds to an existing token.

When users later call `RegisterForProfits`, the function retrieves the scheme and uses `scheme.Symbol` to lock tokens: [2](#0-1) 

The `Lock` method in the MultiToken contract performs strict symbol validation: [3](#0-2) 

Line 197 checks for non-empty/non-whitespace symbols, and line 207 calls `AssertValidToken` which validates symbol format and token existence: [4](#0-3) 

This validation checks the symbol matches the regex pattern `^[a-zA-Z0-9]+(-[0-9]+)?$` and that the token exists in state: [5](#0-4) 

The `Withdraw` function is also affected, as it uses `scheme.Symbol` for both getting the locked amount and unlocking: [6](#0-5) 

### Impact Explanation
**Operational Impact - Medium Severity:**

1. **Denial of Service**: Any user who calls `RegisterForProfits` on a scheme with an invalid symbol will experience transaction failure, rendering the entire profit scheme unusable.

2. **Gas Waste**: Users attempting to register for profits will consume gas fees for failed transactions, with no way to recover these costs.

3. **User Experience Degradation**: Users cannot determine if a scheme is valid without attempting registration, leading to poor user experience and potential loss of trust.

4. **Griefing Vector**: Malicious actors could create schemes with invalid symbols and promote them off-chain, causing legitimate users to waste resources attempting to participate.

The scheme creator themselves is also affected since their scheme becomes permanently unusable, but the primary concern is unsuspecting third-party users who waste gas attempting to interact with broken schemes.

### Likelihood Explanation
**High Likelihood:**

1. **No Access Control**: `CreateScheme` is a public function with no authorization checks - any address can create schemes.

2. **Easy to Execute**: The attack requires a single transaction with an empty string, malformed symbol (e.g., "INVALID@#$"), or non-existent token name as the symbol parameter.

3. **Accidental Creation**: Beyond malicious intent, developers or users may accidentally create broken schemes through typos or configuration errors, with no validation to catch the mistake.

4. **No Detection Mechanism**: The contract provides no way to validate a scheme's symbol before attempting to register, forcing users to submit transactions to discover if a scheme is usable.

5. **Realistic Scenarios**:
   - Honest mistake: User types wrong symbol during scheme creation
   - Malicious griefing: Attacker creates scheme with invalid symbol and promotes it
   - Token not yet created: User creates scheme before token exists

### Recommendation
Add symbol validation in the `CreateScheme` function before storing the scheme:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Validate symbol is non-empty
    Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid symbol: cannot be empty.");
    
    // Validate symbol format and existence
    if (State.TokenContract.Value == null)
        State.TokenContract.Value = 
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
    
    var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput 
    { 
        Symbol = input.Symbol 
    });
    Assert(tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.Symbol), 
        $"Token does not exist: {input.Symbol}");
    
    // Rest of existing implementation...
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

**Additional Recommendations:**

1. Add test cases for invalid symbol scenarios:
   - Empty string
   - Invalid format (special characters)
   - Non-existent token
   - Null/whitespace strings

2. Consider adding a view method to validate schemes before registration attempts.

### Proof of Concept

**Initial State:**
- Token contract deployed with standard tokens (e.g., "ELF")
- User A has an account
- User B has an account with sufficient balance for gas

**Attack Sequence:**

1. **User A creates scheme with empty symbol:**
   ```
   Transaction: CreateScheme
   Input: { Symbol: "", MinimumLockMinutes: 100 }
   Sender: User A
   Expected: Success (no validation performed)
   ```

2. **User B attempts to register for profits:**
   ```
   Transaction: RegisterForProfits
   Input: { SchemeManager: User A, Amount: 1000 }
   Sender: User B
   Expected: Transaction fails with error "Invalid input symbol."
   Actual: Failure occurs at Lock method validation, User B loses gas
   ```

3. **Alternative: Create scheme with non-existent token:**
   ```
   Transaction: CreateScheme
   Input: { Symbol: "NONEXISTENT", MinimumLockMinutes: 100 }
   Sender: User A
   Expected: Success (no validation performed)
   ```

4. **User B attempts to register:**
   ```
   Transaction: RegisterForProfits
   Input: { SchemeManager: User A, Amount: 1000 }
   Sender: User B
   Expected: Transaction fails with error "Token is not found. NONEXISTENT"
   Actual: Failure occurs at AssertValidToken, User B loses gas
   ```

**Success Condition:** Users can create schemes with invalid symbols that pass `CreateScheme` but cause all subsequent `RegisterForProfits` calls to fail, confirming the absence of upfront validation.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-35)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
    {
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
