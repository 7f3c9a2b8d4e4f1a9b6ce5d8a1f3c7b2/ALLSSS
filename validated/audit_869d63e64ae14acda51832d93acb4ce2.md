# Audit Report

## Title
Indefinite Symbol Reservation via Unbounded SEED NFT Expiration Time

## Summary
The `CreateNFTInfo()` and `ExtendSeedExpirationTime()` functions lack upper bound validation on expiration times, allowing SEED NFT owners to reserve token symbols indefinitely (e.g., until year 9999). This enables permanent namespace squatting attacks that prevent legitimate users from creating tokens with reserved symbols, causing a denial-of-service on the token creation system.

## Finding Description

**Root Cause - No Upper Bound Validation:**

In `CreateNFTInfo()`, expiration time validation only enforces a lower bound with no maximum limit: [1](#0-0) 

The validation merely checks that current block time is before or equal to the expiration time, permitting astronomically large timestamp values representing year 9999 or beyond.

Similarly, `ExtendSeedExpirationTime()` allows SEED NFT owners to update expiration times without any upper bound validation: [2](#0-1) 

The function only validates sender ownership but imposes no limits on the new expiration value when updating the token's external info.

**Symbol Reservation Mechanism:**

When a SEED NFT is created, it reserves a symbol in the state mapping: [3](#0-2) 

The `CheckSymbolSeed()` function prevents creating new SEED NFTs for symbols that are already reserved by unexpired SEEDs: [4](#0-3) 

The assertion fails if an existing SEED reserves the symbol and hasn't expired (current time must be AFTER expiration time for the check to pass).

**Attack Execution Path:**

1. Attacker obtains a SEED NFT (as SEED-0 collection owner or through transfer)
2. Attacker calls `ExtendSeedExpirationTime()` with `ExpirationTime = 253402300799` (December 31, 9999)
3. The symbol remains reserved in `State.SymbolSeedMap` until year 9999
4. Token creation attempts fail for ALL users:

**Non-whitelisted users** must provide a valid SEED NFT via `CheckSeedNFT()` during token creation: [5](#0-4) 

But they cannot create a new SEED NFT for an already-reserved symbol because `CheckSymbolSeed()` is called during `CreateNFTInfo()`: [6](#0-5) 

**Whitelisted addresses** must also pass `CheckSymbolSeed()` validation: [7](#0-6) 

Both paths are blocked when an unexpired SEED NFT reserves the symbol.

**No Remediation Mechanism:**

No governance function or admin control exists to forcibly clear `SymbolSeedMap` entries. The codebase analysis confirms that `SymbolSeedMap` is only written to in one location and has no removal methods. The only way for a symbol to become available is natural expiration when current block time exceeds the expiration timestamp, which could be thousands of years in the future.

## Impact Explanation

**Concrete Harm:**
- **Symbol Namespace DoS**: Attackers can permanently block desirable token symbols (e.g., "BTC", "ETH", "USD") from being created by legitimate projects
- **Griefing Attack**: Malicious actors can squat on hundreds or thousands of valuable symbol names at minimal cost (only transaction fees)
- **Economic Damage**: Projects unable to use their intended symbols face branding issues, user confusion, and potential business losses
- **Ecosystem Degradation**: The token namespace utility degrades over time as more symbols get permanently locked

**Affected Parties:**
- All future token creators (both whitelisted and non-whitelisted users)
- The broader AElf ecosystem's token namespace availability
- Projects requiring specific symbol names for branding/interoperability

The impact is classified as Medium severity because it causes operational denial-of-service on token namespace rather than direct fund theft, but the effects are permanent and affect the entire ecosystem.

## Likelihood Explanation

**Attacker Capabilities:**
- Must own a SEED NFT to call `ExtendSeedExpirationTime()`
- SEED NFTs can be obtained by being the SEED-0 collection owner or receiving them via transfer (NFTs are transferable via standard Transfer/TransferFrom methods)
- Once in possession, can extend expiration arbitrarily with no restrictions

**Attack Complexity:**
- Very low: Single function call with two parameters (symbol and far-future timestamp)
- No special preconditions beyond SEED NFT ownership
- Attack is immediately effective and irreversible
- Can be repeated for multiple symbols if attacker has multiple SEED NFTs

**Economic Rationality:**
- Attack cost: Single transaction fee for `ExtendSeedExpirationTime()` call (negligible)
- Potential gain: Control over valuable namespace, potential speculation/ransom opportunities
- Risk: None - no penalty mechanism exists for setting far-future expiration times

The likelihood is classified as Medium because it depends on SEED NFT distribution policies, but the mechanism is unprotected once SEEDs enter circulation. The attack is economically rational for speculation or griefing purposes.

## Recommendation

Add upper bound validation for expiration times in both `CreateNFTInfo()` and `ExtendSeedExpirationTime()` functions. The validation should limit expiration times to a reasonable maximum (e.g., 10 years from current time).

For `CreateNFTInfo()`, add a maximum bound check:
```csharp
const long MaxExpirationPeriod = 315360000; // 10 years in seconds
Assert(expirationTimeLong <= Context.CurrentBlockTime.Seconds + MaxExpirationPeriod, 
    "Expiration time exceeds maximum allowed period.");
```

For `ExtendSeedExpirationTime()`, add similar validation:
```csharp
const long MaxExpirationPeriod = 315360000; // 10 years in seconds
Assert(input.ExpirationTime <= Context.CurrentBlockTime.Seconds + MaxExpirationPeriod,
    "Expiration time exceeds maximum allowed period.");
```

Additionally, consider implementing a governance function to clear or override `SymbolSeedMap` entries in emergency situations.

## Proof of Concept

```csharp
[Fact]
public async Task IndefiniteSymbolReservation_NamespaceDoS_Test()
{
    // Setup: Create SEED-0 collection and a SEED NFT for symbol "TESTTOKEN"
    var seedOwnedSymbol = "TESTTOKEN";
    var createInput = new CreateInput
    {
        Symbol = seedOwnedSymbol,
        TokenName = "Test Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultAddress,
        IsBurnable = true,
        IssueChainId = _chainId
    };
    
    await CreateSeedNftAsync(TokenContractStub, createInput);
    
    // Attack: Extend expiration time to year 9999 (timestamp: 253402300799)
    var seedSymbol = "SEED-1"; // Assuming this is the created SEED NFT symbol
    await TokenContractStub.ExtendSeedExpirationTime.SendAsync(new ExtendSeedExpirationTimeInput
    {
        Symbol = seedSymbol,
        ExpirationTime = 253402300799 // December 31, 9999
    });
    
    // Impact: Any user (including whitelisted) cannot create token with "TESTTOKEN" symbol
    // Non-whitelisted user cannot create new SEED NFT for "TESTTOKEN"
    var newSeedCreateInput = new CreateInput
    {
        Symbol = "SEED-2",
        Decimals = 0,
        IsBurnable = true,
        TokenName = "seed token 2",
        TotalSupply = 1,
        Issuer = Accounts[1].Address,
        Owner = Accounts[1].Address,
        ExternalInfo = new ExternalInfo()
    };
    newSeedCreateInput.ExternalInfo.Value["__seed_owned_symbol"] = seedOwnedSymbol;
    newSeedCreateInput.ExternalInfo.Value["__seed_exp_time"] = TimestampHelper.GetUtcNow().AddDays(1).Seconds.ToString();
    
    // This should fail with "OwnedSymbol has been created"
    var result = await TokenContractStub.Create.SendWithExceptionAsync(newSeedCreateInput);
    result.TransactionResult.Error.ShouldContain("OwnedSymbol has been created");
    
    // Symbol remains reserved until year 9999, causing permanent namespace DoS
}
```

This test demonstrates that once a SEED NFT's expiration is extended to a far-future date, no other user can create a SEED NFT for the same symbol, effectively causing permanent namespace squatting.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L42-45)
```csharp
            Assert(input.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                       out var expirationTime)
                   && long.TryParse(expirationTime, out var expirationTimeLong) &&
                   Context.CurrentBlockTime.Seconds <= expirationTimeLong, "Invalid ownedSymbol.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L50-50)
```csharp
            CheckSymbolSeed(ownedSymbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L51-51)
```csharp
            State.SymbolSeedMap[ownedSymbol.ToUpper()] = input.Symbol;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L57-67)
```csharp
    private void CheckSymbolSeed(string ownedSymbol)
    {
        var oldSymbolSeed = State.SymbolSeedMap[ownedSymbol.ToUpper()];

        Assert(oldSymbolSeed == null || !GetTokenInfo(oldSymbolSeed).ExternalInfo.Value
                   .TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                       out var oldSymbolSeedExpireTime) ||
               !long.TryParse(oldSymbolSeedExpireTime, out var symbolSeedExpireTime)
               || Context.CurrentBlockTime.Seconds > symbolSeedExpireTime,
            "OwnedSymbol has been created");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L118-131)
```csharp
    private void CheckSeedNFT(string symbolSeed, String symbol)
    {
        Assert(!string.IsNullOrEmpty(symbolSeed), "Seed NFT does not exist.");
        var tokenInfo = GetTokenInfo(symbolSeed);
        Assert(tokenInfo != null, "Seed NFT does not exist.");
        Assert(State.Balances[Context.Sender][symbolSeed] > 0, "Seed NFT balance is not enough.");
        Assert(tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.SeedOwnedSymbolExternalInfoKey, out var ownedSymbol) && ownedSymbol == symbol,
            "Invalid OwnedSymbol.");
        Assert(tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                   out var expirationTime)
               && long.TryParse(expirationTime, out var expirationTimeLong) &&
               Context.CurrentBlockTime.Seconds <= expirationTimeLong, "OwnedSymbol is expired.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L695-722)
```csharp
    public override Empty ExtendSeedExpirationTime(ExtendSeedExpirationTimeInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo == null)
        {
            throw new AssertionException("Seed NFT does not exist.");
        }

        Assert(tokenInfo.Owner == Context.Sender, "Sender is not Seed NFT owner.");
        var oldExpireTimeLong = 0L;
        if (tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                out var oldExpireTime))
        {
            long.TryParse(oldExpireTime, out oldExpireTimeLong);
        }

        tokenInfo.ExternalInfo.Value[TokenContractConstants.SeedExpireTimeExternalInfoKey] =
            input.ExpirationTime.ToString();
        State.TokenInfos[input.Symbol] = tokenInfo;
        Context.Fire(new SeedExpirationTimeUpdated
        {
            ChainId = tokenInfo.IssueChainId,
            Symbol = input.Symbol,
            OldExpirationTime = oldExpireTimeLong,
            NewExpirationTime = input.ExpirationTime
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L282-282)
```csharp
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
```
