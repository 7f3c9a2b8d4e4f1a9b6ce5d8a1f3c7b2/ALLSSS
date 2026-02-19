# Audit Report

## Title
Symbol Alias Shadowing via Direct Token Registration

## Summary
The `SetSymbolAlias` function fails to validate whether a proposed alias already exists as a direct token in `State.TokenInfos`. This creates an asymmetric validation vulnerability where an attacker can register a malicious token with a simple symbol before an NFT collection owner sets that same symbol as an alias. Due to `GetTokenInfo`'s prioritization of direct token lookups, users will unknowingly interact with the attacker's token instead of the intended NFT.

## Finding Description

The vulnerability stems from an asymmetric validation pattern between token creation and alias registration.

**Vulnerable Alias Registration:**
The `SetSymbolAlias` function only validates that the alias doesn't exist in `SymbolAliasMap`, but fails to check whether a direct token already exists with that symbol in `State.TokenInfos`. [1](#0-0) 

**Token Lookup Priority:**
The `GetTokenInfo` helper method prioritizes direct token lookups over alias resolution. When both a direct token and an alias exist with the same symbol, the direct token is always returned. [2](#0-1) 

**Attack Prerequisites:**
1. Symbol validation allows simple symbols without dashes (e.g., "ABC"): [3](#0-2) 

2. Symbols without dashes are classified as regular tokens: [4](#0-3) 

3. Token creation via SEED NFT allows creating tokens with simple symbols: [5](#0-4) 

4. SEED NFT ownership verification confirms the OwnedSymbol matches the token being created: [6](#0-5) 

5. Alias rules enforce that the alias must match the NFT collection prefix: [7](#0-6) 

**The Asymmetry:**
The `CheckTokenExists` validation runs during token creation and uses `GetTokenInfo`, which checks both direct tokens AND aliases. This provides one-way protection: you cannot create a token if an alias already exists. [8](#0-7) 

However, there is no reverse check in `SetSymbolAlias` to prevent creating an alias when a direct token already exists. This asymmetry enables the shadowing attack.

**Exploit Sequence:**
1. Attacker obtains SEED NFT with `OwnedSymbol="ABC"`
2. Attacker calls `Create()` with `Symbol="ABC"` → succeeds because `CheckTokenExists` finds no alias in `SymbolAliasMap`
3. Token "ABC" is registered in `State.TokenInfos["ABC"]`
4. Later, NFT collection owner calls `SetSymbolAlias(alias="ABC")` → succeeds because line 750 only checks `SymbolAliasMap`
5. Alias is registered in `State.SymbolAliasMap["ABC"]`
6. Both now exist: `State.TokenInfos["ABC"]` (attacker's token) and `State.SymbolAliasMap["ABC"]` (NFT alias)
7. Any call to `GetTokenInfo("ABC")` returns the attacker's token due to priority at lines 407-408

## Impact Explanation

**Direct Financial Loss:**
Users intending to interact with the NFT via its alias will unknowingly transact with the attacker's malicious token. This results in:
- Misdirected transfers that permanently lock funds in the attacker's token
- Approvals granted to the wrong token that can be exploited to drain balances
- Failed NFT operations as users are operating on an incompatible token contract

**Protocol Integrity:**
The NFT alias system's core guarantee—that aliases uniquely resolve to their intended NFT collections—is violated. The alias becomes permanently unusable for its intended purpose, as the direct token will always shadow it.

**Ecosystem Impact:**
- DApps and marketplaces that rely on alias-based lookups will malfunction
- NFT collection owners lose their intended user-friendly branding
- Protocol reputation suffers from user confusion and fund losses

**Severity: Medium**
The vulnerability requires specific preconditions (attacker must acquire and burn a SEED NFT), but once exploited, it causes concrete financial harm and permanent functional degradation of the alias system.

## Likelihood Explanation

**Attacker Requirements:**
1. Acquire a SEED NFT with `OwnedSymbol` matching the target alias
2. Execute token creation before the NFT owner sets their alias
3. SEED NFTs are tradeable assets that can be purchased on the market

**Attack Complexity: Low**
Once the SEED NFT is obtained, the attack requires only a single `Create()` transaction. No special privileges, complex state manipulation, or cryptographic operations are needed.

**Economic Rationality: Viable**
For valuable or widely-used NFT collections with simple, brandable symbols, the investment cost (SEED NFT price + gas) can be justified by:
- Capturing misdirected user funds
- Phishing opportunities through brand impersonation
- Extortion by holding the symbol hostage

**Detection Difficulty:**
The vulnerability window exists from NFT collection creation until alias registration. Attackers can monitor chain events to identify targets and frontrun alias registration transactions. Users may not detect the collision until funds are lost.

**Probability: Medium**
While requiring upfront investment and timing, the attack is technically straightforward and economically rational for high-value targets. No protocol-level protections exist to prevent the collision.

## Recommendation

Add a validation check in `SetSymbolAlias` to prevent alias registration if a direct token with the same symbol already exists:

```csharp
public override Empty SetSymbolAlias(SetSymbolAliasInput input)
{
    // ... existing validations ...
    
    // Check if alias exists in SymbolAliasMap
    Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");
    
    // ADD THIS: Check if a direct token with this symbol exists
    var existingToken = State.TokenInfos[input.Alias];
    Assert(existingToken == null || string.IsNullOrEmpty(existingToken.Symbol), 
           $"Cannot set alias {input.Alias}: a token with this symbol already exists.");
    
    // ... rest of function ...
}
```

This creates symmetric validation: neither tokens nor aliases can be registered if the other already exists with the same symbol.

## Proof of Concept

```csharp
[Fact]
public async Task SymbolAliasShadowing_AttackerTokenShadowsNFTAlias()
{
    // Setup: Create SEED NFT with OwnedSymbol="ABC"
    var seedSymbol = "SEED-123";
    await CreateSeedNftAsync(DefaultSender, seedSymbol, "ABC");
    
    // Step 1: Attacker creates malicious token "ABC" using SEED NFT
    var createResult = await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ABC",
        TokenName = "Malicious Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true
    });
    createResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 2: NFT collection owner creates NFT collection "ABC-0"
    await CreateNFTCollectionAsync(User1Address, "ABC");
    
    // Step 3: NFT owner attempts to set alias "ABC" for their NFT
    var aliasResult = await TokenContractUser1Stub.SetSymbolAlias.SendAsync(
        new SetSymbolAliasInput
        {
            Symbol = "ABC-123",  // NFT item symbol
            Alias = "ABC"        // Desired alias
        });
    aliasResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 4: Verify shadowing - GetTokenInfo returns attacker's token, not NFT
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
    {
        Symbol = "ABC"
    });
    
    // VULNERABILITY: Returns attacker's malicious token instead of resolving to NFT
    tokenInfo.Symbol.ShouldBe("ABC");
    tokenInfo.TokenName.ShouldBe("Malicious Token");
    tokenInfo.Issuer.ShouldBe(DefaultSender); // Attacker, not NFT owner
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L59-64)
```csharp
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L124-126)
```csharp
        Assert(tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.SeedOwnedSymbolExternalInfoKey, out var ownedSymbol) && ownedSymbol == symbol,
            "Invalid OwnedSymbol.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L750-750)
```csharp
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L840-852)
```csharp
    private void CheckTokenAlias(string alias, string collectionSymbol)
    {
        if (collectionSymbol == null)
        {
            throw new AssertionException("Token alias can only be set for NFT Item.");
        }

        // Current Rule: Alias must be the seed name.
        var parts = collectionSymbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(parts.Length == 2, $"Incorrect collection symbol: {collectionSymbol}.");
        Assert(parts.Last() == TokenContractConstants.CollectionSymbolSuffix, "Incorrect collection symbol suffix.");
        Assert(alias == parts.First(), $"Alias for an item of {collectionSymbol} cannot be {alias}.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L28-31)
```csharp
    private bool IsValidCreateSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L295-300)
```csharp
    private void CheckTokenExists(string symbol)
    {
        var empty = new TokenInfo();
        // check old token
        var existing = GetTokenInfo(symbol);
        Assert(existing == null || existing.Equals(empty), "Token already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L407-415)
```csharp
        var tokenInfo = State.TokenInfos[symbolOrAlias];
        if (tokenInfo != null) return tokenInfo;
        var actualTokenSymbol = State.SymbolAliasMap[symbolOrAlias];
        if (!string.IsNullOrEmpty(actualTokenSymbol))
        {
            tokenInfo = State.TokenInfos[actualTokenSymbol];
        }

        return tokenInfo;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
    }
```
