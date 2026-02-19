### Title
Symbol Alias Shadowing via Direct Token Registration

### Summary
The `SetSymbolAlias` function fails to validate whether a proposed alias already exists as a direct token symbol in `State.TokenInfos`. An attacker can exploit this by registering a malicious token with a simple symbol (e.g., "ABC") before an NFT collection owner sets that same symbol as an alias. When both exist, `GetTokenInfo` prioritizes the direct token, causing users to interact with the attacker's token instead of the intended NFT.

### Finding Description

The vulnerability exists in the `SetSymbolAlias` function where the only validation for alias uniqueness checks the `SymbolAliasMap`: [1](#0-0) 

This check does not verify whether `State.TokenInfos[input.Alias]` already contains a direct token with the same symbol. The `GetTokenInfo` function is designed to prioritize direct symbol lookups over alias resolution: [2](#0-1) 

At line 407-408, if a direct token exists at `State.TokenInfos[symbolOrAlias]`, it is returned immediately, and the alias mapping is never checked. This design creates an exploitable race condition.

The attack path works because:

1. Symbol validation allows simple symbols without dashes (e.g., "ABC"): [3](#0-2) 

2. Symbol type determination treats symbols without dashes as regular tokens: [4](#0-3) 

3. Token creation via seed NFT allows creating tokens with simple symbols: [5](#0-4) 

4. Alias rules require the alias to match the NFT collection prefix (the seed name): [6](#0-5) 

The `CheckTokenExists` validation only runs during token creation and uses `GetTokenInfo`, which would prevent creating a token if an alias already exists. However, there is no reverse check when setting aliases: [7](#0-6) 

### Impact Explanation

**Direct Financial Impact:**
- Users attempting to interact with NFT "ABC-123" via its intended alias "ABC" will unknowingly interact with the attacker's malicious token
- Transfers to the attacker's token result in permanent loss of funds
- Approvals granted to the attacker's token can be exploited to drain user balances

**Operational Impact:**
- The NFT collection's intended alias functionality becomes unusable
- DApps and marketplaces that rely on alias-based token lookups will operate on the wrong token
- The NFT collection owner loses the ability to provide user-friendly access to their NFT items

**Affected Parties:**
- End users who hold or want to interact with the NFT
- NFT collection owners who lose their brand identity
- DApp developers whose applications break due to token confusion
- The protocol's reputation due to user experience degradation

**Severity Justification:**
This is a Medium severity issue because it requires specific preconditions (attacker must obtain and burn a seed NFT) but has concrete financial impact. The vulnerability undermines the NFT alias system's core functionality and can lead to measurable fund losses.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Obtain a seed NFT (SEED-X) with `OwnedSymbol` matching the target alias (e.g., "ABC")
2. Create and burn the seed NFT to register a token with the simple symbol
3. Time the attack before the legitimate NFT owner sets their alias

**Attack Complexity:**
The attack is straightforward once the seed NFT is obtained:
- Single transaction to create the malicious token
- No special privileges required beyond seed NFT ownership
- No complex state manipulation needed

**Feasibility Conditions:**
- Seed NFTs are tradeable and can be purchased/acquired
- The cost is the seed NFT acquisition price plus transaction fees
- For high-value or popular symbols (common brand names), this investment may be economically rational
- Attacker can frontrun alias registration by monitoring NFT collection creation events

**Economic Rationality:**
- If the target NFT collection is valuable or widely used, victims may transfer significant value to the attacker's token
- The attack cost (seed NFT + gas) can be recovered from even a few mistaken transfers
- Attacker can also use the shadowing for phishing or brand impersonation

**Detection and Constraints:**
- The vulnerability window exists from when the NFT collection is created until the alias is set
- Monitoring blockchain events could detect the collision, but users may not notice until losses occur
- No automatic circuit breakers or validations exist to prevent the collision

**Probability Assessment:**
Medium likelihood - requires active attacker investment and timing, but is economically viable for valuable NFT collections and technically straightforward to execute.

### Recommendation

**Code-Level Mitigation:**

Add a validation check in `SetSymbolAlias` to ensure the proposed alias does not already exist as a direct token symbol:

```csharp
// In SetSymbolAlias function, after line 750:
Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");

// ADD THIS CHECK:
Assert(State.TokenInfos[input.Alias] == null || string.IsNullOrEmpty(State.TokenInfos[input.Alias].Symbol), 
    $"Cannot set alias {input.Alias} - a token with this symbol already exists.");
```

**Additional Invariant:**
- Enforce mutual exclusion: A symbol string cannot simultaneously exist in both `State.TokenInfos` (as a key with non-null/non-empty TokenInfo) and `State.SymbolAliasMap` (as a key)

**Test Cases:**
1. Attempt to set alias "ABC" when direct token "ABC" already exists → should fail
2. Attempt to create token "ABC" when alias "ABC" already exists → should fail (already works via `CheckTokenExists`)
3. Verify `GetTokenInfo` behavior when both direct token and alias exist (for regression testing of fix)
4. Cross-chain synchronization test: ensure alias collision prevention works for `CrossChainCreateToken`

### Proof of Concept

**Initial State:**
- SEED NFT collection "SEED-0" exists
- SEED NFT "SEED-123" exists with `OwnedSymbol="ABC"` and valid expiration
- Attacker owns "SEED-123"
- NFT collection "ABC-0" exists with owner Alice
- NFT item "ABC-123" has been created

**Attack Steps:**

1. **Attacker creates malicious token "ABC":**
   - Transaction: `TokenContract.Create({Symbol: "ABC", ...})`
   - Seed NFT "SEED-123" is validated and burned
   - Result: `State.TokenInfos["ABC"]` = attacker's token (malicious)

2. **Alice attempts to set alias for her NFT:**
   - Transaction: `TokenContract.SetSymbolAlias({Symbol: "ABC-123", Alias: "ABC"})`
   - Validation at line 750 checks only `State.SymbolAliasMap["ABC"] == null` ✓ passes
   - Result: `State.SymbolAliasMap["ABC"]` = "ABC-123"

3. **Collision State Achieved:**
   - `State.TokenInfos["ABC"]` = attacker's malicious token
   - `State.SymbolAliasMap["ABC"]` = "ABC-123" (Alice's NFT)

4. **Victim Bob attempts to interact with Alice's NFT via alias:**
   - Transaction: `TokenContract.Transfer({Symbol: "ABC", Amount: 1000, To: AliceAddress})`
   - `GetTokenInfo("ABC")` executes:
     - Line 407: Returns `State.TokenInfos["ABC"]` (attacker's token)
     - Never checks `SymbolAliasMap`
   - Result: Bob transfers 1000 of attacker's token instead of Alice's NFT

**Expected vs Actual:**
- **Expected:** `GetTokenInfo("ABC")` should return Alice's NFT "ABC-123" 
- **Actual:** `GetTokenInfo("ABC")` returns attacker's malicious token "ABC"

**Success Condition:**
The attack succeeds when `GetTokenInfo("ABC")` returns the attacker's token (verified by checking `tokenInfo.Symbol == "ABC"` and `tokenInfo.Issuer == attackerAddress`) instead of resolving to "ABC-123".

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-65)
```csharp
            if (!IsAddressInCreateWhiteList(Context.Sender) &&
                input.Symbol != TokenContractConstants.SeedCollectionSymbol)
            {
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L750-750)
```csharp
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L847-851)
```csharp
        // Current Rule: Alias must be the seed name.
        var parts = collectionSymbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(parts.Length == 2, $"Incorrect collection symbol: {collectionSymbol}.");
        Assert(parts.Last() == TokenContractConstants.CollectionSymbolSuffix, "Incorrect collection symbol suffix.");
        Assert(alias == parts.First(), $"Alias for an item of {collectionSymbol} cannot be {alias}.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L18-21)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L295-303)
```csharp
    private void CheckTokenExists(string symbol)
    {
        var empty = new TokenInfo();
        // check old token
        var existing = GetTokenInfo(symbol);
        Assert(existing == null || existing.Equals(empty), "Token already exists.");
        // check new token
        Assert(!State.InsensitiveTokenExisting[symbol.ToUpper()], "Token already exists.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L405-416)
```csharp
    private TokenInfo GetTokenInfo(string symbolOrAlias)
    {
        var tokenInfo = State.TokenInfos[symbolOrAlias];
        if (tokenInfo != null) return tokenInfo;
        var actualTokenSymbol = State.SymbolAliasMap[symbolOrAlias];
        if (!string.IsNullOrEmpty(actualTokenSymbol))
        {
            tokenInfo = State.TokenInfos[actualTokenSymbol];
        }

        return tokenInfo;
    }
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
