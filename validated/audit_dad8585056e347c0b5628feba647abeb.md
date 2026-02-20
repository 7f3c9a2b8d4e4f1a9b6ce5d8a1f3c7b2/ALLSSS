# Audit Report

## Title
Symbol Alias Shadowing via Direct Token Registration

## Summary
The `SetSymbolAlias` function only validates that an alias doesn't exist in `SymbolAliasMap` without checking if a direct token with that symbol already exists in `State.TokenInfos`. This asymmetric validation allows an attacker to register a malicious token with a simple symbol before an NFT collection owner sets that symbol as an alias. Since `GetTokenInfo` prioritizes direct token lookups over alias resolution, all subsequent operations will interact with the attacker's token instead of the intended NFT.

## Finding Description

The vulnerability arises from inconsistent validation between token creation and alias registration, combined with lookup priority rules that favor direct tokens.

**Asymmetric Validation Pattern:**

When creating a token, `CheckTokenExists` uses `GetTokenInfo` to verify the symbol doesn't exist. [1](#0-0)  This helper method checks both `State.TokenInfos` (direct tokens) AND `State.SymbolAliasMap` (aliases), preventing token creation if either exists. [2](#0-1) 

However, `SetSymbolAlias` only validates that the alias doesn't exist in `SymbolAliasMap`. [3](#0-2)  It never checks `State.TokenInfos` to see if a direct token with that symbol already exists.

**Lookup Priority Exploitation:**

The `GetTokenInfo` helper prioritizes direct token lookups. [4](#0-3)  When both a direct token and an alias share the same symbol, the direct token is always returned, effectively shadowing the alias.

**Attack Sequence:**

1. Attacker creates a SEED NFT with `OwnedSymbol="ABC"` (simple symbols without dashes are valid per symbol validation rules [5](#0-4)  and are classified as regular tokens [6](#0-5) )

2. Attacker calls `Create()` with `Symbol="ABC"`, which verifies SEED NFT ownership [7](#0-6)  and burns the SEED [8](#0-7) 

3. `CheckTokenExists` validates no token or alias "ABC" exists and succeeds [9](#0-8) 

4. Token "ABC" is registered in `State.TokenInfos["ABC"]`

5. NFT collection owner later creates collection "ABC-0" and calls `SetSymbolAlias(symbol="ABC-1", alias="ABC")` to set user-friendly alias

6. `SetSymbolAlias` validation passes because `State.SymbolAliasMap["ABC"]` is null [3](#0-2) 

7. Alias is registered in `State.SymbolAliasMap["ABC"]` mapping to NFT item [10](#0-9) 

8. Both now coexist: `State.TokenInfos["ABC"]` (attacker's token) and `State.SymbolAliasMap["ABC"]` (NFT alias)

9. All calls to `GetTokenInfo("ABC")` return the attacker's token due to direct lookup priority, never reaching alias resolution

## Impact Explanation

**Direct Financial Loss:**
Users and applications intending to interact with the NFT via its alias will unknowingly transact with the attacker's malicious token. This causes:
- Misdirected transfers that permanently lock user funds in an unrelated token contract
- Approvals granted to the wrong token that can be exploited by the attacker
- Failed NFT marketplace operations as users operate on an incompatible token type

**Protocol Invariant Violation:**
The alias system's core guarantee—that aliases uniquely and reliably resolve to their intended NFT collections—is permanently broken. The NFT owner cannot recover the alias as the direct token will always take precedence in lookups.

**Ecosystem-Wide Impact:**
DApps, wallets, and marketplaces relying on alias-based token resolution will systematically malfunction, directing user interactions to the wrong token. This undermines user trust in the NFT alias feature and causes confusion about which token is legitimate.

**Severity: Medium**
While the attack requires acquiring a SEED NFT (economic cost) and precise timing, once executed it causes concrete financial harm to users and permanent functional degradation of the alias system with no recovery mechanism.

## Likelihood Explanation

**Attacker Prerequisites:**
- Acquire a SEED NFT with `OwnedSymbol` matching the target alias (SEED NFTs are tradeable on the market)
- Execute token creation before the NFT owner registers their alias
- Cost is bounded by SEED NFT market price plus gas fees

**Attack Complexity: Low**
After obtaining the SEED NFT, the attack requires only a single `Create()` transaction. No special permissions, complex state manipulation, or multi-step coordination is needed. The vulnerability is deterministic and reproducible.

**Economic Viability:**
For popular NFT collections with simple, brandable symbols (e.g., "COOL", "RARE"), the attack ROI can justify SEED NFT acquisition through:
- Capturing misdirected user transfers
- Phishing via brand impersonation  
- Holding the symbol hostage for ransom

**Detection and Prevention:**
Attackers can monitor blockchain events to identify when valuable NFT collections are created, then frontrun the alias registration. Users discover the issue only after losing funds. No on-chain protections exist to prevent the collision.

**Probability: Medium**
The attack is technically straightforward and economically rational for high-value targets, with no protocol-level defenses to stop symbol squatting.

## Recommendation

Add validation in `SetSymbolAlias` to check if a direct token already exists:

```csharp
public override Empty SetSymbolAlias(SetSymbolAliasInput input)
{
    // ... existing chain and collection checks ...
    
    // For now, token alias can only be set once.
    Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");
    
    // ADD THIS CHECK:
    Assert(State.TokenInfos[input.Alias] == null, 
        $"Cannot set alias {input.Alias}: a direct token with this symbol already exists.");
    
    CheckTokenAlias(input.Alias, collectionSymbol);
    // ... rest of the method ...
}
```

This ensures bidirectional protection: tokens cannot shadow aliases, and aliases cannot shadow tokens.

## Proof of Concept

```csharp
[Fact]
public async Task SymbolAliasShadowing_Attack()
{
    // Setup: Attacker obtains SEED NFT for "ABC"
    var attackerSeed = await CreateSeedNFT("ABC");
    
    // Step 1: Attacker creates malicious token "ABC" using SEED
    var createResult = await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ABC",
        TokenName = "Malicious Token",
        TotalSupply = 1000000,
        Issuer = DefaultAddress,
        Decimals = 8,
        IsBurnable = true
    });
    createResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 2: Legitimate NFT owner creates collection "ABC-0"
    var nftSeed = await CreateSeedNFT("ABC-0");
    var nftCollectionResult = await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ABC-0",
        TokenName = "NFT Collection",
        TotalSupply = 0,
        Issuer = User1Address,
        Owner = User1Address
    });
    nftCollectionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: NFT owner creates item and sets alias "ABC"
    var nftItemResult = await User1TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ABC-1",
        TokenName = "NFT Item",
        TotalSupply = 1,
        Issuer = User1Address,
        Owner = User1Address
    });
    
    var aliasResult = await User1TokenContractStub.SetSymbolAlias.SendAsync(new SetSymbolAliasInput
    {
        Symbol = "ABC-1",
        Alias = "ABC"
    });
    aliasResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // SUCCEEDS - no validation!
    
    // Step 4: Verify shadowing - GetTokenInfo returns attacker's token
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "ABC" });
    tokenInfo.TokenName.ShouldBe("Malicious Token"); // Returns attacker's token, NOT NFT
    
    // User attempting to interact with NFT via alias will use wrong token
    // Transfers, approvals, etc. will go to attacker's malicious token
}
```

## Notes

This vulnerability exploits a fundamental asymmetry in validation logic. While `CheckTokenExists` provides comprehensive protection during token creation by checking both storage locations, `SetSymbolAlias` implements only partial validation by checking a single storage location. The combination of this validation gap with the deterministic lookup priority in `GetTokenInfo` creates a reliable attack vector for symbol squatting that permanently damages the utility of the NFT alias system.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L28-31)
```csharp
    private bool IsValidCreateSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L59-64)
```csharp
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L87-87)
```csharp
        CheckTokenExists(tokenInfo.Symbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L750-750)
```csharp
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L768-768)
```csharp
        State.SymbolAliasMap[input.Alias] = input.Symbol;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L11-11)
```csharp
        if (words.Length == 1) return SymbolType.Token;
```
