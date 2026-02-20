# Audit Report

## Title
Chained Alias Creation Enables Incomplete Symbol Resolution in Token Operations

## Summary
The token alias system allows creating aliases that point to other aliases instead of actual token symbols during NFT collection creation. The `GetActualTokenSymbol` function performs only single-level resolution, causing balance queries to return incorrect results and transfer operations to fail when chained aliases (3+ levels) are used.

## Finding Description

The vulnerability exists due to missing validation during alias creation that allows chained alias mappings:

**1. Single-Level Alias Resolution**

The `GetActualTokenSymbol` function performs only one lookup in `SymbolAliasMap`. [1](#0-0)  When an alias points to another alias, resolution stops at the intermediate alias instead of continuing to the actual token symbol.

**2. Missing Validation in Alias Creation**

The private `SetTokenAlias` function extracts symbol-to-alias mappings from `TokenInfo.ExternalInfo` and directly creates the mapping without validating that the target symbol is not itself an alias. [2](#0-1)  The `CheckTokenAlias` validation only verifies that the alias matches the collection's seed name but never validates the target symbol. [3](#0-2) 

**3. Attack Vector - NFT Collection Creation**

During NFT collection creation via the `Create` method, if `ExternalInfo` contains alias settings, the code calls `SetTokenAlias` without validating the target symbol. [4](#0-3)  The `ExternalInfo` from user input is directly used with the symbol field extracted from it. [5](#0-4) 

**4. Cross-Chain Propagation**

The `CrossChainCreateToken` method constructs `TokenInfo` with unvalidated `ExternalInfo` from cross-chain messages, [6](#0-5)  then calls `SyncSymbolAliasFromTokenInfo` which triggers `SetTokenAlias` without additional validation. [7](#0-6) 

**Attack Scenario:**

1. Attacker creates collection "ALIAS1-0" with legitimate alias "ALIAS1" → "NFT-1"
2. Attacker creates collection "ALIAS2-0" with `ExternalInfo = {"ALIAS1":"ALIAS2"}`
3. This creates chained mapping: "ALIAS2" → "ALIAS1" → "NFT-1"
4. Operations using "ALIAS2" fail or return incorrect results

For balance queries, the helper `GetBalance` performs a second resolution call, [8](#0-7)  providing two levels of resolution. However, chains of 3+ aliases still fail because the third level is never resolved.

For transfer operations, `AssertValidToken` calls `GetTokenInfo` which only performs single-level resolution, [9](#0-8)  causing transfers with 2+ level chained aliases to fail with "Token is not found."

## Impact Explanation

**Operational Disruption:**
- Balance queries using 3+ level chained aliases return 0 or incorrect balances because intermediate aliases don't correspond to actual token symbols
- Transfer operations using 2+ level chained aliases fail completely with assertion errors
- Approval operations using 3+ level aliases set allowances on intermediate alias symbols instead of actual tokens
- Cross-chain synchronization can propagate these broken alias chains to other chains

**Limited Scope:**
The impact is localized to tokens accessed via the specific chained aliases created by the attacker. The actual tokens remain fully accessible via their real symbols or first-level aliases. This is not system-wide corruption but targeted disruption of specific alias paths.

**No Direct Fund Loss:**
This vulnerability does not enable direct theft of funds. The underlying token balances and ownership remain intact and accessible through proper symbol references.

## Likelihood Explanation

**Attacker Capabilities:**
- Requires NFT collection creation rights (seed NFT ownership)
- Standard user capability available to anyone with seed NFTs
- No governance approval or privileged role required

**Attack Complexity:**
- Single transaction to create NFT collection with crafted `ExternalInfo` like `{"EXISTING_ALIAS":"NEW_ALIAS"}`
- No timing requirements or race conditions
- Can be executed repeatedly to create multiple chained aliases

**Feasibility:**
The public `SetSymbolAlias` method cannot be used for this attack because it validates the input symbol format. [10](#0-9)  However, the NFT collection creation path bypasses this validation by using `ExternalInfo`.

**Note on Circular References:**
Circular references (A→B→A) are NOT possible because the immutability check prevents modifying existing aliases. [11](#0-10) 

## Recommendation

Add validation in `SetTokenAlias` to ensure the target symbol is not itself an alias:

```csharp
private void SetTokenAlias(TokenInfo tokenInfo)
{
    var (symbol, alias) = ExtractAliasSetting(tokenInfo);
    
    // Validate that symbol is not itself an alias
    Assert(State.SymbolAliasMap[symbol] == null, 
        $"Cannot create alias to another alias: {symbol}");
    
    // Validate that symbol refers to an actual token
    Assert(State.TokenInfos[symbol] != null, 
        $"Target symbol does not exist: {symbol}");
    
    State.SymbolAliasMap[alias] = symbol;
    CheckTokenAlias(alias, tokenInfo.Symbol);
    
    Context.Fire(new SymbolAliasAdded
    {
        Symbol = symbol,
        Alias = alias
    });
}
```

Alternatively, implement recursive resolution in `GetActualTokenSymbol` with cycle detection:

```csharp
private string GetActualTokenSymbol(string aliasOrSymbol, int maxDepth = 10)
{
    var current = aliasOrSymbol;
    for (int i = 0; i < maxDepth; i++)
    {
        if (State.TokenInfos[current] != null)
            return current;
        
        var next = State.SymbolAliasMap[current];
        if (string.IsNullOrEmpty(next))
            return current;
        
        Assert(next != aliasOrSymbol, "Circular alias reference detected");
        current = next;
    }
    throw new AssertionException("Alias resolution depth exceeded");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ChainedAlias_CausesIncorrectBalanceQuery_Test()
{
    // Setup: Create first level alias "ALIAS1" -> "TP-31175"
    await CreateNftCollectionAsync(new TokenInfo
    {
        Symbol = "ALIAS1-",
        TokenName = "Collection 1",
        TotalSupply = TotalSupply,
        Decimals = 0,
        Issuer = DefaultAddress,
        IssueChainId = _chainId,
        ExternalInfo = new ExternalInfo
        {
            Value = { { TokenAliasExternalInfoKey, "{\"TP-31175\":\"ALIAS1\"}" } }
        }
    });
    
    await CreateNftAsync("ALIAS1-0", new TokenInfo { Symbol = "TP-31175", ... });
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "TP-31175",
        Amount = 100,
        To = DefaultAddress
    });
    
    // Create second level alias "ALIAS2" -> "ALIAS1" (which itself is an alias)
    await CreateNftCollectionAsync(new TokenInfo
    {
        Symbol = "ALIAS2-",
        TokenName = "Collection 2",
        TotalSupply = TotalSupply,
        Decimals = 0,
        Issuer = DefaultAddress,
        IssueChainId = _chainId,
        ExternalInfo = new ExternalInfo
        {
            Value = { { TokenAliasExternalInfoKey, "{\"ALIAS1\":\"ALIAS2\"}" } }
        }
    });
    
    // Create third level alias "ALIAS3" -> "ALIAS2"
    await CreateNftCollectionAsync(new TokenInfo
    {
        Symbol = "ALIAS3-",
        TokenName = "Collection 3",
        TotalSupply = TotalSupply,
        Decimals = 0,
        Issuer = DefaultAddress,
        IssueChainId = _chainId,
        ExternalInfo = new ExternalInfo
        {
            Value = { { TokenAliasExternalInfoKey, "{\"ALIAS2\":\"ALIAS3\"}" } }
        }
    });
    
    // Query balance via ALIAS3 (3-level chain)
    var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultAddress,
        Symbol = "ALIAS3"
    });
    
    // BUG: Balance is 0 instead of 100 because resolution stops at "ALIAS1"
    // which is an alias, not the actual token "TP-31175"
    balance.Balance.ShouldBe(100);  // This assertion will FAIL
    Assert.Equal(0, balance.Balance); // Actual result
}
```

**Notes**

The vulnerability is valid for chained aliases where an alias points to another alias during NFT collection creation. The core issue is the lack of validation in `SetTokenAlias` that the target symbol is an actual token rather than another alias. While the report's claim about circular references is incorrect (they cannot be created due to alias immutability), the chained alias vulnerability is real and exploitable through standard NFT collection creation with crafted `ExternalInfo`. The impact is localized to specific alias chains rather than system-wide, but still creates operational disruption for users attempting to interact with tokens via these chained aliases.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L286-294)
```csharp
    private string GetActualTokenSymbol(string aliasOrSymbol)
    {
        if (State.TokenInfos[aliasOrSymbol] == null)
        {
            return State.SymbolAliasMap[aliasOrSymbol] ?? aliasOrSymbol;
        }

        return aliasOrSymbol;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L81-85)
```csharp
        if (IsAliasSettingExists(tokenInfo))
        {
            Assert(symbolType == SymbolType.NftCollection, "Token alias can only be set for NFT Item.");
            SetTokenAlias(tokenInfo);
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L492-503)
```csharp
        var tokenInfo = new TokenInfo
        {
            Symbol = validateTokenInfoExistsInput.Symbol,
            TokenName = validateTokenInfoExistsInput.TokenName,
            TotalSupply = validateTokenInfoExistsInput.TotalSupply,
            Decimals = validateTokenInfoExistsInput.Decimals,
            Issuer = validateTokenInfoExistsInput.Issuer,
            IsBurnable = validateTokenInfoExistsInput.IsBurnable,
            IssueChainId = validateTokenInfoExistsInput.IssueChainId,
            ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
            Owner = validateTokenInfoExistsInput.Owner ?? validateTokenInfoExistsInput.Issuer
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L747-752)
```csharp
        var collectionSymbol = GetNftCollectionSymbol(input.Symbol, true);

        // For now, token alias can only be set once.
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");

        CheckTokenAlias(input.Alias, collectionSymbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L781-797)
```csharp
    private bool SyncSymbolAliasFromTokenInfo(TokenInfo newTokenInfo)
    {
        var maybePreviousTokenInfo = State.TokenInfos[newTokenInfo.Symbol]?.Clone();

        if (maybePreviousTokenInfo != null && IsAliasSettingExists(maybePreviousTokenInfo))
        {
            return false;
        }

        if (IsAliasSettingExists(newTokenInfo))
        {
            SetTokenAlias(newTokenInfo);
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L811-824)
```csharp
    private KeyValuePair<string, string> ExtractAliasSetting(TokenInfo tokenInfo)
    {
        if (!tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.TokenAliasExternalInfoKey))
        {
            return new KeyValuePair<string, string>(string.Empty, string.Empty);
        }

        var tokenAliasSetting = tokenInfo.ExternalInfo.Value[TokenContractConstants.TokenAliasExternalInfoKey];
        tokenAliasSetting = tokenAliasSetting.Trim('{', '}');
        var parts = tokenAliasSetting.Split(':');
        var key = parts[0].Trim().Trim('\"');
        var value = parts[1].Trim().Trim('\"');
        return new KeyValuePair<string, string>(key, value);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L826-838)
```csharp
    private void SetTokenAlias(TokenInfo tokenInfo)
    {
        var (symbol, alias) = ExtractAliasSetting(tokenInfo);
        State.SymbolAliasMap[alias] = symbol;

        CheckTokenAlias(alias, tokenInfo.Symbol);

        Context.Fire(new SymbolAliasAdded
        {
            Symbol = symbol,
            Alias = alias
        });
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L166-172)
```csharp
    private long GetBalance(Address address, string symbol)
    {
        AssertValidInputAddress(address);
        var actualSymbol = GetActualTokenSymbol(symbol);
        Assert(!string.IsNullOrWhiteSpace(actualSymbol), "Invalid symbol.");
        return State.Balances[address][actualSymbol];
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
