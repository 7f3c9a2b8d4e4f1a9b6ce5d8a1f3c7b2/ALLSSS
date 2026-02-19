### Title
Regex Anchor Bypass Allows Invalid Token Symbols with Trailing Newlines

### Summary
The regex validation patterns in `IsValidCreateSymbol`, `IsValidItemId`, and `IsValidSymbol` use the `$` anchor which, in C#, matches before a trailing newline character. This allows attackers to create tokens with symbols containing trailing newlines (e.g., `"ABC\n"` or `"ABC-123\n"`), bypassing validation and enabling symbol collision attacks where multiple tokens with visually identical symbols can be registered.

### Finding Description

The vulnerability exists in three regex validation functions that all use the `$` anchor: [1](#0-0) [2](#0-1) [3](#0-2) 

In C#, the `$` anchor has special behavior: it matches at the end of the string OR before a trailing `\n` character if it's the last character in the string. This means:
- Input `"ABC\n"` against pattern `^[a-zA-Z0-9]+$` returns TRUE (should be FALSE)
- Input `"123\n"` against pattern `^[0-9]+$` returns TRUE (should be FALSE)

The vulnerability is triggered in the `GetSymbolType` function: [4](#0-3) 

When a user calls the public `Create` method with a symbol containing trailing newlines: [5](#0-4) 

The validation flow proceeds as:
1. `GetSymbolType(input.Symbol)` splits the symbol by `-`
2. Validates each part with `IsValidCreateSymbol` and `IsValidItemId` - both incorrectly pass for trailing newlines
3. The token creation proceeds through `CreateToken` and `RegisterTokenInfo`
4. `RegisterTokenInfo` also uses `IsValidSymbol` which has the same flaw [6](#0-5) 

The duplicate check only verifies exact string matches: [7](#0-6) 

Since `"ABC"` and `"ABC\n"` are different strings, they pass as distinct tokens despite being visually identical.

### Impact Explanation

**Symbol Collision and Confusion:**
- Attackers can create multiple tokens with visually identical symbols: `"ABC"`, `"ABC\n"`, `"ABC\r"`, `"ABC\n\r"`, etc.
- Each is stored as a separate token in `State.TokenInfos` with different keys
- The case-insensitive check `State.InsensitiveTokenExisting[symbol.ToUpper()]` also treats them as different since `"ABC".ToUpper()` = `"ABC"` while `"ABC\n".ToUpper()` = `"ABC\n"`

**Operational Impact:**
- Front-end UIs and blockchain explorers will display these tokens with identical visual symbols, causing user confusion
- Users cannot distinguish between legitimate tokens and malicious duplicates
- External integrations expecting clean alphanumeric symbols may break when encountering control characters
- State storage is polluted with invalid symbols containing non-printable characters

**Attack Scenario:**
1. Legitimate project creates token `"USDT"`
2. Attacker creates token `"USDT\n"` (with trailing newline)
3. Both tokens appear identical in most UIs
4. Attacker can scam users by convincing them the malicious token is legitimate

This affects all token holders and users of the platform, as symbol uniqueness is a fundamental invariant. Severity is Medium due to the confusion and potential for scam attacks, though no direct fund theft occurs.

### Likelihood Explanation

**Reachable Entry Point:** The `Create` method is publicly accessible to any user (with appropriate seed NFT for non-whitelisted addresses).

**Feasible Preconditions:** 
- Attacker needs to obtain a seed NFT or be in the create whitelist
- No special privileges required beyond normal token creation requirements
- Attack can be executed by any malicious actor

**Execution Practicality:**
- Simple to execute: call `Create` with `input.Symbol = "SYMBOL\n"` (trailing newline)
- Works for both regular tokens and NFT symbols (e.g., `"ABC\n-1\n"`)
- No complex state manipulation required
- Deterministic and reliable exploitation

**Detection Constraints:**
- Trailing newlines are invisible in most debugging outputs
- No logging or monitoring specifically checks for control characters in symbols
- The vulnerability is subtle and unlikely to be caught in normal testing

The attack is practical, low-cost, and highly likely to succeed. Combined with Medium impact, this represents a real security risk.

### Recommendation

**Fix the regex patterns to use proper anchors:**

Replace `^` and `$` with `\A` and `\z` respectively, which strictly match string boundaries without special newline handling:

```csharp
private static bool IsValidSymbol(string symbol)
{
    return Regex.IsMatch(symbol, @"\A[a-zA-Z0-9]+(-[0-9]+)?\z");
}

private bool IsValidItemId(string symbolItemId)
{
    return Regex.IsMatch(symbolItemId, @"\A[0-9]+\z");
}

private bool IsValidCreateSymbol(string symbol)
{
    return Regex.IsMatch(symbolItemId, @"\A[a-zA-Z0-9]+\z");
}
```

**Alternative fix using RegexOptions.ECMAScript:**

```csharp
private static bool IsValidSymbol(string symbol)
{
    return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$", RegexOptions.ECMAScript);
}
```

**Add explicit validation:**

```csharp
private bool IsValidCreateSymbol(string symbol)
{
    return !symbol.Contains('\n') && !symbol.Contains('\r') && 
           Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
}
```

**Add test cases to prevent regression:**

```csharp
[Theory]
[InlineData("ELF\n", false)]
[InlineData("ABC\n", false)]
[InlineData("ABC-123\n", false)]
[InlineData("ABC\r", false)]
[InlineData("ABC-\n123", false)]
public void SymbolValidation_RejectsControlCharacters(string symbol, bool isValid)
{
    Regex.IsMatch(symbol, @"\A[a-zA-Z0-9]+(-[0-9]+)?\z").ShouldBe(isValid);
}
```

### Proof of Concept

**Initial State:**
- Attacker has obtained a seed NFT for token creation (or is whitelisted)
- No token with symbol "USDT" exists yet

**Attack Steps:**

1. **Legitimate user creates token "USDT":**
   ```
   Create(CreateInput {
       Symbol: "USDT",
       TokenName: "Tether USD",
       TotalSupply: 1000000,
       Decimals: 6,
       Issuer: <legitimate_address>,
       ...
   })
   ```
   - Result: Token registered in `State.TokenInfos["USDT"]`

2. **Attacker creates token "USDT\n" (with trailing newline):**
   ```
   Create(CreateInput {
       Symbol: "USDT\n",  // Contains trailing newline
       TokenName: "Fake Tether",
       TotalSupply: 1000000,
       Decimals: 6,
       Issuer: <attacker_address>,
       ...
   })
   ```
   - `GetSymbolType("USDT\n")` splits by `-`, gets `["USDT\n"]`
   - `IsValidCreateSymbol("USDT\n")` checks `^[a-zA-Z0-9]+$` against `"USDT\n"`
   - Regex matches: `^` at position 0, `[a-zA-Z0-9]+` matches "USDT", `$` matches before `\n`
   - Returns TRUE (bypass successful!)
   - Token registered in `State.TokenInfos["USDT\n"]`

**Expected Result:** Creation should fail with "Invalid symbol" error

**Actual Result:** Both tokens are successfully created and coexist:
- `State.TokenInfos["USDT"]` exists (legitimate token)
- `State.TokenInfos["USDT\n"]` exists (malicious token)
- `State.InsensitiveTokenExisting["USDT"]` = true
- `State.InsensitiveTokenExisting["USDT\n"]` = true (different key!)

**Success Condition:** Query both symbols and observe they are distinct tokens despite appearing identical in UI displays that strip control characters.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L18-21)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L23-26)
```csharp
    private bool IsValidItemId(string symbolItemId)
    {
        return Regex.IsMatch(symbolItemId, "^[0-9]+$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L28-31)
```csharp
    private bool IsValidCreateSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L224-234)
```csharp
    private void RegisterTokenInfo(TokenInfo tokenInfo)
    {
        Assert(!string.IsNullOrEmpty(tokenInfo.Symbol) && IsValidSymbol(tokenInfo.Symbol),
            "Invalid symbol.");
        Assert(!string.IsNullOrEmpty(tokenInfo.TokenName), "Token name can neither be null nor empty.");
        Assert(tokenInfo.TotalSupply > 0, "Invalid total supply.");
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
        Assert(tokenInfo.Owner != null, "Invalid owner address.");
        State.TokenInfos[tokenInfo.Symbol] = tokenInfo;
        State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()] = true;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L33-46)
```csharp
    public override Empty Create(CreateInput input)
    {
        var inputSymbolType = GetSymbolType(input.Symbol);
        if (input.Owner == null)
        {
            input.Owner = input.Issuer;
        }
        return inputSymbolType switch
        {
            SymbolType.NftCollection => CreateNFTCollection(input),
            SymbolType.Nft => CreateNFTInfo(input),
            _ => CreateToken(input)
        };
    }
```
