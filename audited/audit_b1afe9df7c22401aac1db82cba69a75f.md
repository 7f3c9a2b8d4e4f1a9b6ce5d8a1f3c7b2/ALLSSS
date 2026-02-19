### Title
Null Reference Exception in GetTokenAlias View Method Due to Missing Null Check

### Summary
The `GetTokenAlias` view method fails to validate that the NFT collection exists before accessing its TokenInfo properties, causing a NullReferenceException when called with regular token symbols or non-existent NFT collections. While `AssertNftCollectionExist` properly handles null cases, the `GetTokenAlias` method calls `ExtractAliasSetting` without null checking, leading to query failures.

### Finding Description

**Location:**
- `contract/AElf.Contracts.MultiToken/TokenContract_Views.cs`, lines 267-276 (GetTokenAlias)
- `contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs`, line 813 (ExtractAliasSetting)

**Root Cause:**

The `GetTokenAlias` method retrieves the NFT collection symbol and attempts to extract alias settings without validating whether the collection TokenInfo exists: [1](#0-0) 

The method calls `GetNftCollectionSymbol` which can return null for regular tokens or a collection symbol string for NFT items/collections: [2](#0-1) 

When `GetTokenInfo(collectionSymbol)` returns null (because the collection doesn't exist or collectionSymbol is null), `ExtractAliasSetting(tokenInfo)` is called without null validation: [3](#0-2) 

At line 813, `tokenInfo.ExternalInfo.Value.ContainsKey(...)` throws a NullReferenceException when tokenInfo is null.

**Why Existing Protections Fail:**

While `AssertNftCollectionExist` properly validates collection existence with explicit null checks: [4](#0-3) 

The `GetTokenAlias` view method bypasses this protection and directly calls methods that assume TokenInfo is non-null.

### Impact Explanation

**Operational Impact:**
- The `GetTokenAlias` RPC method (marked as `is_view = true`) becomes unusable for regular tokens and non-existent NFT collections
- Any dApp or frontend integration calling `GetTokenAlias` expecting graceful empty-string responses will encounter exceptions
- The method fails for legitimate queries like `GetTokenAlias("ELF")` or queries for NFT items whose collections haven't been created [5](#0-4) 

**Severity Justification:**
This is a **MEDIUM** severity issue because:
- It only affects a view method (no state modification or fund impact)
- It causes query failures but doesn't compromise token operations or balances
- However, it violates expected behavior (should return empty string, not crash)
- It can break dApp integrations that rely on this method

### Likelihood Explanation

**Exploitability:**
- **Reachable Entry Point**: `GetTokenAlias` is a public view method accessible via RPC
- **Attacker Capabilities**: Any user can call this method with arbitrary input
- **Attack Complexity**: Trivial - single RPC call with a regular token symbol
- **Preconditions**: None required

**Probability**: 100% reproducible with inputs like:
1. Regular token symbols (e.g., "ELF", "USDT")
2. Non-existent NFT collection symbols (e.g., "NONEXIST-0")
3. NFT item symbols whose collections don't exist (e.g., "NONEXIST-1")

### Recommendation

**Code-Level Mitigation:**

Add null validation in `GetTokenAlias` before calling `ExtractAliasSetting`:

```csharp
public override StringValue GetTokenAlias(StringValue input)
{
    var collectionSymbol = GetNftCollectionSymbol(input.Value, true);
    if (collectionSymbol == null)
    {
        return new StringValue { Value = string.Empty };
    }
    
    var tokenInfo = GetTokenInfo(collectionSymbol);
    if (tokenInfo == null)
    {
        return new StringValue { Value = string.Empty };
    }
    
    var (_, alias) = ExtractAliasSetting(tokenInfo);
    return new StringValue { Value = alias };
}
```

**Additional Hardening:**

Add defensive null check in `ExtractAliasSetting`:

```csharp
private KeyValuePair<string, string> ExtractAliasSetting(TokenInfo tokenInfo)
{
    if (tokenInfo == null || tokenInfo.ExternalInfo == null || 
        !tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.TokenAliasExternalInfoKey))
    {
        return new KeyValuePair<string, string>(string.Empty, string.Empty);
    }
    // ... rest of method
}
```

**Test Cases:**

Add tests verifying `GetTokenAlias` returns empty string for:
- Regular token symbols
- Non-existent NFT collections
- NFT items without collections [6](#0-5) 

### Proof of Concept

**Initial State:**
- MultiToken contract deployed
- Regular token "ELF" exists in State.TokenInfos
- No NFT collection "TEST-0" exists

**Exploitation Steps:**

1. Call `GetTokenAlias` with regular token symbol:
   ```
   Input: StringValue { Value = "ELF" }
   ```

2. Execution trace:
   - Line 269: `GetNftCollectionSymbol("ELF", true)` returns null (no hyphen separator)
   - Line 270: `GetTokenInfo(null)` returns null
   - Line 271: `ExtractAliasSetting(null)` called
   - Line 813: `null.ExternalInfo.Value.ContainsKey(...)` throws NullReferenceException

**Expected vs Actual:**
- **Expected**: Return `StringValue { Value = "" }` (empty string for non-NFT)
- **Actual**: Throws NullReferenceException, query fails

**Success Condition:**
Query returns exception instead of empty string, confirming the vulnerability.

### Notes

The original security question asks specifically about `AssertNftCollectionExist` which properly handles null cases. The vulnerability exists in `GetTokenAlias`, a less critical view method. Under normal contract operation, NFT items cannot exist without their collections due to validation in `CreateNFTInfo` and `CrossChainCreateToken`, but `GetTokenAlias` lacks defensive programming to handle edge cases gracefully.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L267-276)
```csharp
    public override StringValue GetTokenAlias(StringValue input)
    {
        var collectionSymbol = GetNftCollectionSymbol(input.Value, true);
        var tokenInfo = GetTokenInfo(collectionSymbol);
        var (_, alias) = ExtractAliasSetting(tokenInfo);
        return new StringValue
        {
            Value = alias
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L153-161)
```csharp
    private string GetNftCollectionSymbol(string inputSymbol, bool isAllowCollection = false)
    {
        var symbol = inputSymbol;
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        const int tokenSymbolLength = 1;
        if (words.Length == tokenSymbolLength) return null;
        Assert(words.Length == 2 && IsValidItemId(words[1]), "Invalid NFT Symbol Input");
        return symbol == $"{words[0]}-0" ? (isAllowCollection ? $"{words[0]}-0" : null) : $"{words[0]}-0";
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L163-170)
```csharp
    private TokenInfo AssertNftCollectionExist(string symbol)
    {
        var collectionSymbol = GetNftCollectionSymbol(symbol);
        if (collectionSymbol == null) return null;
        var collectionInfo = GetTokenInfo(collectionSymbol);
        Assert(collectionInfo != null, "NFT collection not exist");
        return collectionInfo;
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

**File:** protobuf/token_contract.proto (L241-243)
```text
    rpc GetTokenAlias (google.protobuf.StringValue) returns (google.protobuf.StringValue) {
        option (aelf.is_view) = true;
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenAliasTests.cs (L14-52)
```csharp
    public async Task SetTokenAlias_NFTCollection_Test()
    {
        var symbols = await CreateNftCollectionAndNft();
        await TokenContractStub.SetSymbolAlias.SendAsync(new SetSymbolAliasInput
        {
            Symbol = symbols[1],
            Alias = "TP"
        });

        {
            // Check TokenInfo of NFT Collection.
            var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
            {
                Symbol = symbols[0]
            });
            tokenInfo.ExternalInfo.Value.ContainsKey(TokenAliasExternalInfoKey);
            tokenInfo.ExternalInfo.Value[TokenAliasExternalInfoKey].ShouldBe("{\"TP-31175\":\"TP\"}");
        }

        {
            // Check TokenInfo of NFT Item.
            var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
            {
                Symbol = "TP"
            });
            tokenInfo.Symbol.ShouldBe(symbols[1]);
        }

        {
            // Check alias.
            var alias = await TokenContractStub.GetTokenAlias.CallAsync(new StringValue { Value = "TP-31175" });
            alias.Value.ShouldBe("TP");
        }

        {
            var alias = await TokenContractStub.GetSymbolByAlias.CallAsync(new StringValue { Value = "TP" });
            alias.Value.ShouldBe("TP-31175");
        }
    }
```
