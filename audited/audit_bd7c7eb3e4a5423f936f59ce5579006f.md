# Audit Report

## Title
Case-Insensitive Token Uniqueness Bypass via CrossChainCreateToken

## Summary
The `CrossChainCreateToken` function implements only case-sensitive token existence checking, while normal token creation enforces case-insensitive uniqueness. This inconsistency allows attackers to create duplicate tokens with different casing (e.g., "ABC-0" and "abc-0") through cross-chain operations, violating the protocol's fundamental token uniqueness invariant.

## Finding Description

The MultiToken contract establishes case-insensitive token uniqueness through the `State.InsensitiveTokenExisting` mapping, which stores symbols in uppercase. [1](#0-0) 

Normal token creation via `CreateToken` properly enforces this invariant by calling `CheckTokenExists`, which validates both case-sensitive and case-insensitive uniqueness. [2](#0-1) 

The `CheckTokenExists` function performs dual validation: [3](#0-2) 

However, `CrossChainCreateToken` bypasses this protection by using only a case-sensitive check that verifies `State.TokenInfos[tokenInfo.Symbol] == null` without checking `State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()]`. [4](#0-3) 

When the check passes, `RegisterTokenInfo` is called, which creates a separate entry in `State.TokenInfos` with the different casing while setting the same uppercase key in `State.InsensitiveTokenExisting`. [5](#0-4) 

This results in two distinct tokens ("ABC-0" and "abc-0") with separate balance and allowance mappings, as these use the symbol string as the key. [6](#0-5) 

Since `GetTokenInfo` performs case-sensitive lookups without normalization, users querying for "ABC-0" will not find "abc-0" and vice versa. [7](#0-6) 

## Impact Explanation

**Protocol Invariant Violation**: The fundamental guarantee that token symbols are case-insensitively unique is broken. This is a core protocol invariant that all token operations depend on.

**State Fragmentation**: If token "ABC-0" exists, an attacker can create "abc-0" as a completely separate token with independent:
- Token information (issuer, owner, supply, decimals)
- Balance mappings for all addresses
- Allowance mappings between addresses
- Lock whitelist configurations

**User Confusion**: Users and dApps expecting case-insensitive token identification will interact with the wrong token, as token lookups use exact case matching.

**NFT Collection Fragmentation**: For NFT collections, this creates parallel namespaces where "ABC-0" and "abc-0" can each issue their own items (ABC-1, ABC-2 vs abc-1, abc-2), fragmenting what should be a unified collection.

**Cross-Chain Consistency**: Multi-chain deployments will face inconsistencies when case variants exist on different chains, breaking cross-chain transfer assumptions.

## Likelihood Explanation

**Entry Point**: `CrossChainCreateToken` is a public method accessible to any caller with valid cross-chain proof. [8](#0-7) 

**Prerequisites**:
1. Token contract must be registered in `State.CrossChainTransferWhiteList` for the source chain - this is standard in multi-chain setups [9](#0-8) 
2. Valid merkle proof and cross-chain verification required [10](#0-9) 
3. Attacker must be able to create token on source chain

**Feasibility**: In legitimate multi-chain environments where parent/side chains are properly registered (normal operation), the attack is straightforward once prerequisites are met. The attacker creates a case-variant token on Chain A, then submits `CrossChainCreateToken` on Chain B with valid proof.

**Assessment**: MEDIUM likelihood - feasible in multi-chain deployments where chains are legitimately connected and source chain allows token creation.

## Recommendation

Add case-insensitive uniqueness validation to `CrossChainCreateToken` before calling `RegisterTokenInfo`. The fix should mirror the validation in normal token creation:

```csharp
if (State.TokenInfos[tokenInfo.Symbol] == null)
{
    // Add case-insensitive check
    Assert(!State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()], 
           "Token already exists.");
    
    RegisterTokenInfo(tokenInfo);
    // ... rest of the code
}
```

Alternatively, extract the complete validation logic from `CheckTokenExists` into a reusable method and call it from both `CreateToken` and `CrossChainCreateToken`.

## Proof of Concept

```csharp
// Proof of Concept Test
[Fact]
public async Task CrossChainCreateToken_CaseInsensitiveDuplicate_ShouldFail()
{
    // Setup: Create token "ABC-0" on the chain
    await CreateTokenAsync("ABC-0", "Test Token", 1000000);
    
    // Simulate cross-chain creation of "abc-0" from another chain
    var validateInput = new ValidateTokenInfoExistsInput
    {
        Symbol = "abc-0", // lowercase variant
        TokenName = "Test Token Lower",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true,
        IssueChainId = ChainHelper.GetChainId(1)
    };
    
    var txBytes = GenerateCrossChainTransaction(validateInput);
    var merklePath = GenerateMerklePath(txBytes);
    
    // Attempt to create case variant via cross-chain
    var result = await TokenContractStub.CrossChainCreateToken.SendAsync(
        new CrossChainCreateTokenInput
        {
            FromChainId = ChainHelper.GetChainId(1),
            TransactionBytes = txBytes,
            MerklePath = merklePath,
            ParentChainHeight = 100
        });
    
    // Vulnerability: This succeeds when it should fail
    // Both "ABC-0" and "abc-0" now exist as separate tokens
    var tokenABC = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "ABC-0" });
    var tokenabc = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "abc-0" });
    
    // Assert both tokens exist (demonstrates the vulnerability)
    Assert.NotNull(tokenABC);
    Assert.NotNull(tokenabc);
    Assert.NotEqual(tokenABC.TokenName, tokenabc.TokenName);
}
```

**Notes:**
- This vulnerability requires a multi-chain environment with registered cross-chain token contracts
- The symbol validation regex `^[a-zA-Z0-9]+(-[0-9]+)?$` permits both uppercase and lowercase letters, enabling the exploit [11](#0-10) 
- The issue stems from inconsistent validation between normal and cross-chain token creation flows
- Fix should be applied before deployment to any multi-chain environment

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L17-17)
```csharp
    public MappedState<string, bool> InsensitiveTokenExisting { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L19-20)
```csharp
    public MappedState<Address, string, long> Balances { get; set; }
    public MappedState<Address, Address, string, long> Allowances { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L87-88)
```csharp
        CheckTokenExists(tokenInfo.Symbol);
        RegisterTokenInfo(tokenInfo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L478-479)
```csharp
    public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
    {
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L480-482)
```csharp
        var tokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        Assert(tokenContractAddress != null,
            $"Token contract address of chain {ChainHelper.ConvertChainIdToBase58(input.FromChainId)} not registered.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L486-488)
```csharp
        AssertCrossChainTransaction(originalTransaction, tokenContractAddress, nameof(ValidateTokenInfoExists));
        var originalTransactionId = originalTransaction.GetHash();
        CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L506-508)
```csharp
        if (State.TokenInfos[tokenInfo.Symbol] == null)
        {
            RegisterTokenInfo(tokenInfo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L18-21)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$");
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
