# Audit Report

## Title
Case-Insensitive Token Uniqueness Check Bypassed in Cross-Chain Token Creation

## Summary
The `CrossChainCreateToken` function performs only a case-sensitive token existence check, while the normal `Create` flow enforces case-insensitive uniqueness. This inconsistency allows tokens with symbols differing only in case (e.g., "ABC" and "abc") to coexist on the same chain, causing balance fragmentation, operational confusion, and SymbolSeedMap conflicts.

## Finding Description

**Root Cause - Case-Sensitive vs Case-Insensitive Checks:**

The normal token creation flow calls `CheckTokenExists`, which enforces case-insensitive uniqueness through `State.InsensitiveTokenExisting[symbol.ToUpper()]`. [1](#0-0) 

When a token is registered, both the case-sensitive `TokenInfos` map and the case-insensitive tracking state are updated. [2](#0-1) 

However, `CrossChainCreateToken` only checks `State.TokenInfos[tokenInfo.Symbol] == null`, which is case-sensitive, completely bypassing the case-insensitive validation. [3](#0-2) 

**Storage Implementation:**

All token-related state maps use the exact symbol string as the key without normalization. [4](#0-3) 

This means "ABC" and "abc" are stored as completely separate keys, maintaining distinct balances and token information.

**SymbolSeedMap Conflict:**

The SymbolSeedMap consistently uses `.ToUpper()` for both writes and reads. [5](#0-4) [6](#0-5) [7](#0-6) 

If both "ABC" and "abc" tokens exist, they conflict when used in SEED NFT operations since both normalize to the same uppercase key "ABC".

## Impact Explanation

**Critical Protocol Invariant Violated:**
The protocol's fundamental assumption that token symbols are case-insensitively unique is broken. This creates multiple concrete harms:

1. **Balance Fragmentation**: User balances are split across case variants (e.g., `State.Balances[user]["ABC"]` vs `State.Balances[user]["abc"]`), making total holdings opaque and potentially causing funds to appear "lost" to users and contracts expecting consolidated balances.

2. **SymbolSeedMap Corruption**: When both "ABC" and "abc" are used in NFT creation flows, they share `SymbolSeedMap["ABC"]`, causing one to overwrite the other's SEED mapping. This breaks the one-time-use SEED NFT enforcement and could allow unauthorized token creation or prevent legitimate token creation.

3. **Cross-Chain State Divergence**: Parent and child chains can have different token uniqueness states - parent chain with "ABC" only, child chain with both "ABC" and "abc" - violating cross-chain consistency guarantees.

4. **Contract Integration Failures**: Smart contracts and dApps assuming case-insensitive symbol resolution will interact with incorrect token variants, causing failed transactions, misrouted funds, and broken allowances.

**Severity: Medium** - No direct fund theft, but significant operational disruption, state integrity violation, and potential for user fund confusion. The vulnerability requires cross-chain conditions but has measurable impact on token accounting and NFT creation mechanisms.

## Likelihood Explanation

**Feasibility: Medium**

**Preconditions:**
1. Token with specific casing exists on child chain (e.g., "abc" created via normal `Create`)
2. Token with different casing exists on parent chain (e.g., "ABC")
3. Cross-chain registration initiated from parent to child

**Execution Path:**
1. Parent chain has token "ABC" (created normally)
2. Attacker creates token "abc" on child chain via normal `Create` flow
3. User initiates legitimate cross-chain registration from parent to child
4. `CrossChainCreateToken` checks `State.TokenInfos["ABC"] == null` - passes (only "abc" exists)
5. `RegisterTokenInfo` called for "ABC"
6. Both "ABC" and "abc" now coexist on child chain

**Accessibility:**
`CrossChainCreateToken` is a public method callable by anyone with valid cross-chain merkle proof. [8](#0-7) 

**Complexity:** Medium - requires cross-chain operation setup but no privileged access. Attacker only needs to time token creation on child chain before cross-chain sync occurs, which is a race condition in normal protocol operations.

**Detection:** Low - duplicate tokens are visible in contract state but require explicit case-sensitive queries to detect. Most UIs and explorers would normalize symbols, masking the issue.

## Recommendation

**Fix:** Add case-insensitive existence check in `CrossChainCreateToken` before registering the token.

Modify `CrossChainCreateToken` to call `CheckTokenExists` or add an explicit case-insensitive check:

```csharp
if (State.TokenInfos[tokenInfo.Symbol] == null)
{
    // Add case-insensitive check before registration
    Assert(!State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()], 
        "Token with same symbol (case-insensitive) already exists.");
    
    RegisterTokenInfo(tokenInfo);
    // ... rest of the logic
}
```

Alternatively, refactor to reuse the existing `CheckTokenExists` helper method before registration to maintain consistency with the normal creation flow.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task CrossChainCreateToken_Bypasses_CaseInsensitive_Check()
{
    // Setup: Child chain creates token "abc" via normal flow
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "abc",
        TokenName = "Test Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true
    });
    
    // Verify "abc" exists and case-insensitive protection works
    var result = await TokenContractStub.Create.SendWithExceptionAsync(new CreateInput
    {
        Symbol = "ABC", // Different case
        TokenName = "Test Token 2",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true
    });
    result.TransactionResult.Error.ShouldContain("Token already exists");
    
    // Exploit: Use CrossChainCreateToken to create "ABC" on child chain
    // Simulate parent chain having token "ABC"
    var validateInput = new ValidateTokenInfoExistsInput
    {
        Symbol = "ABC",
        TokenName = "Parent Token",
        TotalSupply = 2000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true
    };
    
    // Create cross-chain proof (merkle path and transaction bytes)
    var transaction = GenerateValidateTransaction(validateInput);
    var merklePath = GenerateMerklePath(transaction);
    
    // Execute CrossChainCreateToken - bypasses case-insensitive check
    await TokenContractStub.CrossChainCreateToken.SendAsync(new CrossChainCreateTokenInput
    {
        FromChainId = ParentChainId,
        ParentChainHeight = 100,
        TransactionBytes = transaction.ToByteString(),
        MerklePath = merklePath
    });
    
    // Verify: Both "abc" and "ABC" now exist as separate tokens
    var tokenAbc = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "abc" });
    var tokenABC = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "ABC" });
    
    tokenAbc.Symbol.ShouldBe("abc");
    tokenABC.Symbol.ShouldBe("ABC");
    
    // Demonstrate SymbolSeedMap conflict
    // Both will map to State.SymbolSeedMap["ABC"], causing overwrite
}
```

**Notes:**
- This vulnerability exists in the production MultiToken contract and affects all AElf chains using cross-chain token registration
- The issue is particularly problematic for NFT SEED tokens where SymbolSeedMap collisions break the one-time-use enforcement
- Exploitation requires timing but no special privileges beyond normal cross-chain operations

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L59-59)
```csharp
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L478-478)
```csharp
    public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L506-508)
```csharp
        if (State.TokenInfos[tokenInfo.Symbol] == null)
        {
            RegisterTokenInfo(tokenInfo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L16-20)
```csharp
    public MappedState<string, TokenInfo> TokenInfos { get; set; }
    public MappedState<string, bool> InsensitiveTokenExisting { get; set; }
    public MappedState<string, string> SymbolSeedMap { get; set; }
    public MappedState<Address, string, long> Balances { get; set; }
    public MappedState<Address, Address, string, long> Allowances { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L51-51)
```csharp
            State.SymbolSeedMap[ownedSymbol.ToUpper()] = input.Symbol;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L59-59)
```csharp
        var oldSymbolSeed = State.SymbolSeedMap[ownedSymbol.ToUpper()];
```
