# Audit Report

## Title
Case-Insensitive Token Uniqueness Bypass via CrossChainCreateToken

## Summary
The `CrossChainCreateToken` method bypasses the protocol's case-insensitive token uniqueness enforcement by performing only a case-sensitive existence check before registering tokens. This allows an attacker controlling a registered side-chain to create duplicate tokens differing only in case (e.g., "token" when "TOKEN" exists), violating the fundamental design invariant enforced by `State.InsensitiveTokenExisting`.

## Finding Description

The AElf MultiToken contract enforces case-insensitive token uniqueness through `State.InsensitiveTokenExisting`, which stores uppercased symbols to prevent tokens differing only in case. [1](#0-0) 

**Secure Path:**
The standard `CreateToken` method properly enforces this invariant by calling `CheckTokenExists` before registration. [2](#0-1) 

The `CheckTokenExists` method validates case-insensitive uniqueness by asserting the uppercased symbol does not exist in `State.InsensitiveTokenExisting`. [3](#0-2) 

**Vulnerable Path:**
The `CrossChainCreateToken` method bypasses this validation. After cross-chain verification, it calls `AssertNftCollectionExist` which returns `null` for non-NFT tokens, providing no validation. [4](#0-3) 

It then performs only a case-sensitive check before calling `RegisterTokenInfo`. [5](#0-4) 

**Root Cause:**
The check `if (State.TokenInfos[tokenInfo.Symbol] == null)` is insufficient because `State.TokenInfos` uses case-sensitive keys. If "TOKEN" exists, checking `State.TokenInfos["token"]` returns `null`, allowing duplicate registration. The `RegisterTokenInfo` method unconditionally sets both states without validation. [6](#0-5) 

**Attack Scenario:**
1. Token "TOKEN" legitimately exists on destination chain
2. Attacker controls a registered side-chain (via Parliament approval)
3. Attacker creates "token" (lowercase) on their side-chain
4. Attacker calls `CrossChainCreateToken` with valid merkle proofs
5. Line 506 check passes (case-sensitive: `State.TokenInfos["token"]` is `null`)
6. `RegisterTokenInfo` creates separate `State.TokenInfos["token"]` entry
7. Both "TOKEN" and "token" coexist with independent balances and supplies

## Impact Explanation

This vulnerability violates the protocol's fundamental case-insensitive token uniqueness invariant. The impact includes:

1. **Token Impersonation**: Attackers can create "elf" to impersonate "ELF", or "usdt" to impersonate "USDT"
2. **User Financial Loss**: Users relying on symbol-based identification interact with wrong tokens
3. **Independent Token State**: Both tokens have separate `TokenInfos` entries with distinct balances, supplies, and issuers
4. **DApp Confusion**: Symbol resolution becomes unpredictable since lookups are case-sensitive

The severity is HIGH because it breaks a core protocol invariant, enables targeted impersonation of high-value tokens, and causes direct user financial harm.

## Likelihood Explanation

The entry point `CrossChainCreateToken` is a public method callable with valid cross-chain merkle proofs. [7](#0-6) 

**Attacker Requirements:**
1. Control or deploy a side-chain
2. Register side-chain token contract via Parliament approval (standard governance process)
3. Create token with different case on their side-chain
4. Generate valid cross-chain merkle proofs

While Parliament approval creates a governance barrier, it is achievable through standard processes for legitimate side-chains. The technical execution is straightforward after registration.

**Likelihood Assessment**: MEDIUM - Requires governance approval but is technically feasible and economically rational for high-value token impersonation attacks.

## Recommendation

Add case-insensitive validation to `CrossChainCreateToken` before calling `RegisterTokenInfo`:

```csharp
public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
{
    // ... existing validation code ...
    
    var isSymbolAliasSet = SyncSymbolAliasFromTokenInfo(tokenInfo);
    if (State.TokenInfos[tokenInfo.Symbol] == null)
    {
        // ADD THIS CHECK:
        CheckTokenExists(tokenInfo.Symbol);
        
        RegisterTokenInfo(tokenInfo);
        // ... rest of code ...
    }
    // ...
}
```

This ensures `CrossChainCreateToken` enforces the same case-insensitive uniqueness as `CreateToken`.

## Proof of Concept

The following test demonstrates creating "token" via cross-chain when "TOKEN" already exists:

```csharp
[Fact]
public async Task CrossChainCreateToken_CaseInsensitive_Bypass_Test()
{
    // Setup: Create "TOKEN" on main chain
    await CreateTokenOnMainChain("TOKEN");
    
    // Setup cross-chain infrastructure
    var sideChainId = await GenerateSideChainAsync();
    await RegisterSideChainContractAddressOnMainChainAsync(sideChainId);
    
    // Attacker creates "token" (lowercase) on side chain
    await CreateTokenOnSideChain("token");
    var tokenValidationTx = CreateTokenInfoValidationTransaction("token");
    
    // Generate cross-chain proof
    var merklePath = await GenerateMerklePathForTransaction(tokenValidationTx);
    
    // Execute cross-chain create - should fail but succeeds
    var result = await TokenContractStub.CrossChainCreateToken.SendAsync(
        new CrossChainCreateTokenInput
        {
            FromChainId = sideChainId,
            TransactionBytes = tokenValidationTx.ToByteString(),
            MerklePath = merklePath,
            ParentChainHeight = blockHeight
        });
    
    // Vulnerability: Both "TOKEN" and "token" now exist
    var upperToken = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "TOKEN" });
    var lowerToken = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "token" });
    
    Assert.NotNull(upperToken);
    Assert.NotNull(lowerToken);
    Assert.NotEqual(upperToken.Issuer, lowerToken.Issuer); // Separate tokens!
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L17-17)
```csharp
    public MappedState<string, bool> InsensitiveTokenExisting { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L87-88)
```csharp
        CheckTokenExists(tokenInfo.Symbol);
        RegisterTokenInfo(tokenInfo);
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
