# Audit Report

## Title
Missing Token Name Length Validation in Cross-Chain Token Creation Allows Storage DoS

## Summary
The `CrossChainCreateToken` function bypasses the 80-character TokenName length validation enforced in the normal `Create` flow, allowing tokens with extremely long names (up to ~100KB within the 128KB state size limit) to be registered from whitelisted cross-chains, causing storage bloat and potential DoS.

## Finding Description

The vulnerability exists due to inconsistent validation across two token registration paths:

**Normal Create Path (Protected):**
The `CreateToken` method calls `AssertValidCreateInput` which enforces the TokenName length constraint. [1](#0-0) 

The validation logic checks that `input.TokenName.Length <= TokenContractConstants.TokenNameLength`. [2](#0-1) 

The constant `TokenNameLength` is defined as 80 characters. [3](#0-2) 

**Cross-Chain Create Path (Vulnerable):**
The `CrossChainCreateToken` method creates a `TokenInfo` object directly from cross-chain data and passes it to `RegisterTokenInfo` without calling `AssertValidCreateInput`. [4](#0-3) 

**Root Cause:**
The `RegisterTokenInfo` function only validates that TokenName is not null or empty but never checks its length, relying entirely on upstream callers to perform this validation. [5](#0-4) 

**Why State Size Limit Is Insufficient:**
While AElf enforces a 128KB state size limit [6](#0-5) , this only provides an upper bound. It still allows TokenName values approximately 1,250x larger than the intended 80 bytes (~100KB vs 80 bytes), violating defense-in-depth principles. The state size validation occurs at the VM level through automatic IL injection [7](#0-6)  but does not enforce contract-specific business logic constraints.

## Impact Explanation

**Storage Bloat:** Each malicious token can consume ~100KB for TokenName instead of the intended 80 bytes, a ~1,250x increase per token.

**Cumulative DoS:** An attacker controlling a compromised whitelisted source chain can register multiple such tokens, causing cumulative storage consumption that stresses node storage infrastructure.

**Expensive Operations:** Reading/writing `TokenInfo` objects with extremely large TokenName fields increases gas costs proportionally, degrading contract performance and user experience.

**State Database Stress:** Large state entries burden the underlying storage layer, affecting overall blockchain performance.

**Quantified Impact:** A single token with 100KB TokenName consumes ~131,000 excess bytes. Ten such tokens = ~1.3MB excess storage, with proportionally higher gas costs for all token operations involving these TokenInfo objects.

**Affected Parties:** Node operators (storage costs), contract users (higher gas fees), protocol (state bloat).

## Likelihood Explanation

**Prerequisites:**
1. Source chain must be whitelisted via Parliament governance [8](#0-7) 
2. Source chain must be compromised, have a validation bug, or run a different contract version allowing oversized TokenName
3. Attacker must execute cross-chain token creation with valid merkle proof verification [9](#0-8) 

**Likelihood Assessment:** Medium-Low. Requires compromising or exploiting a trusted whitelisted source chain, which has governance controls. However, this represents a **mis-scoped privilege** issue where `CrossChainCreateToken` bypasses validation that should apply to all token creation paths. Defense-in-depth principles suggest the receiving chain should independently validate all inputs regardless of source trust, making this a valid security concern.

**Feasibility:** Executable if preconditions are met. While whitelisted chains are presumed trustworthy, cross-chain integrations inherently involve external trust boundaries where validation should occur. This is a directly reachable invariant break that violates the 80-character design constraint.

## Recommendation

Add TokenName length validation to the `CrossChainCreateToken` method before calling `RegisterTokenInfo`:

```csharp
// In CrossChainCreateToken method, after line 503:
Assert(tokenInfo.TokenName.Length <= TokenContractConstants.TokenNameLength, 
    "Token name exceeds maximum length.");
```

Alternatively, add the validation directly in `RegisterTokenInfo` to ensure all paths enforce this invariant:

```csharp
private void RegisterTokenInfo(TokenInfo tokenInfo)
{
    Assert(!string.IsNullOrEmpty(tokenInfo.Symbol) && IsValidSymbol(tokenInfo.Symbol),
        "Invalid symbol.");
    Assert(!string.IsNullOrEmpty(tokenInfo.TokenName), "Token name can neither be null nor empty.");
    Assert(tokenInfo.TokenName.Length <= TokenContractConstants.TokenNameLength, 
        "Token name exceeds maximum length.");
    Assert(tokenInfo.TotalSupply > 0, "Invalid total supply.");
    Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
    Assert(tokenInfo.Owner != null, "Invalid owner address.");
    State.TokenInfos[tokenInfo.Symbol] = tokenInfo;
    State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()] = true;
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a whitelisted source chain via Parliament governance
2. Creating a token on the source chain with TokenName exceeding 80 characters (e.g., 10,000 characters)
3. Calling `ValidateTokenInfoExists` on the source chain with the oversized TokenName
4. Executing `CrossChainCreateToken` on the target chain with valid merkle proof
5. Observing that the token is successfully registered with the oversized TokenName, bypassing the 80-character limit

The test would verify that:
- Normal `Create` path rejects TokenName > 80 characters
- `CrossChainCreateToken` accepts TokenName > 80 characters from whitelisted chain
- The registered token has TokenName exceeding the intended 80-character limit

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-50)
```csharp
    private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
    {
        AssertValidCreateInput(input, symbolType);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L480-482)
```csharp
        var tokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        Assert(tokenContractAddress != null,
            $"Token contract address of chain {ChainHelper.ConvertChainIdToBase58(input.FromChainId)} not registered.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L488-488)
```csharp
        CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L492-508)
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

        var isSymbolAliasSet = SyncSymbolAliasFromTokenInfo(tokenInfo);
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-277)
```csharp
    private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
    {
        Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
               && input.Symbol.Length > 0
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L5-5)
```csharp
    public const int TokenNameLength = 80;
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L148-160)
```csharp
    public object ValidateStateSize(object obj)
    {
        var stateSizeLimit = AsyncHelper.RunSync(() => _smartContractBridgeService.GetStateSizeLimitAsync(
            new ChainContext
            {
                BlockHash = _transactionContext.PreviousBlockHash,
                BlockHeight = _transactionContext.BlockHeight - 1
            }));
        var size = SerializationHelper.Serialize(obj).Length;
        if (size > stateSizeLimit)
            throw new StateOverSizeException($"State size {size} exceeds limit of {stateSizeLimit}.");
        return obj;
    }
```
