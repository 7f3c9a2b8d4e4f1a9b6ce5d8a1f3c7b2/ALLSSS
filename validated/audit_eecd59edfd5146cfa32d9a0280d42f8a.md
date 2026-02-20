# Audit Report

## Title
Unhandled Exception in CrossChainCreate Due to Missing External Info Validation

## Summary
The `CrossChainCreate` method in the NFT contract performs unsafe dictionary access on token ExternalInfo without validating key existence, causing unhandled `KeyNotFoundException` or `FormatException` when NFT-specific metadata keys are missing or malformed. This creates a denial-of-service vector that prevents cross-chain NFT protocol synchronization for improperly created tokens.

## Finding Description

The `CrossChainCreate` method directly accesses dictionary keys from `tokenInfo.ExternalInfo.Value` without defensive checks, violating the safe access pattern used elsewhere in the codebase. [1](#0-0) 

The vulnerable lines use direct dictionary indexing for `NftBaseUriMetadataKey` ("aelf_nft_base_uri") and `NftTokenIdReuseMetadataKey` ("aelf_nft_token_id_reuse"), then parse the boolean value without error handling. [2](#0-1) 

**Why This Occurs:**

1. **No ExternalInfo Validation in MultiToken.Create**: The MultiToken contract's `Create` method accepts arbitrary ExternalInfo without validating NFT-specific metadata keys. The ExternalInfo is simply assigned with a null coalescing operator, allowing empty or incomplete metadata. [3](#0-2) 

2. **ExternalInfo Preserved Verbatim During Cross-Chain Sync**: When tokens are synchronized cross-chain via `CrossChainCreateToken`, the ExternalInfo is copied without validation, preserving any missing or malformed metadata. [4](#0-3) 

3. **No Authorization on CrossChainCreate**: The method has no authorization check, allowing any user to call it and trigger the exception. [5](#0-4) 

4. **Inconsistent with Codebase Patterns**: Other parts of the codebase use defensive `TryGetValue` patterns for ExternalInfo access, demonstrating awareness of this issue. [6](#0-5) 

**Attack Scenario:**
1. Attacker creates token via `MultiToken.Create` with missing NFT metadata keys (bypassing `NFT.Create` which sets them correctly)
2. Token is synced to side chain via standard `CrossChainCreateToken` mechanism
3. Anyone calls `NFT.CrossChainCreate` with that symbol
4. Transaction reverts with `KeyNotFoundException` or `FormatException`
5. Gas is consumed and NFT protocol sync fails

## Impact Explanation

This vulnerability creates a **denial-of-service condition** with the following impacts:

- **Prevents NFT Protocol Synchronization**: Tokens lacking proper metadata cannot have their NFT protocols created on side chains, blocking legitimate cross-chain NFT functionality
- **Gas Waste**: Users and automated systems attempting to sync NFT protocols waste gas on failed transactions
- **Symbol Squatting**: Malicious actors can preemptively create tokens with specific symbols using improper metadata to prevent legitimate NFT protocols from being synced
- **Operational Disruption**: Automated cross-chain sync systems may encounter failures when processing improperly created tokens

**Severity: Medium** - The impact is limited to availability (DoS) rather than fund loss or privilege escalation. The transaction fails safely without state corruption, and only affects tokens not created through proper NFT creation procedures. Legitimate NFT protocols created via `NFT.Create` (which sets metadata correctly) remain fully functional.

## Likelihood Explanation

**High Likelihood** due to:

- **No Permissions Required**: Both `MultiToken.Create` and `NFT.CrossChainCreate` are public methods accessible to any user
- **Low Attack Complexity**: Direct method calls with no cryptographic or timing requirements
- **Accidental Occurrence**: More likely to happen accidentally when users don't follow proper NFT creation procedures than through deliberate malicious action
- **Automated System Impact**: Cross-chain sync systems could encounter this with any improperly created tokens
- **Straightforward Execution Path**: Create token → sync cross-chain → trigger exception

The vulnerability can be triggered by anyone with minimal effort and could occur both maliciously and accidentally during normal operations.

## Recommendation

Implement defensive dictionary access patterns consistent with the rest of the codebase:

```csharp
public override Empty CrossChainCreate(CrossChainCreateInput input)
{
    MakeSureTokenContractAddressSet();
    InitialNFTTypeNameMap();
    Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
    
    var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
    {
        Symbol = input.Symbol
    });
    
    if (string.IsNullOrEmpty(tokenInfo.Symbol))
        throw new AssertionException($"Token info {input.Symbol} not exists.");

    // Defensive dictionary access with validation
    Assert(tokenInfo.ExternalInfo != null && 
           tokenInfo.ExternalInfo.Value.TryGetValue(NftBaseUriMetadataKey, out var baseUri),
           $"NFT base URI metadata not found for {input.Symbol}");
    
    Assert(tokenInfo.ExternalInfo.Value.TryGetValue(NftTokenIdReuseMetadataKey, out var tokenIdReuseStr) &&
           bool.TryParse(tokenIdReuseStr, out var isTokenIdReuse),
           $"NFT token ID reuse metadata invalid for {input.Symbol}");
    
    // Continue with validated values...
}
```

Alternatively, add validation in `MultiToken.Create` to reject tokens claiming to be NFT collections without proper metadata, or add metadata validation during `CrossChainCreateToken`.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_MissingMetadata_ThrowsException()
{
    // Setup: Create token on main chain via MultiToken.Create 
    // with MISSING NFT metadata keys (bypassing NFT.Create)
    var symbol = "TEST-NFT-1";
    var multiTokenStub = GetMultiTokenContractStub(DefaultSender);
    
    await multiTokenStub.Create.SendAsync(new CreateInput
    {
        Symbol = symbol,
        TokenName = "Test NFT",
        TotalSupply = 1000,
        Decimals = 0,
        Issuer = DefaultSender,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF"),
        // ExternalInfo is EMPTY - no NFT metadata keys!
        ExternalInfo = new ExternalInfo()
    });
    
    // Simulate cross-chain sync (token now exists on side chain with empty ExternalInfo)
    // In real scenario, CrossChainCreateToken would preserve the empty ExternalInfo
    
    // Attempt to create NFT protocol on side chain
    var nftStub = GetNFTContractStub(DefaultSender);
    
    // This should throw KeyNotFoundException when accessing missing metadata keys
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await nftStub.CrossChainCreate.SendAsync(new CrossChainCreateInput
        {
            Symbol = symbol
        });
    });
    
    // Verify the exception is due to missing dictionary key
    Assert.Contains("KeyNotFoundException", exception.GetType().Name);
}
```

**Notes:**
- This vulnerability only affects tokens created via `MultiToken.Create` that bypass the NFT contract's proper `Create` method, which correctly sets the required metadata keys at lines 198-199 of NFTContract_Create.cs
- The codebase demonstrates awareness of safe dictionary access patterns (using `TryGetValue`) in other locations, making this an inconsistency rather than a systemic issue
- No authorization check exists on `CrossChainCreate`, allowing any user to trigger the vulnerability once a malformed token exists
- The issue represents a defensive programming gap that creates a real DoS vector, though without fund loss or state corruption

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-75)
```csharp
    public override Empty CrossChainCreate(CrossChainCreateInput input)
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L87-88)
```csharp
        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L8-9)
```csharp
    private const string NftBaseUriMetadataKey = "aelf_nft_base_uri";
    private const string NftTokenIdReuseMetadataKey = "aelf_nft_token_id_reuse";
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L77-77)
```csharp
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L124-130)
```csharp
        Assert(tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.SeedOwnedSymbolExternalInfoKey, out var ownedSymbol) && ownedSymbol == symbol,
            "Invalid OwnedSymbol.");
        Assert(tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                   out var expirationTime)
               && long.TryParse(expirationTime, out var expirationTimeLong) &&
               Context.CurrentBlockTime.Seconds <= expirationTimeLong, "OwnedSymbol is expired.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L501-501)
```csharp
            ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
```
