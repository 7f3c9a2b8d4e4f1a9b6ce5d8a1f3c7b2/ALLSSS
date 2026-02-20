# Audit Report

## Title
Unhandled Exception in CrossChainCreate Due to Missing External Info Validation

## Summary
The `CrossChainCreate` method in the NFT contract accesses token external info dictionary keys without validation, causing unhandled exceptions (`KeyNotFoundException` or `FormatException`) when required NFT metadata is missing or malformed. This creates a denial-of-service vector preventing cross-chain NFT protocol synchronization for improperly created tokens.

## Finding Description

The vulnerability exists in the `CrossChainCreate` method where external info dictionary values are accessed without checking key existence or validating content format.

**Root Cause:**

The code directly accesses dictionary keys without defensive patterns: [1](#0-0) 

The constant keys are defined as `"aelf_nft_base_uri"` and `"aelf_nft_token_id_reuse"`: [2](#0-1) 

**Why Protections Fail:**

1. **No ExternalInfo Validation in Token Creation**: The MultiToken contract's `Create` method accepts arbitrary `ExternalInfo` without validating NFT-specific metadata keys: [3](#0-2) 

2. **Validation Function Insufficient**: The `AssertValidCreateInput` method validates basic properties but does NOT check ExternalInfo contents: [4](#0-3) 

3. **ExternalInfo Preserved During Cross-Chain Sync**: When tokens are synced cross-chain via `CrossChainCreateToken`, the external info is copied verbatim without validation: [5](#0-4) 

4. **No Authorization Check**: The `CrossChainCreate` method has no authorization check and is publicly callable: [6](#0-5) 

**Execution Path:**

1. Attacker creates token on main chain via `MultiToken.Create` with missing or invalid external info (bypassing NFT contract's proper `Create` method which sets metadata correctly): [7](#0-6) 

2. Token is synced to side chain via `CrossChainCreateToken`, preserving the malformed external info

3. User or automated system calls `CrossChainCreate` on side chain for that token symbol

4. Dictionary access throws `KeyNotFoundException` (if key missing) or `FormatException` (if boolean value invalid)

5. Transaction reverts with unhandled exception, consuming gas up to failure point

## Impact Explanation

**Primary Harm:**
- **Denial of Service**: Prevents cross-chain synchronization of NFT protocols for tokens lacking proper metadata
- **Transaction Reversion**: All attempts to sync the NFT protocol fail with unhandled exceptions
- **Gas Consumption**: Users/systems waste gas on failed transactions
- **Symbol Squatting**: Malicious actors can create tokens with specific symbols on main chain to prevent legitimate NFT protocols from being synced to side chains

**Scope:**
- Only affects tokens NOT created via NFT contract's proper `Create` method
- Legitimate NFT protocols with correct metadata (created via `NFT.Create`) remain functional
- No state corruption, fund loss, or authorization bypass occurs
- Transaction fails safely without corrupting contract state

**Severity Assessment:**
This represents a **Medium severity** defensive programming issue. While it creates operational disruption and a griefing vector, the impact is limited to availability (DoS) rather than fund loss or privilege escalation. The transaction fails safely without state corruption.

## Likelihood Explanation

**Attacker Capabilities:**
- Any user can create tokens via `MultiToken.Create` without restrictions on external info content
- No special permissions required to trigger the vulnerability
- Anyone can call `CrossChainCreate` due to lack of authorization check

**Attack Complexity:**
- **Low**: Straightforward three-step process (create token, sync cross-chain via normal mechanisms, trigger exception)
- No cryptographic or timing requirements
- Direct method calls with predictable behavior

**Feasibility Conditions:**
- Attacker must create token on main chain first (requires SEED NFT or whitelist access)
- Token must be synced cross-chain via legitimate MultiToken cross-chain mechanisms
- Limited practical benefit: only blocks NFT protocol sync for that specific symbol

**Probability:**
- **Moderate to High**: More likely to occur accidentally (users not following proper NFT creation procedures) than maliciously
- Automated cross-chain sync systems could encounter this with improperly created tokens
- Low barrier to entry once token creation requirements are met

## Recommendation

Add defensive dictionary access patterns in the `CrossChainCreate` method:

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

    // Add defensive checks
    Assert(tokenInfo.ExternalInfo?.Value != null, "Token external info is missing.");
    Assert(tokenInfo.ExternalInfo.Value.TryGetValue(NftBaseUriMetadataKey, out var baseUri) && !string.IsNullOrEmpty(baseUri),
        $"Required metadata key '{NftBaseUriMetadataKey}' is missing or empty.");
    Assert(tokenInfo.ExternalInfo.Value.TryGetValue(NftTokenIdReuseMetadataKey, out var tokenIdReuseStr) && 
           bool.TryParse(tokenIdReuseStr, out var isTokenIdReuse),
        $"Required metadata key '{NftTokenIdReuseMetadataKey}' is missing or invalid.");
    
    // Continue with existing logic...
}
```

Additionally, consider adding authorization checks to restrict who can call `CrossChainCreate`, or add validation in `MultiToken.Create` to enforce NFT metadata requirements when appropriate.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_MissingExternalInfo_ShouldThrowException()
{
    // Step 1: Create a token via MultiToken.Create with missing NFT metadata
    // (This bypasses the NFT contract's proper Create method)
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "TESTNFT",
        TokenName = "Test NFT Token",
        TotalSupply = 1000,
        Decimals = 0,
        Issuer = DefaultAddress,
        IsBurnable = true,
        ExternalInfo = new ExternalInfo() // Empty - missing required NFT keys
    });
    
    // Step 2: Attempt to call CrossChainCreate on the token
    // This should throw KeyNotFoundException
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.CrossChainCreate.SendAsync(new CrossChainCreateInput
        {
            Symbol = "TESTNFT"
        });
    });
    
    // Verify the exception is due to missing dictionary key
    Assert.Contains("KeyNotFoundException", exception.ToString());
}
```

**Notes:**
- This vulnerability is confirmed by examining the actual contract code
- The issue affects cross-chain NFT protocol synchronization for improperly created tokens
- Proper NFT protocols created via `NFT.Create` are unaffected as they include all required metadata
- The fix requires adding defensive dictionary access patterns with proper error handling

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L196-199)
```csharp
        tokenExternalInfo.Value[NftTypeMetadataKey] = input.NftType;
        // Add Uri to external info.
        tokenExternalInfo.Value[NftBaseUriMetadataKey] = input.BaseUri;
        tokenExternalInfo.Value[NftTokenIdReuseMetadataKey] = input.IsTokenIdReuse.ToString();
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L501-501)
```csharp
            ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-283)
```csharp
    private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
    {
        Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
               && input.Symbol.Length > 0
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

        CheckSymbolLength(input.Symbol, symbolType);
        if (symbolType == SymbolType.Nft) return;
        CheckTokenAndCollectionExists(input.Symbol);
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
    }
```
