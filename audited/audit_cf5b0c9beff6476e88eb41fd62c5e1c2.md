# Audit Report

## Title
Unhandled Exception in CrossChainCreate() Due to Unsafe bool.Parse() on Unvalidated ExternalInfo

## Summary
The `CrossChainCreate()` method in the NFT contract performs unsafe dictionary access and `bool.Parse()` operations on token `ExternalInfo` without validation or exception handling. An attacker can create a token with malformed ExternalInfo metadata on the mainchain, cross-chain replicate it, and cause permanent denial of service for NFT protocol creation on sidechains for that specific symbol.

## Finding Description

The vulnerability exists in the NFT contract's `CrossChainCreate()` method where it unsafely accesses and parses ExternalInfo metadata without validation: [1](#0-0) 

These operations are unsafe because:
1. **Direct dictionary access** using `tokenInfo.ExternalInfo.Value[key]` throws `KeyNotFoundException` if the key doesn't exist
2. **Unprotected bool.Parse()** throws `FormatException` if the value is not a valid boolean string (e.g., "True", "False")

The metadata key constants are defined as: [2](#0-1) 

**Root Cause**: The MultiToken contract's `Create()` method accepts arbitrary ExternalInfo content without validating its format: [3](#0-2) 

While the legitimate NFT contract's `Create` method properly sets boolean values as strings: [4](#0-3) 

An attacker can bypass this by calling `MultiToken.Create()` directly with malformed ExternalInfo.

**Cross-Chain Replication**: The malformed ExternalInfo is preserved during cross-chain token creation: [5](#0-4) 

The `ValidateTokenInfoExists` method only validates that ExternalInfo keys and values match between source and destination, but does not validate content format: [6](#0-5) 

**Safer Pattern Exists**: Other parts of the codebase use the safer `TryGetValue()` pattern for ExternalInfo access: [7](#0-6) 

The NFT contract's CrossChainCreate lacks this protection, making it vulnerable to exceptions from missing keys or invalid boolean values.

## Impact Explanation

**Severity: High**

The vulnerability enables complete denial of service for cross-chain NFT protocol creation:

1. **Permanent Protocol Lock-Out**: Once a malicious token is replicated to a sidechain, any attempt to call `CrossChainCreate()` for that symbol will fail with an unhandled exception. The NFT protocol becomes permanently unavailable on the sidechain for that symbol.

2. **No Recovery Mechanism**: There is no way to fix the malformed ExternalInfo on the sidechain without a contract upgrade. The protocol check prevents re-creation even if the underlying token could be fixed: [8](#0-7) 

3. **Breaks Cross-Chain Functionality**: NFT protocols that exist on the mainchain cannot be properly instantiated on sidechains, completely breaking the intended cross-chain NFT capability.

4. **Resource Waste**: Users attempting to create the protocol pay transaction fees for transactions that will always fail.

**Who is Affected**:
- NFT protocol creators expanding to sidechains
- DApps depending on cross-chain NFT availability  
- End users unable to interact with NFT protocols on affected chains

## Likelihood Explanation

**Probability: Medium-High**

The attack is feasible with low complexity:

**Attacker Requirements**:
1. Obtain a SEED NFT for token creation - these are tradeable assets on the market
2. Call `MultiToken.Create()` directly with crafted ExternalInfo containing either missing keys or invalid boolean values (e.g., "notabool" instead of "True")
3. Execute standard cross-chain replication

**Attack Complexity**: Low - straightforward 3-step process with no cryptographic manipulation, race conditions, or timing dependencies.

**Economic Rationality**: Cost is one SEED NFT + transaction fees, enabling targeted DoS against specific NFT protocol symbols. Economically viable for competitive griefing.

**No Detection Mechanism**: While the attack leaves on-chain evidence, there is no automatic prevention or detection, and damage is permanent once the token is replicated.

## Recommendation

Implement defensive validation and exception handling in the `CrossChainCreate()` method:

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

    // Validate ExternalInfo has required keys
    Assert(tokenInfo.ExternalInfo?.Value != null, "Token ExternalInfo is missing.");
    Assert(tokenInfo.ExternalInfo.Value.ContainsKey(NftBaseUriMetadataKey), 
        $"Required metadata key {NftBaseUriMetadataKey} is missing.");
    Assert(tokenInfo.ExternalInfo.Value.ContainsKey(NftTokenIdReuseMetadataKey), 
        $"Required metadata key {NftTokenIdReuseMetadataKey} is missing.");
    
    // Safely parse boolean value
    var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
    var isTokenIdReuseStr = tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey];
    Assert(bool.TryParse(isTokenIdReuseStr, out var isTokenIdReuse), 
        $"Invalid boolean value for {NftTokenIdReuseMetadataKey}: {isTokenIdReuseStr}");
    
    // Continue with existing logic...
}
```

Additionally, consider adding validation in the MultiToken contract's `Create()` method to enforce format requirements for known metadata keys.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_WithMalformedExternalInfo_ShouldFail()
{
    // Step 1: Create token on mainchain with malformed ExternalInfo
    var symbol = "AR123456789"; // NFT-like symbol with valid type prefix
    var seedNft = await ObtainSeedNftAsync(symbol);
    
    var createInput = new CreateInput
    {
        Symbol = symbol,
        TokenName = "Malicious Token",
        TotalSupply = 1000,
        Decimals = 0,
        Issuer = DefaultSender,
        IsBurnable = true,
        ExternalInfo = new ExternalInfo
        {
            Value =
            {
                { "aelf_nft_base_uri", "https://example.com" },
                { "aelf_nft_token_id_reuse", "not_a_boolean" } // Invalid boolean value
            }
        }
    };
    
    await MultiTokenContractStub.Create.SendAsync(createInput);
    
    // Step 2: Cross-chain replicate token to sidechain
    await ReplicateTokenCrossChainAsync(symbol);
    
    // Step 3: Attempt CrossChainCreate on sidechain - should throw FormatException
    var result = await NFTContractStubOnSideChain.CrossChainCreate.SendWithExceptionAsync(
        new CrossChainCreateInput { Symbol = symbol }
    );
    
    // Verify transaction failed with unhandled exception
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Format"); // FormatException from bool.Parse
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L79-79)
```csharp
        Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L87-88)
```csharp
        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L199-199)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L449-456)
```csharp
        if (tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.Count > 0 ||
            input.ExternalInfo != null && input.ExternalInfo.Count > 0)
        {
            validationResult = validationResult && tokenInfo.ExternalInfo.Value.Count == input.ExternalInfo.Count;
            if (tokenInfo.ExternalInfo.Value.Any(keyPair =>
                    !input.ExternalInfo.ContainsKey(keyPair.Key) || input.ExternalInfo[keyPair.Key] != keyPair.Value))
                throw new AssertionException("Token validation failed.");
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L501-501)
```csharp
            ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
```
