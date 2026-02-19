# Audit Report

## Title
Unvalidated Boolean Parsing in CrossChainCreate Enables NFT Protocol Creation DoS

## Summary
An attacker can create a token with a malformed `NftTokenIdReuseMetadataKey` value in ExternalInfo by directly calling the MultiToken contract's Create method. When this token is cross-chained to a sidechain and `CrossChainCreate()` is invoked, the unprotected `bool.Parse()` call throws a `FormatException`, permanently preventing NFT protocol creation for that symbol on the sidechain.

## Finding Description

The vulnerability exists in the NFT contract's `CrossChainCreate()` method, which retrieves token information and directly parses the `NftTokenIdReuseMetadataKey` value without any validation or error handling: [1](#0-0) 

The `bool.Parse()` method only accepts "True"/"False" (case-insensitive) as valid inputs. Any other value (e.g., "1", "yes", "TRUE") throws a `FormatException` that is not caught, causing the transaction to fail.

The root cause is that the MultiToken contract's `Create()` method accepts arbitrary ExternalInfo values without validating their format: [2](#0-1) 

The validation method `AssertValidCreateInput` only checks basic token properties (name length, symbol, decimals) but does not validate ExternalInfo value formats: [3](#0-2) 

While the NFT contract's `Create()` method properly sets this value using `bool.ToString()`: [4](#0-3) 

And protects the key as reserved: [5](#0-4) [6](#0-5) 

An attacker can bypass the NFT contract entirely by calling MultiToken.Create() directly. The only requirement is possessing a seed NFT or being on the whitelist: [7](#0-6) 

Once created, the malicious token can be legitimately cross-chained via `CrossChainCreateToken`, which validates token existence but not ExternalInfo value formats: [8](#0-7) 

The NFT protocol creation becomes permanently blocked because:
1. The check at line 79 prevents duplicate protocol creation
2. Every call to `CrossChainCreate` will fail at line 88 before reaching line 108 where the protocol would be stored
3. The symbol remains permanently uncreatable on that sidechain [9](#0-8) 

## Impact Explanation

**Operational Impact - Permanent DoS of NFT Protocol Creation:**

This vulnerability causes permanent denial-of-service for NFT protocol creation on sidechains for affected token symbols. When `CrossChainCreate()` is called for a poisoned token, the unhandled `FormatException` causes transaction failure. Since the protocol is never created (the method fails before reaching the state update), subsequent attempts will pass the duplicate check but fail again at the same parsing line, creating a permanent DoS condition.

The impact includes:
- Permanent blocking of legitimate NFT functionality for affected symbol namespaces on all sidechains where the malicious token is cross-chained
- Multiple symbols can be poisoned if the attacker obtains multiple seed NFTs
- No direct fund loss, but protocol functionality is permanently damaged

**Severity: Medium** - This represents an operational DoS with no direct fund impact, but it permanently damages core protocol functionality (NFT protocol deployment) on sidechains for affected symbols.

## Likelihood Explanation

**Attacker Capabilities:**
- Must obtain a seed NFT for the target symbol - seed NFTs are obtainable through normal protocol mechanisms (purchase or creation)
- No special privileges, compromised roles, or consensus control required
- Just needs to interact with public contract methods

**Attack Complexity:**
The attack is straightforward with low complexity:
1. Obtain seed NFT for desired symbol
2. Call `TokenContract.Create()` with malicious ExternalInfo containing invalid boolean value (e.g., "1" instead of "True")
3. Call `ValidateTokenInfoExists` on mainchain
4. Call `CrossChainCreateToken` on sidechain with merkle proof
5. When anyone calls `CrossChainCreate()`, transaction fails permanently

**Detection:**
The malicious token is visible on-chain but may not be detected before cross-chaining since ExternalInfo values are not typically inspected.

**Probability: High** - All preconditions are realistic and achievable under normal AElf contract semantics. Seed NFTs are obtainable, and the attack requires only standard contract interactions.

## Recommendation

Replace the unsafe `bool.Parse()` call with `bool.TryParse()` and provide appropriate error handling:

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

    var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
    
    // FIX: Use TryParse instead of Parse with validation
    if (!bool.TryParse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey], out var isTokenIdReuse))
    {
        throw new AssertionException($"Invalid boolean value for {NftTokenIdReuseMetadataKey}");
    }
    
    // Continue with rest of method...
}
```

Alternatively, add validation in `MultiToken.Create()` for known metadata keys when creating NFT collections:

```csharp
private Empty CreateNFTCollection(CreateInput input)
{
    // Validate known boolean keys in ExternalInfo
    if (input.ExternalInfo?.Value.ContainsKey("aelf_nft_token_id_reuse") == true)
    {
        if (!bool.TryParse(input.ExternalInfo.Value["aelf_nft_token_id_reuse"], out _))
        {
            throw new AssertionException("Invalid boolean format for aelf_nft_token_id_reuse");
        }
    }
    return CreateToken(input, SymbolType.NftCollection);
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_WithMalformedBooleanValue_ShouldFail()
{
    // Step 1: Create seed NFT for attacker
    var seedSymbol = "SEED-1";
    await CreateSeedNFT(seedSymbol, "XX123456");
    
    // Step 2: Attacker creates token with malformed boolean in ExternalInfo
    var maliciousExternalInfo = new ExternalInfo();
    maliciousExternalInfo.Value.Add("aelf_nft_token_id_reuse", "1"); // Invalid: should be "True" or "False"
    maliciousExternalInfo.Value.Add("aelf_nft_base_uri", "https://example.com/");
    maliciousExternalInfo.Value.Add("aelf_nft_type", "Art");
    
    var createInput = new CreateInput
    {
        Symbol = "XX123456",
        TokenName = "Malicious NFT",
        TotalSupply = 10000,
        Decimals = 0,
        Issuer = AttackerAddress,
        IsBurnable = true,
        ExternalInfo = maliciousExternalInfo
    };
    
    // This succeeds because MultiToken.Create doesn't validate ExternalInfo format
    await TokenContractStub.Create.SendAsync(createInput);
    
    // Step 3: Cross-chain the token to sidechain
    await CrossChainTokenToSidechain("XX123456");
    
    // Step 4: Attempt to create NFT protocol on sidechain - this should throw FormatException
    var crossChainInput = new CrossChainCreateInput { Symbol = "XX123456" };
    
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await SidechainNFTContractStub.CrossChainCreate.SendAsync(crossChainInput);
    });
    
    // Verify the exception is due to bool.Parse failure
    Assert.Contains("FormatException", exception.Message);
    
    // Step 5: Verify protocol was NOT created (permanent DoS)
    var protocolInfo = await SidechainNFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = "XX123456" });
    Assert.Null(protocolInfo.Symbol); // Protocol not created
    
    // Step 6: Verify subsequent attempts also fail (permanent DoS condition)
    var exception2 = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await SidechainNFTContractStub.CrossChainCreate.SendAsync(crossChainInput);
    });
    Assert.Contains("FormatException", exception2.Message);
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L79-79)
```csharp
        Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L88-88)
```csharp
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L199-199)
```csharp
        tokenExternalInfo.Value[NftTokenIdReuseMetadataKey] = input.IsTokenIdReuse.ToString();
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-65)
```csharp
            if (!IsAddressInCreateWhiteList(Context.Sender) &&
                input.Symbol != TokenContractConstants.SeedCollectionSymbol)
            {
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
            }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L118-123)
```csharp
    private void AssertMetadataKeysAreCorrect(IEnumerable<string> metadataKeys)
    {
        var reservedMetadataKey = GetNftMetadataReservedKeys();
        foreach (var metadataKey in metadataKeys)
            Assert(!reservedMetadataKey.Contains(metadataKey), $"Metadata key {metadataKey} is reserved.");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L97-107)
```csharp
    private List<string> GetNftMetadataReservedKeys()
    {
        return new List<string>
        {
            NftTypeMetadataKey,
            NftBaseUriMetadataKey,
            AssembledNftsKey,
            AssembledFtsKey,
            NftTokenIdReuseMetadataKey
        };
    }
```
