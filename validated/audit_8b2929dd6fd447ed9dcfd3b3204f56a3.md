# Audit Report

## Title
Unvalidated Boolean Parsing in CrossChainCreate Enables NFT Protocol Creation DoS

## Summary
An attacker can permanently prevent NFT protocol creation for specific symbols on sidechains by creating a token with a malformed `NftTokenIdReuseMetadataKey` value through the MultiToken contract. When this token is cross-chained and `CrossChainCreate()` is invoked, an unprotected `bool.Parse()` call throws a `FormatException`, causing permanent DoS since the protocol is never created but subsequent attempts are blocked.

## Finding Description

The vulnerability exists in the NFT contract's `CrossChainCreate()` method, which directly parses the `NftTokenIdReuseMetadataKey` value from token ExternalInfo without validation or error handling: [1](#0-0) 

C#'s `bool.Parse()` only accepts "True" or "False" (case-insensitive). Any other value throws a `FormatException`, causing transaction failure.

The root cause is that the MultiToken contract accepts arbitrary ExternalInfo values without format validation. While the `AssertValidCreateInput` method validates basic token properties, it does not validate ExternalInfo: [2](#0-1) 

The NFT contract properly sets this value using `bool.ToString()` when creating tokens through the intended path: [3](#0-2) 

And protects the key as reserved: [4](#0-3) [5](#0-4) 

However, an attacker can bypass the NFT contract entirely by calling `MultiToken.Create()` directly. The only requirement is possessing a seed NFT or being on the whitelist: [6](#0-5) 

Once created, the malicious token can be legitimately cross-chained via `CrossChainCreateToken`, which validates token existence but not ExternalInfo value formats: [7](#0-6) 

The NFT protocol creation becomes permanently blocked because the check at line 79 prevents duplicate protocol creation, but every call to `CrossChainCreate` fails at line 88 before reaching line 108 where the protocol would be stored: [8](#0-7) 

## Impact Explanation

**Operational Impact - Permanent DoS of NFT Protocol Creation:**

This vulnerability causes permanent denial-of-service for NFT protocol creation on sidechains for affected token symbols. When `CrossChainCreate()` is called for a poisoned token, the unhandled `FormatException` causes transaction failure. Since the protocol is never created (the method fails before reaching state update at line 108), subsequent attempts will pass the duplicate check at line 79 but fail again at line 88, creating a permanent DoS condition.

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

Add try-catch error handling around the `bool.Parse()` call or validate ExternalInfo boolean values before parsing. Example fix:

```csharp
// In CrossChainCreate method, replace line 88:
bool isTokenIdReuse = false;
if (tokenInfo.ExternalInfo.Value.TryGetValue(NftTokenIdReuseMetadataKey, out var reuseValue))
{
    if (!bool.TryParse(reuseValue, out isTokenIdReuse))
    {
        // Default to false or throw clear error
        throw new AssertionException($"Invalid boolean value for {NftTokenIdReuseMetadataKey}: {reuseValue}");
    }
}
```

Alternatively, add ExternalInfo value format validation in the MultiToken contract's `AssertValidCreateInput` method to prevent malformed metadata at creation time.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_WithMalformedBooleanValue_ShouldFailPermanently()
{
    // 1. Create malicious token via MultiToken with invalid boolean value
    var maliciousSymbol = "AR123456789";
    var createInput = new CreateInput
    {
        Symbol = maliciousSymbol,
        TokenName = "Malicious Token",
        TotalSupply = 1000,
        Decimals = 0,
        Issuer = DefaultAddress,
        IsBurnable = true,
        ExternalInfo = new ExternalInfo
        {
            Value =
            {
                { "aelf_nft_base_uri", "https://example.com/" },
                { "aelf_nft_type", "Art" },
                { "aelf_nft_token_id_reuse", "1" } // Invalid boolean value
            }
        }
    };
    
    await TokenContractStub.Create.SendAsync(createInput);
    
    // 2. Validate on mainchain
    await TokenContractStub.ValidateTokenInfoExists.SendAsync(new ValidateTokenInfoExistsInput
    {
        Symbol = maliciousSymbol,
        TokenName = createInput.TokenName,
        TotalSupply = createInput.TotalSupply,
        Decimals = createInput.Decimals,
        Issuer = createInput.Issuer,
        IsBurnable = createInput.IsBurnable,
        ExternalInfo = { createInput.ExternalInfo.Value }
    });
    
    // 3. Cross-chain create token on sidechain (simulate)
    // ... merkle proof setup ...
    
    // 4. Attempt CrossChainCreate - should throw FormatException
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.CrossChainCreate.SendAsync(new CrossChainCreateInput
        {
            Symbol = maliciousSymbol
        });
    });
    
    Assert.Contains("FormatException", exception.Message);
    
    // 5. Verify protocol was not created
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = maliciousSymbol });
    Assert.Null(protocolInfo.Symbol); // Protocol doesn't exist
    
    // 6. Subsequent attempts also fail - permanent DoS
    var exception2 = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.CrossChainCreate.SendAsync(new CrossChainCreateInput
        {
            Symbol = maliciousSymbol
        });
    });
    
    Assert.Contains("FormatException", exception2.Message);
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-129)
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
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");

        var nftProtocolInfo = new NFTProtocolInfo
        {
            Symbol = input.Symbol,
            TotalSupply = tokenInfo.TotalSupply,
            BaseUri = baseUri,
            Creator = tokenInfo.Issuer,
            IsBurnable = tokenInfo.IsBurnable,
            IssueChainId = tokenInfo.IssueChainId,
            IsTokenIdReuse = isTokenIdReuse,
            Metadata = new Metadata { Value = { tokenInfo.ExternalInfo.Value } },
            ProtocolName = tokenInfo.TokenName,
            NftType = nftTypeFullName
        };
        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;

        State.MinterListMap[input.Symbol] = new MinterList
        {
            Value = { nftProtocolInfo.Creator }
        };

        Context.Fire(new NFTProtocolCreated
        {
            Symbol = input.Symbol,
            Creator = nftProtocolInfo.Creator,
            IsBurnable = nftProtocolInfo.IsBurnable,
            IssueChainId = nftProtocolInfo.IssueChainId,
            ProtocolName = nftProtocolInfo.ProtocolName,
            TotalSupply = nftProtocolInfo.TotalSupply,
            Metadata = nftProtocolInfo.Metadata,
            BaseUri = nftProtocolInfo.BaseUri,
            IsTokenIdReuse = isTokenIdReuse,
            NftType = nftProtocolInfo.NftType
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L199-199)
```csharp
        tokenExternalInfo.Value[NftTokenIdReuseMetadataKey] = input.IsTokenIdReuse.ToString();
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L118-123)
```csharp
    private void AssertMetadataKeysAreCorrect(IEnumerable<string> metadataKeys)
    {
        var reservedMetadataKey = GetNftMetadataReservedKeys();
        foreach (var metadataKey in metadataKeys)
            Assert(!reservedMetadataKey.Contains(metadataKey), $"Metadata key {metadataKey} is reserved.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-80)
```csharp
    private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
    {
        AssertValidCreateInput(input, symbolType);
        if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
        {
            // can not call create on side chain
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
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
        }

        var tokenInfo = new TokenInfo
        {
            Symbol = input.Symbol,
            TokenName = input.TokenName,
            TotalSupply = input.TotalSupply,
            Decimals = input.Decimals,
            Issuer = input.Issuer,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
            Owner = input.Owner
        };

```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L478-503)
```csharp
    public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
    {
        var tokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        Assert(tokenContractAddress != null,
            $"Token contract address of chain {ChainHelper.ConvertChainIdToBase58(input.FromChainId)} not registered.");

        var originalTransaction = Transaction.Parser.ParseFrom(input.TransactionBytes);

        AssertCrossChainTransaction(originalTransaction, tokenContractAddress, nameof(ValidateTokenInfoExists));
        var originalTransactionId = originalTransaction.GetHash();
        CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
        var validateTokenInfoExistsInput =
            ValidateTokenInfoExistsInput.Parser.ParseFrom(originalTransaction.Params);
        AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
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
```
