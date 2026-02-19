# Audit Report

## Title
Missing Dictionary Key Validation in CrossChainCreate Causes KeyNotFoundException and DoS

## Summary
The `CrossChainCreate` method in the NFT contract directly accesses `ExternalInfo` dictionary keys without validation, causing `KeyNotFoundException` when tokens lack required NFT metadata. This enables permanent DoS attacks on cross-chain NFT protocol creation by pre-creating tokens with NFT collection symbol formats but incomplete metadata.

## Finding Description

The vulnerability exists in the `CrossChainCreate` method where it directly accesses dictionary keys without checking if they exist: [1](#0-0) 

The method only verifies token existence but never validates that the required NFT metadata keys are present in `ExternalInfo`: [2](#0-1) 

**Root Cause:**

Normal NFT protocol creation through `Create()` guarantees these metadata keys are added: [3](#0-2) 

However, the MultiToken contract's `Create` method accepts arbitrary `ExternalInfo` without enforcing NFT-specific metadata requirements: [4](#0-3) 

The MultiToken contract determines symbol types based purely on format (symbols ending in "-0" are NFT collections): [5](#0-4) [6](#0-5) 

This allows anyone with token creation permissions to create tokens with NFT collection symbol formats (e.g., "ABART-0") but incomplete `ExternalInfo`. When these tokens are synced to sidechains via `CrossChainCreateToken`, the incomplete `ExternalInfo` is preserved: [7](#0-6) 

**Why Existing Protections Fail:**

The `CrossChainCreate` method has no authorization checks and can be called by anyone: [8](#0-7) [9](#0-8) 

The MultiToken contract itself uses defensive `ContainsKey` checks before accessing `ExternalInfo` dictionary entries: [10](#0-9) 

However, the NFT contract does not follow this defensive pattern in `CrossChainCreate`.

## Impact Explanation

**Concrete Harm:**
- **Complete DoS of NFT Protocol Creation**: Attackers can permanently block legitimate NFT protocols from being created on sidechains by pre-creating tokens with matching symbols but incomplete metadata
- **No Recovery Mechanism**: Once a token with incomplete metadata exists and is synced cross-chain, the NFT protocol cannot be created on sidechains for that symbol
- **Cross-Chain Griefing**: Any token created without proper NFT metadata will cause failures when users call `CrossChainCreate` on sidechains
- **Protocol Availability Breach**: All calls to `CrossChainCreate` for affected symbols throw unhandled `KeyNotFoundException`, breaking cross-chain NFT synchronization

**Who is Affected:**
- NFT protocol creators attempting to sync protocols to sidechains
- Sidechain users unable to access NFT protocols
- The broader AElf ecosystem's cross-chain NFT functionality

**Severity Justification:**
High severity because this vulnerability enables complete denial of service for cross-chain NFT protocol creation with permanent impact and no recovery path.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must have permission to call `TokenContract.Create()` through either being in the create whitelist OR owning a seed NFT for the desired symbol [11](#0-10) 

**Attack Complexity:**
Low - The attack requires only:
1. One call to `TokenContract.Create()` with an NFT collection symbol format (e.g., "ABART-0") and empty/incomplete `ExternalInfo`
2. Natural cross-chain token synchronization occurs automatically
3. Any user calling `CrossChainCreate()` triggers the `KeyNotFoundException`

**Feasibility:**
- Seed NFTs are obtainable through normal protocol mechanisms
- No special timing or state requirements
- Attack is difficult to detect until `CrossChainCreate()` is called
- Standard cross-chain synchronization propagates the vulnerability automatically

**Probability:** Medium-High - Seed NFTs are accessible through normal means, the attack is straightforward, and clear griefing motivation exists for competitors' NFT protocols.

## Recommendation

Add defensive dictionary key validation before accessing `ExternalInfo` entries in the `CrossChainCreate` method:

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

    // Add validation checks
    Assert(tokenInfo.ExternalInfo != null && 
           tokenInfo.ExternalInfo.Value.ContainsKey(NftBaseUriMetadataKey), 
           "Token missing required NFT base URI metadata.");
    Assert(tokenInfo.ExternalInfo.Value.ContainsKey(NftTokenIdReuseMetadataKey),
           "Token missing required NFT token ID reuse metadata.");

    var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
    var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
    // ... rest of method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_MissingMetadata_ThrowsKeyNotFoundException()
{
    // Step 1: Create a token with NFT collection symbol format but no NFT metadata
    var symbol = "TEST-0"; // NFT collection format
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = symbol,
        TokenName = "Test Token",
        TotalSupply = 1000,
        Decimals = 0,
        Issuer = DefaultAddress,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF"),
        ExternalInfo = new ExternalInfo() // Empty - no NFT metadata keys
    });
    
    // Step 2: Verify token was created
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput 
    { 
        Symbol = symbol 
    });
    tokenInfo.Symbol.ShouldBe(symbol);
    
    // Step 3: Attempt to call CrossChainCreate on sidechain
    // This will throw KeyNotFoundException because ExternalInfo lacks NFT metadata keys
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NftContractStub.CrossChainCreate.SendAsync(new CrossChainCreateInput
        {
            Symbol = symbol
        });
    });
    
    // Verify the exception is KeyNotFoundException for missing metadata keys
    exception.Message.ShouldContain("aelf_nft_base_uri");
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-78)
```csharp
    public override Empty CrossChainCreate(CrossChainCreateInput input)
    {
        MakeSureTokenContractAddressSet();
        InitialNFTTypeNameMap();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L80-85)
```csharp
        var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
        {
            Symbol = input.Symbol
        });
        if (string.IsNullOrEmpty(tokenInfo.Symbol))
            throw new AssertionException($"Token info {input.Symbol} not exists.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-79)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L492-503)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L22-22)
```csharp
    public const string CollectionSymbolSuffix = "0";
```

**File:** protobuf/nft_contract.proto (L25-26)
```text
    rpc CrossChainCreate (CrossChainCreateInput) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L326-331)
```csharp
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.LockCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.LockCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
```
