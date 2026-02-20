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

An attacker can bypass this by calling `MultiToken.Create()` directly with malformed ExternalInfo. Token creation is permissioned only by SEED NFT ownership: [5](#0-4) 

**Cross-Chain Replication**: The malformed ExternalInfo is preserved during cross-chain token creation: [6](#0-5) 

The `ValidateTokenInfoExists` method only validates that ExternalInfo keys and values match between source and destination, but does not validate content format: [7](#0-6) 

**Safer Pattern Exists**: Other parts of the codebase use the safer `TryGetValue()` pattern for ExternalInfo access: [8](#0-7) 

The NFT contract's CrossChainCreate lacks this protection, making it vulnerable to exceptions from missing keys or invalid boolean values.

## Impact Explanation

**Severity: High**

The vulnerability enables complete denial of service for cross-chain NFT protocol creation:

1. **Permanent Protocol Lock-Out**: Once a malicious token is replicated to a sidechain, any attempt to call `CrossChainCreate()` for that symbol will fail with an unhandled exception. The NFT protocol becomes permanently unavailable on the sidechain for that symbol.

2. **No Recovery Mechanism**: There is no way to fix the malformed ExternalInfo on the sidechain without a contract upgrade. The protocol check only verifies that the protocol doesn't already exist: [9](#0-8) 

Since the transaction reverts due to exception before this map entry is set, the assertion passes on every retry, but lines 87-88 always throw the exception - creating a permanent DoS state.

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
3. Execute standard cross-chain replication using `ValidateTokenInfoExists` and `CrossChainCreateToken`

**Attack Complexity**: Low - straightforward 3-step process with no cryptographic manipulation, race conditions, or timing dependencies.

**Economic Rationality**: Cost is one SEED NFT + transaction fees, enabling targeted DoS against specific NFT protocol symbols. Economically viable for competitive griefing.

**No Detection Mechanism**: While the attack leaves on-chain evidence, there is no automatic prevention or detection, and damage is permanent once the token is replicated.

## Recommendation

Implement defensive programming with exception handling and validation in `CrossChainCreate()`:

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

    // Validate ExternalInfo keys exist before accessing
    if (!tokenInfo.ExternalInfo.Value.TryGetValue(NftBaseUriMetadataKey, out var baseUri))
        throw new AssertionException($"Missing required metadata: {NftBaseUriMetadataKey}");
    
    if (!tokenInfo.ExternalInfo.Value.TryGetValue(NftTokenIdReuseMetadataKey, out var tokenIdReuseStr))
        throw new AssertionException($"Missing required metadata: {NftTokenIdReuseMetadataKey}");
    
    // Validate and parse boolean value
    if (!bool.TryParse(tokenIdReuseStr, out var isTokenIdReuse))
        throw new AssertionException($"Invalid boolean value for {NftTokenIdReuseMetadataKey}: {tokenIdReuseStr}");

    // ... rest of method
}
```

Additionally, consider adding validation in `MultiToken.Create()` to verify ExternalInfo format for NFT collection tokens, or add a separate NFT-specific creation method that enforces proper metadata structure.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_Should_Fail_With_Malformed_ExternalInfo()
{
    // 1. On mainchain: Create token with malformed ExternalInfo via MultiToken.Create()
    var malformedExternalInfo = new ExternalInfo();
    malformedExternalInfo.Value["aelf_nft_type"] = "BadgeNFT";
    malformedExternalInfo.Value["aelf_nft_base_uri"] = "https://test.com/";
    // Missing "aelf_nft_token_id_reuse" key OR
    malformedExternalInfo.Value["aelf_nft_token_id_reuse"] = "not_a_boolean"; // Invalid boolean
    
    var createInput = new CreateInput
    {
        Symbol = "BA-1",
        TokenName = "Malicious Badge",
        TotalSupply = 1000,
        Decimals = 0,
        Issuer = AttackerAddress,
        IsBurnable = true,
        ExternalInfo = malformedExternalInfo
    };
    
    // Attacker has SEED NFT and calls Create
    await TokenContractStub.Create.SendAsync(createInput);
    
    // 2. Cross-chain replicate token to sidechain (standard flow)
    // ... ValidateTokenInfoExists on mainchain
    // ... CrossChainCreateToken on sidechain
    
    // 3. Attempt to call NFT.CrossChainCreate on sidechain
    var crossChainInput = new CrossChainCreateInput { Symbol = "BA-1" };
    
    // This should throw KeyNotFoundException or FormatException
    var result = await Assert.ThrowsAsync<Exception>(async () =>
        await NFTContractStub.CrossChainCreate.SendAsync(crossChainInput)
    );
    
    // 4. Verify NFT protocol was NOT created (State.NftProtocolMap[symbol] is still null)
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = "BA-1" });
    Assert.Null(protocolInfo.Symbol); // Protocol doesn't exist
    
    // 5. Retry should fail again - permanent DoS
    await Assert.ThrowsAsync<Exception>(async () =>
        await NFTContractStub.CrossChainCreate.SendAsync(crossChainInput)
    );
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

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L7-9)
```csharp
    private const string NftTypeMetadataKey = "aelf_nft_type";
    private const string NftBaseUriMetadataKey = "aelf_nft_base_uri";
    private const string NftTokenIdReuseMetadataKey = "aelf_nft_token_id_reuse";
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
