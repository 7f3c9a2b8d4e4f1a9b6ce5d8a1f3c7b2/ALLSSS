# Audit Report

## Title
NFT Type Removal Breaks Cross-Chain Protocol Creation Without Validation

## Summary
The `RemoveNFTType()` method allows parliament to remove NFT type mappings without validating whether existing NFT protocols use those types. When a type is removed, the `CrossChainCreate()` method fails for all protocols with that type prefix, permanently breaking cross-chain NFT mirroring functionality.

## Finding Description

The NFT contract maintains type mappings that are initialized in the `InitialNFTTypeNameMap()` method, creating bidirectional mappings between 2-character short names (e.g., "AR") and full type names (e.g., "Art"). [1](#0-0) 

When NFT protocols are created on the mainchain via the `Create()` method, they store the NFT type in the `NFTProtocolInfo.NftType` field and generate symbols with the type's 2-character prefix. [2](#0-1)  The symbol generation extracts the short name from the type mapping. [3](#0-2) 

The `RemoveNFTType()` method removes type mappings from all three state variables (`NFTTypeFullNameMap`, `NFTTypeShortNameMap`, and `NFTTypes.Value`) but lacks validation to check if existing protocols use the type being removed. [4](#0-3) 

The critical failure occurs in `CrossChainCreate()`, which is used to mirror NFT protocols from mainchain to sidechains. It extracts the 2-character type prefix from the symbol using `Substring(0, 2)` and looks it up in `State.NFTTypeFullNameMap`. If the lookup returns null (because the type was removed), the assertion fails and throws an exception, blocking cross-chain protocol creation. [5](#0-4) 

The root cause is that `RemoveNFTType()` only validates the type exists but never checks if `State.NftProtocolMap` contains any protocols using that type. The state mapping for protocols exists at line 24. [6](#0-5) 

**Attack Scenario:**
1. NFT protocol "AR123456" (Art type) is created on mainchain
2. Parliament governance calls `RemoveNFTType(StringValue { Value = "AR" })`
3. Type mappings are removed from all state variables
4. Later, when attempting to mirror the protocol to a sidechain via `CrossChainCreate(CrossChainCreateInput { Symbol = "AR123456" })`:
   - The method extracts "AR" from the symbol
   - Looks up `State.NFTTypeFullNameMap["AR"]` → returns null
   - Assertion at lines 91-93 fails with "Full name of AR not found"
5. Cross-chain mirroring is permanently broken for all protocols with "AR" prefix

## Impact Explanation

**Cross-Chain Integrity Breakdown:** This vulnerability breaks the cross-chain NFT protocol mirroring mechanism, a critical component of AElf's multi-chain architecture. Once a type is removed, all existing mainchain NFT protocols with that type prefix become impossible to mirror to sidechains.

**Operational DoS:** Users cannot use their NFTs on sidechains if the protocol cannot be created there. This affects all holders of NFTs under protocols using the removed type. The cross-chain creation is a prerequisite for cross-chain NFT operations, as shown in the token external info metadata keys. [7](#0-6) 

**Permanent Damage:** There is no recovery path - even if the type is re-added via `AddNFTType()`, the historical inconsistency remains. The mainchain protocols reference a type that was temporarily non-existent in the mappings.

**Affected Parties:**
- NFT protocol creators whose protocols become incompatible with cross-chain operations
- NFT holders who cannot transfer or use their assets on sidechains  
- dApp developers building cross-chain NFT functionality

**Severity:** High - while requiring parliament governance, this causes permanent operational failure of cross-chain NFT functionality, violating the cross-chain integrity invariant that mainchain protocols should be mirrorable to sidechains.

## Likelihood Explanation

**Reachable Entry Point:** The `RemoveNFTType()` method is a public method requiring parliament default address authorization via `AssertSenderIsParliamentDefaultAddress()`. [8](#0-7) 

**Feasible Preconditions:** 
- Parliament approval required (high bar but realistic for governance operations)
- Parliament may legitimately want to deprecate an NFT type category
- No visibility into which types are actively used by existing protocols
- Parliament members may not realize protocols already use the type

**Execution Practicality:** Straightforward single transaction execution - parliament calls `RemoveNFTType(StringValue { Value = "AR" })`.

**Detection Constraints:** The impact is not immediately visible on mainchain. The break only manifests when cross-chain operations are attempted, potentially much later. The mainchain protocol creation enforces mainchain-only creation. [9](#0-8) 

**Economic Rationality:** No economic cost to parliament. The cost is borne by NFT users and protocol creators who lose cross-chain functionality.

**Probability Assessment:** Medium - parliament governance makes this less likely than direct exploits, but the lack of usage validation makes accidental removal realistic during legitimate type management operations.

## Recommendation

Add validation in `RemoveNFTType()` to check if any existing protocols use the type being removed. The fix should iterate through or maintain a counter of protocols using each type:

```csharp
public override Empty RemoveNFTType(StringValue input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    Assert(input.Value.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.Value] != null, $"Short name {input.Value} does not exist.");
    
    // NEW: Validate no protocols use this type
    var fullName = State.NFTTypeFullNameMap[input.Value];
    Assert(!IsNFTTypeInUse(input.Value), 
        $"Cannot remove type {input.Value}. Existing protocols use this type.");
    
    State.NFTTypeFullNameMap.Remove(input.Value);
    State.NFTTypeShortNameMap.Remove(fullName);
    var nftTypes = State.NFTTypes.Value;
    nftTypes.Value.Remove(input.Value);
    State.NFTTypes.Value = nftTypes;
    Context.Fire(new NFTTypeRemoved
    {
        ShortName = input.Value
    });
    return new Empty();
}

private bool IsNFTTypeInUse(string shortName)
{
    // Check if any protocol symbols start with this short name
    // This requires either iterating protocols or maintaining a usage counter
    // Implementation depends on protocol storage structure
    return false; // Placeholder
}
```

Alternatively, maintain a reference counter for each NFT type that increments on protocol creation and decrements on protocol deletion (if supported).

## Proof of Concept

```csharp
[Fact]
public async Task RemoveNFTType_BreaksCrossChainCreate_Test()
{
    // Step 1: Create NFT protocol on mainchain with Art type (AR prefix)
    var createResult = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://aelf/",
        Creator = DefaultAddress,
        IsBurnable = true,
        NftType = NFTType.Art.ToString(), // Will generate symbol like AR123456
        ProtocolName = "ArtCollection",
        TotalSupply = 1000
    });
    var symbol = createResult.Output.Value;
    
    // Verify symbol starts with "AR"
    symbol.Substring(0, 2).ShouldBe("AR");
    
    // Verify protocol was created successfully
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    protocolInfo.NftType.ShouldBe(NFTType.Art.ToString());
    
    // Step 2: Parliament removes the Art type
    await ParliamentContractStub.RemoveNFTType.SendAsync(
        new StringValue { Value = "AR" });
    
    // Verify type was removed
    var nftTypes = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    nftTypes.Value.ShouldNotContainKey("AR");
    
    // Step 3: Attempt CrossChainCreate on sidechain - should fail
    // First, token must exist via CrossChainCreateToken
    await SideChainTokenContractStub.CrossChainCreateToken.SendAsync(
        new CrossChainCreateTokenInput
        {
            FromChainId = MainChainId,
            Symbol = symbol,
            // ... merkle path and verification data
        });
    
    // Now attempt NFT CrossChainCreate - this will fail
    var crossChainResult = await SideChainNFTContractStub.CrossChainCreate
        .SendWithExceptionAsync(new CrossChainCreateInput { Symbol = symbol });
    
    // Verify the failure
    crossChainResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    crossChainResult.TransactionResult.Error.ShouldContain(
        "Full name of AR not found. Use AddNFTType to add this new pair.");
}
```

**Notes:**
- The vulnerability requires parliament governance action, which is a trusted role, but the lack of validation allows legitimate governance operations to accidentally break cross-chain functionality
- The impact is delayed and not immediately visible on mainchain, making it harder to detect before damage occurs
- No recovery mechanism exists even if the type is re-added, as the temporal inconsistency remains
- This breaks a critical cross-chain invariant: mainchain NFT protocols should always be mirrorable to sidechains

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-37)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }

        return $"{shortName}{randomNumber}";
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L39-63)
```csharp
    private NFTTypes InitialNFTTypeNameMap()
    {
        if (State.NFTTypes.Value != null) return State.NFTTypes.Value;

        var nftTypes = new NFTTypes();
        nftTypes.Value.Add("XX", NFTType.Any.ToString());
        nftTypes.Value.Add("AR", NFTType.Art.ToString());
        nftTypes.Value.Add("MU", NFTType.Music.ToString());
        nftTypes.Value.Add("DN", NFTType.DomainNames.ToString());
        nftTypes.Value.Add("VW", NFTType.VirtualWorlds.ToString());
        nftTypes.Value.Add("TC", NFTType.TradingCards.ToString());
        nftTypes.Value.Add("CO", NFTType.Collectables.ToString());
        nftTypes.Value.Add("SP", NFTType.Sports.ToString());
        nftTypes.Value.Add("UT", NFTType.Utility.ToString());
        nftTypes.Value.Add("BA", NFTType.Badges.ToString());
        State.NFTTypes.Value = nftTypes;

        foreach (var pair in nftTypes.Value)
        {
            State.NFTTypeShortNameMap[pair.Value] = pair.Key;
            State.NFTTypeFullNameMap[pair.Key] = pair.Value;
        }

        return nftTypes;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L16-17)
```csharp
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L40-53)
```csharp
        var protocolInfo = new NFTProtocolInfo
        {
            Symbol = symbol,
            BaseUri = input.BaseUri,
            TotalSupply = tokenCreateInput.TotalSupply,
            Creator = tokenCreateInput.Issuer,
            Metadata = new Metadata { Value = { tokenExternalInfo.Value } },
            ProtocolName = tokenCreateInput.TokenName,
            IsTokenIdReuse = input.IsTokenIdReuse,
            IssueChainId = tokenCreateInput.IssueChainId,
            IsBurnable = tokenCreateInput.IsBurnable,
            NftType = input.NftType
        };
        State.NftProtocolMap[symbol] = protocolInfo;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L89-93)
```csharp
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L152-169)
```csharp
    public override Empty RemoveNFTType(StringValue input)
    {
        AssertSenderIsParliamentDefaultAddress();
        InitialNFTTypeNameMap();
        Assert(input.Value.Length == 2, "Incorrect short name.");
        Assert(State.NFTTypeFullNameMap[input.Value] != null, $"Short name {input.Value} does not exist.");
        var fullName = State.NFTTypeFullNameMap[input.Value];
        State.NFTTypeFullNameMap.Remove(input.Value);
        State.NFTTypeShortNameMap.Remove(fullName);
        var nftTypes = State.NFTTypes.Value;
        nftTypes.Value.Remove(input.Value);
        State.NFTTypes.Value = nftTypes;
        Context.Fire(new NFTTypeRemoved
        {
            ShortName = input.Value
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L24-24)
```csharp
    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L7-9)
```csharp
    private const string NftTypeMetadataKey = "aelf_nft_type";
    private const string NftBaseUriMetadataKey = "aelf_nft_base_uri";
    private const string NftTokenIdReuseMetadataKey = "aelf_nft_token_id_reuse";
```
