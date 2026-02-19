### Title
Orphaned NFT Protocols Break Cross-Chain Synchronization After Type Removal

### Summary
The `RemoveNFTType()` function removes NFT type mappings without validating whether existing protocols reference the type being removed. When protocols created with a now-removed type attempt cross-chain synchronization via `CrossChainCreate()`, the transaction fails at line 90 because the type mapping lookup returns null. This permanently breaks cross-chain functionality for all affected NFT protocols.

### Finding Description

The vulnerability exists in the `RemoveNFTType()` function which removes NFT type mappings from state without checking for existing protocol dependencies: [1](#0-0) 

When an NFT type is removed, the function only deletes entries from `NFTTypeFullNameMap`, `NFTTypeShortNameMap`, and `NFTTypes` but does NOT check or update existing protocols in `State.NftProtocolMap` that reference this type.

The `CrossChainCreate()` function attempts to synchronize mainchain protocols to sidechains by reconstructing protocol information. At line 89-93, it extracts the 2-character type prefix from the symbol and looks it up: [2](#0-1) 

When the type mapping has been removed, `State.NFTTypeFullNameMap[nftTypeShortName]` returns null, causing an assertion failure. The protocol information stored in `State.NftProtocolMap` on the mainchain contains the full type name: [3](#0-2) 

However, this stored information becomes "orphaned" and unusable for cross-chain operations because `CrossChainCreate` must independently reconstruct the type from the symbol prefix rather than reading it from cross-chain data.

### Impact Explanation

**Operational Disruption:** All NFT protocols created with a removed type (e.g., symbols starting with "AR" if Art type is removed) become permanently unable to synchronize to sidechains. This affects:

- **Existing Protocols:** Every protocol using the removed type loses cross-chain capability
- **NFT Transfers:** Cross-chain NFT transfers become impossible for affected protocols
- **Sidechain Operations:** Sidechains cannot create protocol entries needed for minting, burning, or transferring these NFTs
- **Irreversibility:** There is no function to update protocol information after creation

**Severity Justification:** High severity because:
1. Breaks core cross-chain functionality, a critical protocol feature
2. Affects all existing protocols with that type, not isolated to new creations
3. No recovery mechanism exists - protocols remain permanently broken on sidechains
4. Can occur through legitimate governance actions without malicious intent

### Likelihood Explanation

**Attack Complexity:** Low - requires only a single governance proposal execution through Parliament.

**Preconditions:**
- Parliament governance decides to remove an NFT type (realistic for deprecating unused types)
- One or more protocols have already been created using that type
- No validation prevents removing types that are actively in use

**Feasibility:** High likelihood because:
1. **Legitimate Use Case:** Governance may legitimately want to remove deprecated or unused type categories
2. **Hidden Dependencies:** No visibility into which protocols use each type, making accidental removal likely
3. **Governance Authority:** Parliament default address controls type management as intended
4. **No Warning System:** No check alerts governance that protocols depend on the type being removed

**Probability:** This can occur unintentionally during normal protocol maintenance when governance attempts to clean up the type registry without realizing protocols still reference removed types.

### Recommendation

Add a validation check in `RemoveNFTType()` to prevent removal of types that are referenced by existing protocols:

```csharp
public override Empty RemoveNFTType(StringValue input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    Assert(input.Value.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.Value] != null, 
        $"Short name {input.Value} does not exist.");
    
    // NEW: Validate no protocols use this type
    var fullName = State.NFTTypeFullNameMap[input.Value];
    var protocolCount = GetProtocolCountForType(fullName);
    Assert(protocolCount == 0, 
        $"Cannot remove type {fullName}. {protocolCount} protocol(s) still reference this type.");
    
    State.NFTTypeFullNameMap.Remove(input.Value);
    State.NFTTypeShortNameMap.Remove(fullName);
    var nftTypes = State.NFTTypes.Value;
    nftTypes.Value.Remove(input.Value);
    State.NFTTypes.Value = nftTypes;
    Context.Fire(new NFTTypeRemoved { ShortName = input.Value });
    return new Empty();
}
```

**Alternative Solution:** If type removal must be supported for protocols in use, modify `CrossChainCreate` to read the type from token external info rather than reconstructing from the symbol prefix, similar to how it reads `baseUri` and `isTokenIdReuse`: [4](#0-3) 

Store the NFT type in token external info during creation: [5](#0-4) 

### Proof of Concept

**Initial State (Mainchain - AELF):**
1. NFT type "AR" → "Art" exists (default initialization)
2. Protocol "AR123456-1" created with `nft_type="Art"` via `Create()`
3. Protocol stored in `State.NftProtocolMap["AR123456-1"]` with `NftType="Art"`
4. Token "AR123456-1" created in MultiToken contract

**Exploitation Steps:**
1. Parliament governance calls `RemoveNFTType("AR")`
   - Removes mapping: `NFTTypeFullNameMap["AR"]` 
   - Protocol "AR123456-1" remains in `NftProtocolMap` unchanged

**Impact on Sidechain:**
2. Token "AR123456-1" cross-chain indexed to sidechain
3. User calls `CrossChainCreate({symbol: "AR123456-1"})` on sidechain
4. Line 79 check passes (protocol doesn't exist on sidechain yet)
5. Lines 80-85: Token info retrieved successfully
6. Line 89: `nftTypeShortName = "AR"`
7. Line 90: `nftTypeFullName = State.NFTTypeFullNameMap["AR"]` returns **null**
8. Lines 91-93: Transaction **reverts** with error: "Full name of AR not found. Use AddNFTType to add this new pair."

**Result:** Protocol "AR123456-1" cannot be created on any sidechain, breaking all cross-chain NFT operations for this protocol permanently.

### Citations

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L87-88)
```csharp
        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L196-196)
```csharp
        tokenExternalInfo.Value[NftTypeMetadataKey] = input.NftType;
```
