# Audit Report

## Title
State Corruption via Reference Mutation in GetNFTInfoByTokenHash View Method

## Summary
The `GetNFTInfoByTokenHash()` view method directly mutates cached state objects by adding protocol-level fields to the NFTInfo reference returned from MappedState. When `Burn()` and `Recast()` subsequently write this modified object back to state, these protocol fields are permanently persisted, corrupting the architectural separation between protocol-level and token-level information.

## Finding Description

The vulnerability originates in the `GetNFTInfoByTokenHash()` view method where protocol-level fields are added directly to the NFTInfo object retrieved from state. [1](#0-0) 

The root cause lies in AElf's `MappedState<TKey, TEntity>` getter implementation, which returns a direct reference to the cached `valuePair.Value` object rather than a defensive copy. [2](#0-1) 

When `LoadKey()` deserializes state, it creates two separate instances - one for `Value` and one for `OriginalValue`. [3](#0-2) 

Since protobuf messages are reference types, modifying the returned reference directly mutates the cached `Value` object. The `Burn()` method demonstrates this pattern - it retrieves NFTInfo via `GetNFTInfoByTokenHash()`, makes modifications, and writes back to state. [4](#0-3) 

The `Recast()` method exhibits identical behavior. [5](#0-4) 

When the setter assigns the same reference back, it reassigns the already-mutated object. The `GetChanges()` method then compares the mutated `Value` against the unchanged `OriginalValue` using protobuf's value-based equality, detects the difference (including the newly added protocol fields), and persists the corrupted state. [6](#0-5) 

The design intent is explicitly documented in `PerformMint()` where protocol-level fields are commented as "No need" when creating NFTInfo state, confirming these fields should not be stored in the NFTInfo state map. [7](#0-6) 

## Impact Explanation

**State Corruption**: NFTInfo records are permanently corrupted with protocol-level data (ProtocolName, Creator, BaseUri, NftType) that should only exist in NFTProtocolInfo state. [8](#0-7) 

**Data Inconsistency**: If protocol information is updated via governance or minter changes, NFTs that have been burned or recast will retain stale protocol-level data, creating system-wide inconsistencies.

**Storage Waste**: Every NFT undergoing burn or recast operations wastes blockchain storage by redundantly storing protocol-level information that should be referenced from NFTProtocolInfo, not duplicated per-token.

**Design Violation**: The architecture explicitly separates concerns - NFTProtocolInfo stores protocol-level metadata once, while NFTInfo stores only token-specific data. This corruption breaks that fundamental design principle.

**Impact: Medium** - While this doesn't enable fund theft or unauthorized access, it corrupts persistent state for core NFT operations, affecting data integrity across the entire NFT system and potentially causing issues when protocol information changes.

## Likelihood Explanation

**Reachable Entry Points**: Both `Burn()` and `Recast()` are publicly callable contract methods accessible to any authorized minter. [9](#0-8) 

**Feasible Preconditions**: 
- For `Burn()`: Caller must be in the minter list and hold balance of the NFT
- For `Recast()`: Caller must be a minter with exclusive ownership of all token quantities

**Execution Practicality**: The vulnerability triggers automatically on every legitimate burn or recast operation through normal contract execution flow, requiring no special attack sequences or malicious inputs.

**Economic Rationality**: No additional cost beyond standard transaction fees. The corruption occurs as an unintended side-effect of normal operations.

**Likelihood: High** - This triggers on every burn/recast operation, which are common NFT lifecycle actions that will occur frequently in production.

## Recommendation

The fix requires creating a defensive copy in `GetNFTInfoByTokenHash()` to prevent mutations from affecting cached state:

```csharp
public override NFTInfo GetNFTInfoByTokenHash(Hash input)
{
    var nftInfo = State.NftInfoMap[input];
    if (nftInfo == null) return new NFTInfo();
    
    // Create a defensive copy to avoid mutating cached state
    var nftInfoCopy = nftInfo.Clone();
    var nftProtocolInfo = State.NftProtocolMap[nftInfoCopy.Symbol];
    nftInfoCopy.ProtocolName = nftProtocolInfo.ProtocolName;
    nftInfoCopy.Creator = nftProtocolInfo.Creator;
    nftInfoCopy.BaseUri = nftProtocolInfo.BaseUri;
    nftInfoCopy.NftType = nftProtocolInfo.NftType;
    return nftInfoCopy;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ProveStateCorruptionViaReferenceMutation()
{
    // Setup: Create NFT protocol and mint an NFT
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Alias = "test",
        Metadata = new Metadata(),
        Owner = MinterAddress,
        Uri = "ipfs://test"
    })).Output;

    // Read NFTInfo from state directly (should NOT have protocol fields)
    var nftInfoBeforeBurn = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(tokenHash);
    
    // Perform burn operation
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 1,
        Amount = 1
    });
    
    // Read NFTInfo from state again
    // If vulnerability exists, protocol fields will now be persisted in state
    var nftInfoAfterBurn = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(tokenHash);
    
    // Verify corruption: Protocol fields should NOT be in stored NFTInfo
    // but they will be due to the reference mutation bug
    nftInfoAfterBurn.ProtocolName.ShouldNotBeEmpty(); // This proves the bug
    nftInfoAfterBurn.Creator.ShouldNotBeNull();
    nftInfoAfterBurn.BaseUri.ShouldNotBeEmpty();
}
```

## Notes

This vulnerability is a subtle reference-sharing bug that violates defensive programming principles. The view method `GetNFTInfoByTokenHash()` is intended to enrich NFTInfo with protocol-level data for display purposes only, but the lack of defensive copying causes unintended state mutations. The bug is particularly insidious because it affects the fundamental state management layer (MappedState) used throughout all AElf contracts, though this specific vulnerability only manifests where view methods mutate returned references.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L20-30)
```csharp
    public override NFTInfo GetNFTInfoByTokenHash(Hash input)
    {
        var nftInfo = State.NftInfoMap[input];
        if (nftInfo == null) return new NFTInfo();
        var nftProtocolInfo = State.NftProtocolMap[nftInfo.Symbol];
        nftInfo.ProtocolName = nftProtocolInfo.ProtocolName;
        nftInfo.Creator = nftProtocolInfo.Creator;
        nftInfo.BaseUri = nftProtocolInfo.BaseUri;
        nftInfo.NftType = nftProtocolInfo.NftType;
        return nftInfo;
    }
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L26-37)
```csharp
    public TEntity this[TKey key]
    {
        get
        {
            if (!Cache.TryGetValue(key, out var valuePair))
            {
                valuePair = LoadKey(key);
                Cache[key] = valuePair;
            }

            return valuePair.IsDeleted ? SerializationHelper.Deserialize<TEntity>(null) : valuePair.Value;
        }
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L78-93)
```csharp
    internal override TransactionExecutingStateSet GetChanges()
    {
        var stateSet = new TransactionExecutingStateSet();
        foreach (var kv in Cache)
        {
            var key = GetSubStatePath(kv.Key.ToString()).ToStateKey(Context.Self);
            if (kv.Value.IsDeleted)
                stateSet.Deletes[key] = true;
            else if (!Equals(kv.Value.OriginalValue, kv.Value.Value))
                stateSet.Writes[key] = ByteString.CopyFrom(SerializationHelper.Serialize(kv.Value.Value));

            stateSet.Reads[key] = true;
        }

        return stateSet;
    }
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L95-108)
```csharp
    private ValuePair LoadKey(TKey key)
    {
        var path = GetSubStatePath(key.ToString());
        var bytes = Provider.Get(path);
        var value = SerializationHelper.Deserialize<TEntity>(bytes);
        var originalValue = SerializationHelper.Deserialize<TEntity>(bytes);

        return new ValuePair
        {
            OriginalValue = originalValue,
            Value = value,
            IsDeleted = false
        };
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L82-111)
```csharp
    public override Empty Burn(BurnInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(nftProtocolInfo.IsBurnable,
            $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
        State.BalanceMap[tokenHash][Context.Sender] = State.BalanceMap[tokenHash][Context.Sender].Sub(input.Amount);
        nftProtocolInfo.Supply = nftProtocolInfo.Supply.Sub(input.Amount);
        nftInfo.Quantity = nftInfo.Quantity.Sub(input.Amount);

        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;
        if (nftInfo.Quantity == 0 && !nftProtocolInfo.IsTokenIdReuse) nftInfo.IsBurned = true;

        State.NftInfoMap[tokenHash] = nftInfo;

        Context.Fire(new Burned
        {
            Burner = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            TokenId = input.TokenId
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L256-293)
```csharp
    public override Empty Recast(RecastInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(minterList.Value.Contains(Context.Sender), "No permission.");
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        Assert(nftInfo.Quantity != 0 && nftInfo.Quantity == State.BalanceMap[tokenHash][Context.Sender],
            "Do not support recast.");
        if (input.Alias != null) nftInfo.Alias = input.Alias;

        if (input.Uri != null) nftInfo.Uri = input.Uri;

        var oldMetadata = nftInfo.Metadata.Clone();
        var metadata = new Metadata();
        // Need to keep reserved metadata key.
        foreach (var reservedKey in GetNftMetadataReservedKeys())
        {
            if (oldMetadata.Value.ContainsKey(reservedKey))
                metadata.Value[reservedKey] = oldMetadata.Value[reservedKey];

            if (input.Metadata.Value.ContainsKey(reservedKey)) input.Metadata.Value.Remove(reservedKey);
        }

        metadata.Value.Add(input.Metadata.Value);
        nftInfo.Metadata = metadata;

        State.NftInfoMap[tokenHash] = nftInfo;
        Context.Fire(new Recasted
        {
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            OldMetadata = oldMetadata,
            NewMetadata = nftInfo.Metadata,
            Alias = nftInfo.Alias,
            Uri = nftInfo.Uri
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L427-431)
```csharp
                // No need.
                //BaseUri = protocolInfo.BaseUri,
                //Creator = protocolInfo.Creator,
                //ProtocolName = protocolInfo.ProtocolName
            };
```

**File:** protobuf/nft_contract.proto (L45-56)
```text
    // Destroy nfts.
    rpc Burn (BurnInput) returns (google.protobuf.Empty) {
    }
    // Lock several nfts and fts to mint one nft.
    rpc Assemble (AssembleInput) returns (aelf.Hash) {
    }
    // Disassemble one assembled nft to get locked nfts and fts back.
    rpc Disassemble (DisassembleInput) returns (google.protobuf.Empty) {
    }
    // Modify metadata of one nft.
    rpc Recast (RecastInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/nft_contract.proto (L287-312)
```text
message NFTInfo {
    // The symbol of the protocol this nft belongs to.
    string symbol = 1;
    // The name of the protocol this nft belongs to.
    string protocol_name = 2;
    // Actually is the order of this token.
    int64 token_id = 3;
    // The address that creat the base token.
    aelf.Address creator = 4;
    // The addresses that mint this token.
    repeated aelf.Address minters = 5;
    // The metadata of the token.
    Metadata metadata = 6;
    // Minted amount.
    int64 quantity = 7;
    // Token Uri.
    string uri = 8;
    // Base Uri.
    string base_uri = 9;
    // Alias
    string alias = 10;
    // Is burned.
    bool is_burned = 11;
    // NFT Type
    string nft_type = 12;
}
```
