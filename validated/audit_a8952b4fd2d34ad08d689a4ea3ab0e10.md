# Audit Report

## Title
Cross-Chain NFT Type Synchronization DOS - Custom NFT Types Cause CrossChainCreate Failure

## Summary
Custom NFT types added via `AddNFTType` on one chain are not automatically synchronized to other chains, causing `CrossChainCreate` to fail for any NFT protocol using those custom types. This creates a DOS condition where NFT protocols using custom types cannot be synced cross-chain until parliament manually adds the same custom type on each destination chain.

## Finding Description

The NFT contract stores NFT type mappings (short name to full name) in per-chain state variables. [1](#0-0) 

When `CrossChainCreate` is called on a destination chain, it initializes NFT type mappings by calling `InitialNFTTypeNameMap()`, which only adds 10 predefined types. [2](#0-1) 

The initialization function hardcodes only these default types: [3](#0-2) 

However, parliament can add custom NFT types via `AddNFTType`, which modifies state only on the current chain: [4](#0-3) 

The vulnerability manifests when `CrossChainCreate` extracts the 2-character NFT type short name from the symbol and looks it up in the destination chain's `State.NFTTypeFullNameMap`. If the custom type doesn't exist on the destination chain, the transaction fails: [5](#0-4) 

**Execution Path:**
1. MainChain: Parliament calls `AddNFTType` with custom type "GG" -> "Gaming" 
2. MainChain: User creates NFT protocol with Gaming type, receives symbol "GG123456789"
3. Cross-chain: MultiToken's `CrossChainCreateToken` syncs token info to SideChain (including all metadata)
4. SideChain: User calls NFT contract's `CrossChainCreate("GG123456789")`
5. SideChain: `InitialNFTTypeNameMap()` only initializes default types
6. SideChain: Lookup of "GG" in `State.NFTTypeFullNameMap` returns null
7. Transaction reverts with: "Full name of GG not found. Use AddNFTType to add this new pair."

The root cause is that NFT type mappings are stored as `MappedState` (per-chain state), and there is no automatic synchronization mechanism when types are added via `AddNFTType`.

## Impact Explanation

This vulnerability creates a **systematic operational DOS** affecting all NFT protocols that use custom types:

1. **Protocol Availability Impact:** Legitimate NFT protocols using custom types cannot function cross-chain, completely blocking users from accessing their NFT protocols on sidechains until governance intervention occurs.

2. **Governance Coordination Burden:** For each custom NFT type, parliament must create and approve proposals on EVERY destination chain where the protocol needs to operate. This creates significant coordination overhead and delays.

3. **Potential for Permanent DOS:** If sidechain governance is inactive, slow to respond, or uncooperative, NFT protocols remain permanently unavailable on that chain, effectively locking users out of their cross-chain functionality.

4. **User Experience Degradation:** Users attempting legitimate cross-chain operations receive cryptic error messages without understanding that a governance action is required, leading to confusion and support burden.

The severity is **High** because:
- It affects core cross-chain NFT functionality
- It requires multi-chain governance coordination to resolve
- It impacts all custom NFT types systematically
- The only resolution is manual governance action on each chain

## Likelihood Explanation

The likelihood is **High** because:

**No Attacker Required:** This is a design flaw that manifests during normal protocol operations. Any legitimate use of the custom NFT type feature triggers the issue.

**Minimal Complexity:**
- Parliament adds a custom NFT type on mainchain (expected and legitimate governance operation)
- Protocol creator uses the custom type (the explicit purpose of the `AddNFTType` feature)
- Cross-chain sync is attempted (standard protocol operation)

**Feasibility Conditions Met:**
- Custom NFT types are an explicit system feature with dedicated `AddNFTType` function
- Cross-chain protocol creation is a core use case
- No automatic synchronization mechanism exists

**Immediate Detection:** The issue is immediately visible when `CrossChainCreate` is called with a custom type, making this highly likely to occur once custom types are used in production.

## Recommendation

Implement one of the following solutions:

**Option 1: Automatic Cross-Chain Type Synchronization**
Modify `CrossChainCreate` to extract the NFT type from the token's ExternalInfo metadata (which is already synchronized via `CrossChainCreateToken`) and automatically add it to the local type mapping if it doesn't exist:

```csharp
public override Empty CrossChainCreate(CrossChainCreateInput input)
{
    MakeSureTokenContractAddressSet();
    InitialNFTTypeNameMap();
    Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
    
    var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput { Symbol = input.Symbol });
    if (string.IsNullOrEmpty(tokenInfo.Symbol))
        throw new AssertionException($"Token info {input.Symbol} not exists.");

    var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
    var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
    var nftTypeShortName = input.Symbol.Substring(0, 2);
    
    // NEW: Get full type name from token metadata (already synced cross-chain)
    var nftTypeFullName = tokenInfo.ExternalInfo.Value[NftTypeMetadataKey];
    
    // NEW: Auto-register the type if it doesn't exist locally
    if (State.NFTTypeFullNameMap[nftTypeShortName] == null)
    {
        State.NFTTypeFullNameMap[nftTypeShortName] = nftTypeFullName;
        State.NFTTypeShortNameMap[nftTypeFullName] = nftTypeShortName;
        var nftTypes = State.NFTTypes.Value;
        nftTypes.Value.Add(nftTypeShortName, nftTypeFullName);
        State.NFTTypes.Value = nftTypes;
    }
    
    // Continue with rest of function...
}
```

**Option 2: Validate Type Exists Before Protocol Creation**
On the mainchain, validate that custom types exist on all registered sidechains before allowing protocol creation with that type. This would prevent the DOS but requires more complex cross-chain coordination.

**Option 3: Relax Type Validation**
Allow `CrossChainCreate` to proceed even if the type mapping doesn't exist locally, using the type from the token's ExternalInfo. This maintains functionality but loses type validation guarantees.

**Recommended:** Option 1 provides the best balance of functionality and security by automatically synchronizing custom types during cross-chain protocol creation, eliminating the governance coordination burden.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreate_WithCustomNFTType_ShouldFail()
{
    // Setup: Simulate mainchain adding custom NFT type
    var mainChainNFTContract = GetMainChainNFTContractStub();
    await mainChainNFTContract.AddNFTType.SendAsync(new AddNFTTypeInput
    {
        ShortName = "GG",
        FullName = "Gaming"
    });
    
    // Create NFT protocol on mainchain with custom type
    var createResult = await mainChainNFTContract.Create.SendAsync(new CreateInput
    {
        NftType = "Gaming",
        ProtocolName = "Test Gaming NFT",
        BaseUri = "ipfs://test/",
        TotalSupply = 1000000
    });
    var symbol = createResult.Output.Value;
    
    // Verify symbol uses custom type prefix
    Assert.StartsWith("GG", symbol);
    
    // Simulate cross-chain token sync (MultiToken.CrossChainCreateToken)
    var sideChainTokenContract = GetSideChainTokenContractStub();
    await sideChainTokenContract.CrossChainCreateToken.SendAsync(/* merkle proof */);
    
    // Verify token exists on sidechain
    var tokenInfo = await sideChainTokenContract.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = symbol });
    Assert.NotNull(tokenInfo);
    
    // Attempt CrossChainCreate on sidechain WITHOUT adding custom type first
    var sideChainNFTContract = GetSideChainNFTContractStub();
    
    // This should FAIL with "Full name of GG not found"
    var exception = await Assert.ThrowsAsync<AssertionException>(async () =>
    {
        await sideChainNFTContract.CrossChainCreate.SendAsync(new CrossChainCreateInput
        {
            Symbol = symbol
        });
    });
    
    Assert.Contains("Full name of GG not found", exception.Message);
    Assert.Contains("Use AddNFTType to add this new pair", exception.Message);
}
```

**Notes:**
- The vulnerability is confirmed by examining the state variable definitions and the `CrossChainCreate` implementation
- NFT type mappings are explicitly per-chain state (`MappedState`) with no cross-chain synchronization
- The `InitialNFTTypeNameMap` function only initializes the 10 hardcoded default types
- The error message at line 93 explicitly confirms this is the expected behavior, treating it as a missing configuration rather than a bug
- However, from a protocol design perspective, this creates an operational DOS that requires multi-chain governance coordination

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L35-36)
```csharp
    public MappedState<string, string> NFTTypeShortNameMap { get; set; }
    public MappedState<string, string> NFTTypeFullNameMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L78-78)
```csharp
        InitialNFTTypeNameMap();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L89-93)
```csharp
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L131-149)
```csharp
    public override Empty AddNFTType(AddNFTTypeInput input)
    {
        AssertSenderIsParliamentDefaultAddress();
        InitialNFTTypeNameMap();
        var fullName = input.FullName;
        Assert(input.ShortName.Length == 2, "Incorrect short name.");
        Assert(State.NFTTypeFullNameMap[input.ShortName] == null, $"Short name {input.ShortName} already exists.");
        Assert(State.NFTTypeShortNameMap[fullName] == null, $"Full name {fullName} already exists.");
        State.NFTTypeFullNameMap[input.ShortName] = fullName;
        State.NFTTypeShortNameMap[fullName] = input.ShortName;
        var nftTypes = State.NFTTypes.Value;
        nftTypes.Value.Add(input.ShortName, fullName);
        State.NFTTypes.Value = nftTypes;
        Context.Fire(new NFTTypeAdded
        {
            ShortName = input.ShortName,
            FullName = input.FullName
        });
        return new Empty();
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
