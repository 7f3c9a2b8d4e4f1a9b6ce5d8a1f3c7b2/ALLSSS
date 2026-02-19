### Title
Cross-Chain NFT Type Synchronization DOS - Custom NFT Types Cause CrossChainCreate Failure

### Summary
Custom NFT types added via `AddNFTType` on one chain are not automatically synchronized to other chains, causing `CrossChainCreate` to fail for any NFT protocol using those custom types. This creates a DOS condition where NFT protocols created on the mainchain cannot be properly synced to sidechains until parliament manually adds the same custom type on each destination chain.

### Finding Description

The vulnerability exists in the `CrossChainCreate` function's handling of NFT type mappings across chains. [1](#0-0) 

At line 78, `InitialNFTTypeNameMap()` is called, which only initializes 10 predefined NFT types: [2](#0-1) 

However, the `AddNFTType` function allows parliament to add custom NFT types to the mapping: [3](#0-2) 

**Root Cause:**
When `CrossChainCreate` extracts the 2-character NFT type short name from the symbol (line 89) and looks it up in `State.NFTTypeFullNameMap` (line 90), it only finds types that have been explicitly added on the current chain. Custom types added via `AddNFTType` on the mainchain do not propagate to sidechains automatically. If the custom type doesn't exist on the destination chain, the function throws an exception at lines 91-93, completely blocking the cross-chain protocol creation.

**Execution Path:**
1. MainChain: Parliament calls `AddNFTType` to add custom type "GG" -> "Gaming"
2. MainChain: NFT protocol created with Gaming type, symbol = "GG123456"  
3. MainChain: MultiToken's `CrossChainCreateToken` syncs token to SideChain
4. SideChain: `CrossChainCreate("GG123456")` is called
5. SideChain: `InitialNFTTypeNameMap()` only initializes predefined types (XX, AR, MU, DN, VW, TC, CO, SP, UT, BA)
6. SideChain: Lookup of "GG" in `State.NFTTypeFullNameMap` returns null
7. Transaction fails: "Full name of GG not found. Use AddNFTType to add this new pair."

### Impact Explanation

**Operational DOS:** All NFT protocols using custom types cannot be synchronized to sidechains until parliament governance on EACH sidechain manually adds the same custom type via `AddNFTType`. This creates several concrete harms:

1. **Protocol Availability:** Legitimate NFT protocols cannot function cross-chain, blocking users from accessing their assets on sidechains
2. **Governance Coordination Burden:** Requires parliament proposals on every chain for each custom type, with associated delay and coordination costs
3. **Potential for Permanent DOS:** If sidechain governance is inactive or uncooperative, protocols remain permanently unavailable on that chain
4. **User Experience Degradation:** Users attempting cross-chain operations receive cryptic error messages without understanding the governance prerequisite

**Affected Parties:**
- NFT protocol creators using custom types
- Users holding NFTs that cannot be accessed cross-chain
- dApp developers relying on cross-chain NFT functionality

**Severity:** High - This is a systematic operational DOS affecting core cross-chain functionality, requiring multi-chain governance coordination to resolve.

### Likelihood Explanation

**Attacker Capabilities:** None required - this is a design flaw that manifests during normal protocol operations. Any legitimate use of custom NFT types triggers the issue.

**Attack Complexity:** Minimal
- Parliament adds a custom NFT type on mainchain (expected governance operation)
- Protocol creator uses the custom type (legitimate use case)
- Cross-chain sync attempt occurs (standard protocol operation)

**Feasibility Conditions:**
- Custom NFT types are an explicit feature of the system (`AddNFTType` function exists)
- Cross-chain protocol creation is a core use case
- No automatic synchronization mechanism exists for custom type mappings

**Detection/Operational Constraints:**
- Issue is immediately visible when `CrossChainCreate` is called
- Error message indicates the missing type, but requires governance intervention
- No workaround exists except parliament action on destination chain

**Probability:** High - As soon as any custom NFT type is added and used, all cross-chain operations for that type will fail until manual synchronization.

### Recommendation

**Immediate Fix:**
1. Document the requirement that custom NFT types must be added via `AddNFTType` on EACH chain before cross-chain protocol creation
2. Add a view function to check if an NFT type exists on the current chain
3. Modify `CrossChainCreate` to emit a specific event indicating which type is missing

**Long-term Solution:**
Implement automatic cross-chain synchronization of NFT type mappings:

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

    var nftTypeShortName = input.Symbol.Substring(0, 2);
    var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
    
    // NEW: If custom type not found, extract from token external info and auto-add
    if (nftTypeFullName == null)
    {
        var nftTypeFromToken = tokenInfo.ExternalInfo.Value["aelf_nft_type"];
        if (!string.IsNullOrEmpty(nftTypeFromToken))
        {
            // Auto-synchronize the custom type from cross-chain token info
            State.NFTTypeFullNameMap[nftTypeShortName] = nftTypeFromToken;
            State.NFTTypeShortNameMap[nftTypeFromToken] = nftTypeShortName;
            var nftTypes = State.NFTTypes.Value ?? new NFTTypes();
            nftTypes.Value.Add(nftTypeShortName, nftTypeFromToken);
            State.NFTTypes.Value = nftTypes;
            nftTypeFullName = nftTypeFromToken;
        }
        else
        {
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
        }
    }
    
    // Continue with rest of function...
}
```

**Test Cases:**
1. Create custom NFT type on chain A
2. Create protocol using custom type on chain A
3. Attempt `CrossChainCreate` on chain B without adding type - verify auto-sync or clear error
4. Verify custom type persists in State.NFTTypeFullNameMap after auto-sync

### Proof of Concept

**Initial State:**
- MainChain and SideChain both deployed with NFT contract
- Both chains have predefined types (XX, AR, MU, DN, VW, TC, CO, SP, UT, BA)

**Transaction Sequence:**

1. **MainChain - Add Custom Type:**
   ```
   ParliamentContract.Propose(AddNFTType{
       FullName: "Gaming",
       ShortName: "GG"
   })
   // Vote and execute proposal
   ```

2. **MainChain - Create Protocol:**
   ```
   NFTContract.Create({
       NftType: "Gaming",
       ProtocolName: "GameItems",
       TotalSupply: 1000000,
       ...
   })
   // Returns symbol: "GG123456"
   ```

3. **Cross-Chain Token Sync:**
   ```
   MultiTokenContract.CrossChainCreateToken({
       FromChainId: MainChain,
       Symbol: "GG123456"
   })
   // Token info successfully synced to SideChain
   ```

4. **SideChain - Attempt Protocol Sync:**
   ```
   NFTContract.CrossChainCreate({
       Symbol: "GG123456"
   })
   ```

**Expected Result:** Protocol created successfully on SideChain

**Actual Result:** Transaction reverts with error: "Full name of GG not found. Use AddNFTType to add this new pair."

**Success Condition:** Transaction should complete without requiring separate `AddNFTType` governance action on SideChain, OR system should provide clear documentation and tooling for synchronizing custom types across chains.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-93)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L131-150)
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
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L39-62)
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
```
