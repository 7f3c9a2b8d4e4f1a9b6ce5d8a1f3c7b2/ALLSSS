### Title
RemoveNFTType Breaks Cross-Chain Protocol Creation for Existing NFT Protocols

### Summary
The `RemoveNFTType()` function removes NFT type mappings from `NFTTypeFullNameMap` without verifying whether any existing protocols use that type. When protocols created on the mainchain with the removed type attempt cross-chain synchronization via `CrossChainCreate()`, the operation fails permanently, breaking critical cross-chain functionality for all affected protocols.

### Finding Description

The vulnerability exists in the `RemoveNFTType()` function which removes NFT type mappings: [1](#0-0) 

The function removes entries from both `NFTTypeFullNameMap` (line 159) and `NFTTypeShortNameMap` (line 160) without any validation that the type is not currently in use by existing protocols.

**Root Cause**: The contract uses a `MappedState<string, NFTProtocolInfo>` to store protocols, which does not support enumeration. There is no mechanism to iterate through all protocols to check if any use the type being removed: [2](#0-1) 

**Why Existing Protections Fail**: The only validation in `RemoveNFTType()` is that the short name exists (line 157), but not whether it's actively used by any protocols.

**Execution Path**: When `CrossChainCreate()` attempts to synchronize a protocol to a sidechain, it extracts the 2-character short name from the protocol symbol and looks it up in `NFTTypeFullNameMap`: [3](#0-2) 

If the type has been removed, this lookup returns null and throws an exception, permanently preventing the protocol from being created on any sidechain.

### Impact Explanation

**Operational DoS of Cross-Chain Functionality**: All NFT protocols created on the mainchain with a removed type can no longer be synchronized to sidechains. This breaks the cross-chain NFT protocol creation flow, which is a core feature of the AElf ecosystem.

**Affected Parties**: 
- Protocol creators who cannot expand to sidechains
- Users who cannot access NFT protocols on sidechains
- The entire cross-chain NFT ecosystem

**Severity Justification**: HIGH - While existing protocols on already-synchronized chains continue functioning (they store their own `NftType` value), any protocol not yet created on a sidechain becomes permanently unable to synchronize. This violates the "Consensus & Cross-Chain" critical invariant requiring correct cross-chain proof verification and operations. The only recovery requires Parliament action to re-add the type, causing downtime and potential confusion if different mappings are used.

### Likelihood Explanation

**Attacker Capabilities**: Requires Parliament default organization authorization to call `RemoveNFTType()`: [4](#0-3) 

**Attack Complexity**: LOW - Single function call with Parliament authorization.

**Feasibility Conditions**: This is not a traditional "attack" but rather a governance action with severe unintended consequences. Parliament could legitimately vote to remove a type they believe is unused, unaware that protocols on the mainchain depend on it for cross-chain synchronization.

**Probability**: MEDIUM - While requiring governance action, the lack of visibility into which types are actively used makes accidental removal realistic during protocol cleanup or reorganization.

### Recommendation

**Code-Level Mitigation**:
1. Add a reference counter to track how many protocols use each NFT type
2. Modify `RemoveNFTType()` to check the counter and reject removal if non-zero
3. Increment the counter in `Create()` when a protocol is created with a type
4. Store the counter in contract state: `MappedState<string, long> NFTTypeUsageCount`

**Invariant Check**:
```csharp
public override Empty RemoveNFTType(StringValue input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    Assert(input.Value.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.Value] != null, $"Short name {input.Value} does not exist.");
    
    // NEW CHECK: Ensure type is not in use
    var usageCount = State.NFTTypeUsageCount[input.Value];
    Assert(usageCount == 0, $"Cannot remove type {input.Value}: {usageCount} protocol(s) still using it.");
    
    var fullName = State.NFTTypeFullNameMap[input.Value];
    State.NFTTypeFullNameMap.Remove(input.Value);
    State.NFTTypeShortNameMap.Remove(fullName);
    // ... rest of removal logic
}
```

**Test Cases**:
- Test removing an unused type (should succeed)
- Test removing a type with active protocols (should fail)
- Test cross-chain creation after attempted removal of in-use type (should succeed since removal was blocked)

### Proof of Concept

**Initial State**: Mainchain and sidechain both operational, NFT contract deployed on both.

**Transaction Steps**:

1. **Create Protocol on Mainchain** (as any user):
   - Call `Create()` with `NftType = "VirtualWorlds"` (maps to short name "VW")
   - Protocol created with symbol "VW123456"
   - Protocol stored in mainchain with `NFTProtocolInfo.NftType = "VirtualWorlds"`

2. **Remove NFT Type** (as Parliament):
   - Call `RemoveNFTType("VW")`
   - Succeeds - `NFTTypeFullNameMap["VW"]` is now null
   - `NFTTypeShortNameMap["VirtualWorlds"]` is now null

3. **Attempt Cross-Chain Creation** (as any user):
   - Call `CrossChainCreate(symbol: "VW123456")` on sidechain
   - At line 89: extracts `nftTypeShortName = "VW"` from symbol
   - At line 90: `nftTypeFullName = State.NFTTypeFullNameMap["VW"]` returns **null**
   - At lines 91-93: throws `AssertionException("Full name of VW not found. Use AddNFTType to add this new pair.")`

**Expected Result**: Protocol should be created on sidechain successfully.

**Actual Result**: Cross-chain creation fails with assertion error. Protocol "VW123456" can never be synchronized to the sidechain until Parliament re-adds the "VW" type mapping.

**Success Condition**: The exploit succeeds if `CrossChainCreate()` throws an exception after `RemoveNFTType()` is called for a type that existing protocols use.

### Citations

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
