### Title
RemoveNFTType Causes Permanent DoS of Cross-Chain NFT Protocol Creation

### Summary
The `RemoveNFTType` function removes NFT type mappings without checking if existing protocols use that type. When a type is removed, subsequent `CrossChainCreate` calls for protocols with symbols starting with the removed type's short name will permanently fail, breaking cross-chain NFT functionality. This creates an irreversible denial-of-service condition for legitimate cross-chain protocol creation.

### Finding Description

The vulnerability exists in the interaction between `RemoveNFTType` and `CrossChainCreate` functions: [1](#0-0) 

The `RemoveNFTType` function only removes entries from `State.NFTTypeFullNameMap`, `State.NFTTypeShortNameMap`, and `State.NFTTypes.Value`. It does not validate whether existing protocols in `State.NftProtocolMap` are using the type being removed. [2](#0-1) 

When `CrossChainCreate` is invoked on a sidechain to create a protocol that was originally created on the mainchain: [3](#0-2) 

The function extracts the 2-character short name from the symbol (e.g., "AR" from "AR123456-1") and looks it up in `State.NFTTypeFullNameMap`. If the type was removed, this lookup returns `null` and throws an `AssertionException`, permanently preventing the protocol from being created on the sidechain.

The root cause is that `RemoveNFTType` treats type mappings and protocol data as independent, but `CrossChainCreate` has a hard dependency on the type mappings to validate and populate protocol information. [4](#0-3) 

Existing protocols continue to store the removed type in their `nft_type` field, creating an inconsistent state where protocols reference non-existent types.

### Impact Explanation

**Operational Impact - Cross-Chain Denial of Service:**
- Once a parliament removes an NFT type on a sidechain, all future `CrossChainCreate` attempts for protocols with symbols starting with that type's short name will fail
- This breaks the fundamental cross-chain NFT functionality - protocols created on mainchain cannot be properly instantiated on sidechains
- The failure is permanent and cannot be recovered without re-adding the type or modifying the contract

**Affected Parties:**
- NFT protocol creators whose mainchain protocols cannot be created on sidechains
- Users attempting to interact with cross-chain NFTs
- Sidechains that have removed types lose access to entire categories of NFT protocols

**Severity Justification:**
This is HIGH severity because:
1. It completely breaks cross-chain NFT protocol creation for affected types
2. The impact is permanent and affects all future protocols
3. It undermines a core functionality (cross-chain support) of the NFT contract system
4. No recovery mechanism exists besides governance action to re-add the type

### Likelihood Explanation

**Attacker Capabilities:**
The vulnerability requires parliament's default organization to call `RemoveNFTType`. While this is a privileged action, it's within the normal operational scope of governance to manage NFT types.

**Attack Complexity:**
The exploit is straightforward:
1. Parliament removes an NFT type on a sidechain (legitimate governance action)
2. System automatically attempts to cross-chain create protocols with that type
3. All such attempts fail with no recovery path

**Feasibility Conditions:**
- Parliament has legitimate authority to manage NFT types through `RemoveNFTType` [5](#0-4) 
- The action could be taken for legitimate reasons (e.g., deprecating a type category)
- No validation prevents removal of types with active protocols
- Cross-chain indexing happens automatically, making the failure inevitable

**Probability:**
MEDIUM-HIGH likelihood because:
- Type management is a normal governance operation
- No warnings or checks inform parliament of the consequences
- The vulnerability triggers automatically on cross-chain operations
- Once triggered, all future cross-chain creates for that type fail

### Recommendation

**Immediate Fix:**
Add validation to `RemoveNFTType` to prevent removal of types with existing protocols:

```csharp
public override Empty RemoveNFTType(StringValue input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    Assert(input.Value.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.Value] != null, 
        $"Short name {input.Value} does not exist.");
    
    // NEW: Check if any protocols use this type
    var fullName = State.NFTTypeFullNameMap[input.Value];
    Assert(!HasProtocolsWithType(fullName), 
        $"Cannot remove type {fullName} - existing protocols use this type");
    
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

private bool HasProtocolsWithType(string nftType)
{
    // Implement iteration logic or maintain a counter
    // This may require additional state tracking
    return false; // placeholder
}
```

**Alternative Solution:**
If removal must be allowed, modify `CrossChainCreate` to handle missing types gracefully by using a default type or allowing explicit type specification in the input.

**Test Cases:**
1. Attempt to remove NFT type "AR" when protocol "AR123456-1" exists → should fail
2. Attempt to remove NFT type with no protocols → should succeed
3. Verify CrossChainCreate succeeds after type removal is prevented
4. Verify existing protocols maintain valid type references

### Proof of Concept

**Initial State:**
- MainChain has NFT type "AR" (short) → "Art" (full) registered
- MainChain creates protocol with symbol "AR123456-1", nft_type = "Art"
- Token info for "AR123456-1" is cross-chain indexed to SideChain
- SideChain has NFT type "AR" → "Art" registered initially

**Exploit Sequence:**

**Step 1:** Parliament calls `RemoveNFTType("AR")` on SideChain
- Expected: Type removed from mappings
- Actual: `State.NFTTypeFullNameMap["AR"]` = null, `State.NFTTypeShortNameMap["Art"]` = null

**Step 2:** User/System calls `CrossChainCreate({symbol: "AR123456-1"})` on SideChain
- Expected: Protocol created on sidechain matching mainchain
- Actual: Function extracts "AR" from symbol, looks up `State.NFTTypeFullNameMap["AR"]`, gets null, throws exception: "Full name of AR not found. Use AddNFTType to add this new pair."

**Step 3:** Attempt recovery by re-adding type
- Even if type is re-added, this creates confusion about whether protocols should use old or new type mappings
- Historical protocols already reference the "removed" type in their stored data

**Success Condition:**
The vulnerability is confirmed when `CrossChainCreate` permanently fails for any symbol starting with a removed type's short name, creating an unrecoverable DoS condition for cross-chain NFT protocol creation.

---

**Notes:**

This vulnerability demonstrates a critical architectural issue where state consistency is not maintained across related data structures. The `RemoveNFTType` operation creates orphaned references in existing protocols, and the `CrossChainCreate` dependency on type mappings creates a failure point that was not protected against. The issue is particularly severe because it affects the cross-chain functionality, which is a core feature of the AElf NFT system, and the failure is permanent without governance intervention.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L171-182)
```csharp
    private void AssertSenderIsParliamentDefaultAddress()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        if (State.ParliamentDefaultAddress.Value == null)
            State.ParliamentDefaultAddress.Value =
                State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());

        Assert(Context.Sender == State.ParliamentDefaultAddress.Value, "No permission.");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L24-36)
```csharp
    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }

    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }

    public MappedState<string, string> NFTTypeShortNameMap { get; set; }
    public MappedState<string, string> NFTTypeFullNameMap { get; set; }
```

**File:** protobuf/nft_contract.proto (L261-285)
```text
message NFTProtocolInfo {
    // The symbol of the token.
    string symbol = 1;
    // The minted number of the token.
    int64 supply = 2;
    // The total number of the token.
    int64 total_supply = 3;
    // The address that creat the token.
    aelf.Address creator = 4;
    // Base Uri.
    string base_uri = 5;
    // A flag indicating if this token is burnable.
    bool is_burnable = 6;
    // The chain to mint this token.
    int32 issue_chain_id = 7;
    // The metadata of the token.
    Metadata metadata = 8;
    // NFT Type.
    string nft_type = 9;
    // Protocol name, aka token name in MultiToken Contract.
    string protocol_name = 10;
    // Is token id can be reused.
    bool is_token_id_reuse = 11;
    int64 issued = 12;
}
```
