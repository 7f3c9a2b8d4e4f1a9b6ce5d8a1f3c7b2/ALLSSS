# Audit Report

## Title
InitialNFTTypeNameMap Fails to Re-initialize After All NFT Types Are Removed, Causing Permanent DoS of NFT Creation

## Summary
The `InitialNFTTypeNameMap()` function contains a flawed guard condition that only checks if the `State.NFTTypes.Value` object is null, but does not verify whether its internal map collection is empty. After Parliament removes all default NFT types via `RemoveNFTType()`, subsequent calls to `Create()` and `CrossChainCreate()` permanently fail because the initialization logic returns early without repopulating the required type mappings.

## Finding Description
The vulnerability originates from an insufficient null check in the `InitialNFTTypeNameMap()` helper function that validates object existence but not map population. [1](#0-0) 

The `NFTTypes` protobuf message structure contains a map field where the object instance can be non-null while the internal map is empty. [2](#0-1) 

**Exploitation Path:**

1. During initial contract usage, `InitialNFTTypeNameMap()` creates 10 default NFT type mappings and populates both the singleton state and bidirectional mapping states. [3](#0-2) 

2. Parliament legitimately calls `RemoveNFTType()` to remove all default types (e.g., for deprecation or reorganization). This method is authorized for Parliament's default address. [4](#0-3) 

   Each removal deletes entries from `State.NFTTypeFullNameMap`, `State.NFTTypeShortNameMap`, and `State.NFTTypes.Value.Value` (the internal map). After removing all 10 types, `State.NFTTypes.Value` remains a non-null object with an empty map.

3. When a user attempts to create an NFT via `Create()`, the code calls `GetSymbol()` to generate the protocol symbol. [5](#0-4) 

4. In `GetSymbol()`, the lookup in `State.NFTTypeShortNameMap` fails because the map is empty, triggering a call to `InitialNFTTypeNameMap()`. [6](#0-5) 

5. However, the guard at line 41 detects that `State.NFTTypes.Value != null` and returns early, skipping the reinitialization logic entirely.

6. Back in `GetSymbol()`, the `shortName` remains null, causing an `AssertionException` at line 33 with the message "Short name of NFT Type {nftType} not found."

7. The same vulnerability affects `CrossChainCreate()`, which also relies on the type mappings. [7](#0-6) 

## Impact Explanation
**Severity: HIGH** - Complete operational DoS of core NFT contract functionality.

**Operational Impact:**
- All calls to `Create()` fail with "Short name of NFT Type {nftType} not found"
- All calls to `CrossChainCreate()` fail with "Full name of {nftTypeShortName} not found"
- No new NFT protocols can be created across the entire system
- Cross-chain NFT protocol synchronization becomes impossible

**Affected Parties:**
- All users attempting to create new NFT protocols
- Developers and applications relying on NFT functionality
- Cross-chain NFT operations are completely blocked

**Recovery:**
Recovery requires manual Parliament intervention through multiple `AddNFTType()` transactions to repopulate the type mappings. [8](#0-7) 

During the recovery period (which could take significant time due to governance procedures requiring proposal creation, approval, and execution), the contract remains in a DoS state.

## Likelihood Explanation
**Likelihood: MEDIUM** - Requires Parliament action but realistic through legitimate governance operations.

**Feasible Preconditions:**
- Requires Parliament default address authorization (legitimate trusted role)
- Parliament could legitimately remove types for valid reasons:
  - Deprecation of certain NFT categories
  - Reorganization of type taxonomy
  - Policy changes or contract upgrades
- No malicious intent required - can occur through governance mistakes or incomplete planning

**Execution Practicality:**
- Simple execution: Parliament calls `RemoveNFTType()` 10 times (once per default type)
- Each call is properly authorized through the Parliament authorization check. [9](#0-8) 
- Once triggered, affects all users attempting NFT creation
- Consequences are severe and unexpected

## Recommendation
Modify the guard condition in `InitialNFTTypeNameMap()` to check both object nullity and map population:

```csharp
private NFTTypes InitialNFTTypeNameMap()
{
    if (State.NFTTypes.Value != null && State.NFTTypes.Value.Value.Count > 0) 
        return State.NFTTypes.Value;
    
    // Existing initialization logic...
}
```

Alternatively, check if any of the bidirectional maps are populated:

```csharp
private NFTTypes InitialNFTTypeNameMap()
{
    if (State.NFTTypes.Value != null) 
    {
        // Verify at least one type exists in the mappings
        if (State.NFTTypeShortNameMap[NFTType.Any.ToString()] != null)
            return State.NFTTypes.Value;
    }
    
    // Existing initialization logic...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task RemoveAllNFTTypes_CausesCreateDoS()
{
    // Step 1: Get Parliament authorization
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Step 2: Get initial NFT types
    var initialTypes = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    initialTypes.Value.Count.ShouldBe(10); // 10 default types exist
    
    // Step 3: Parliament removes all 10 NFT types
    var typeShortNames = initialTypes.Value.Keys.ToList();
    foreach (var shortName in typeShortNames)
    {
        var proposalId = await CreateProposalAsync(
            NFTContractAddress,
            defaultParliament,
            nameof(NFTContractStub.RemoveNFTType),
            new StringValue { Value = shortName }
        );
        await ApproveWithMinersAsync(proposalId);
        await ParliamentContractStub.Release.SendAsync(proposalId);
    }
    
    // Step 4: Verify all types are removed
    var typesAfterRemoval = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    typesAfterRemoval.Value.Count.ShouldBe(0); // All types removed
    
    // Step 5: Attempt to create NFT - should fail with AssertionException
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.Create.SendAsync(new CreateInput
        {
            BaseUri = "ipfs://test/",
            Creator = DefaultAddress,
            IsBurnable = true,
            NftType = "VirtualWorlds",
            ProtocolName = "TEST_PROTOCOL",
            TotalSupply = 1000
        });
    });
    
    exception.Message.ShouldContain("Short name of NFT Type VirtualWorlds not found");
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L28-34)
```csharp
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L41-41)
```csharp
        if (State.NFTTypes.Value != null) return State.NFTTypes.Value;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L43-60)
```csharp
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
```

**File:** protobuf/nft_contract.proto (L104-106)
```text
message NFTTypes {
    map<string, string> value = 1;
}
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L20-20)
```csharp
        var symbol = GetSymbol(input.NftType);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L78-93)
```csharp
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
