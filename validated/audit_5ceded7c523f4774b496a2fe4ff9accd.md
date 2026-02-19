# Audit Report

## Title
InitialNFTTypeNameMap Fails to Re-initialize After All NFT Types Are Removed, Causing Permanent DoS of NFT Creation

## Summary
The `InitialNFTTypeNameMap()` function contains a flawed null check that fails to detect when the NFT type collection is empty. If Parliament removes all default NFT types using `RemoveNFTType()`, the initialization logic returns early without repopulating the required mappings, permanently breaking the `Create()` and `CrossChainCreate()` functions until Parliament manually re-adds types.

## Finding Description
The vulnerability stems from an insufficient guard condition in `InitialNFTTypeNameMap()` that only checks if the `State.NFTTypes.Value` object is null, but does not verify whether its internal collection contains any entries. [1](#0-0) 

The `NFTTypes` protobuf message contains a map field, where the object itself can be non-null while the map is empty: [2](#0-1) 

**Exploitation Path:**

1. During initial usage, `InitialNFTTypeNameMap()` creates 10 default NFT type mappings and populates both `State.NFTTypes.Value` and the bidirectional mapping states: [3](#0-2) 

2. Parliament legitimately calls `RemoveNFTType()` to remove all default types (e.g., for deprecation or reorganization): [4](#0-3) 

Each removal deletes entries from `State.NFTTypeFullNameMap`, `State.NFTTypeShortNameMap`, and `State.NFTTypes.Value.Value`. After removing all types, `State.NFTTypes.Value` is a non-null object with an empty map.

3. When a user attempts to create an NFT via `Create()`, the code calls `GetSymbol()`: [5](#0-4) 

4. In `GetSymbol()`, the lookup fails because the maps are empty, triggering a call to `InitialNFTTypeNameMap()`: [6](#0-5) 

5. However, the guard at line 41 detects that `State.NFTTypes.Value != null` and returns early, skipping the reinitialization logic entirely.

6. Back in `GetSymbol()`, the `shortName` remains null, causing an `AssertionException` at line 33.

7. The same vulnerability affects `CrossChainCreate()`: [7](#0-6) 

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
Recovery requires manual Parliament intervention through multiple `AddNFTType()` transactions: [8](#0-7) 

During the recovery period (which could take significant time due to governance procedures), the contract remains in a DoS state.

## Likelihood Explanation
**Likelihood: MEDIUM** - Requires Parliament action but realistic through legitimate governance operations.

**Feasible Preconditions:**
- Requires Parliament default address authorization (legitimate trusted role)
- Parliament could legitimately remove types for valid reasons:
  - Deprecation of certain NFT categories
  - Reorganization of type taxonomy
  - Policy changes or contract upgrades
- No malicious intent required - can occur through governance mistakes

**Execution Practicality:**
- Simple execution: Parliament calls `RemoveNFTType()` 10 times (one per default type)
- Each call is authorized for Parliament: [9](#0-8) 

- Once triggered, affects all users attempting NFT creation
- Consequences are severe and unexpected

## Recommendation
Modify the guard condition in `InitialNFTTypeNameMap()` to check both for null object and empty collection:

```csharp
private NFTTypes InitialNFTTypeNameMap()
{
    // Check if the object is null OR if the collection is empty
    if (State.NFTTypes.Value != null && State.NFTTypes.Value.Value.Count > 0) 
        return State.NFTTypes.Value;
    
    // Reinitialize if null or empty
    var nftTypes = new NFTTypes();
    nftTypes.Value.Add("XX", NFTType.Any.ToString());
    // ... rest of initialization
}
```

Alternatively, set `State.NFTTypes.Value = null` when the last type is removed in `RemoveNFTType()`:

```csharp
public override Empty RemoveNFTType(StringValue input)
{
    // ... existing code ...
    nftTypes.Value.Remove(input.Value);
    
    // If all types removed, set to null to allow reinitialization
    if (nftTypes.Value.Count == 0)
        State.NFTTypes.Value = null;
    else
        State.NFTTypes.Value = nftTypes;
    
    // ... rest of code ...
}
```

## Proof of Concept
```csharp
[Fact]
public async Task InitialNFTTypeNameMap_DoS_After_All_Types_Removed()
{
    // Step 1: Initialize NFT contract (first call populates types)
    var createInput = new CreateInput
    {
        NftType = NFTType.Art.ToString(),
        ProtocolName = "TestNFT",
        TotalSupply = 1000,
        BaseUri = "https://test.com/",
        IsBurnable = true
    };
    
    // First create succeeds - initializes types
    var result = await NFTContractStub.Create.SendAsync(createInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 2: Parliament removes all 10 default NFT types
    var parliamentStub = GetParliamentContractStub();
    var nftTypes = new[] { "XX", "AR", "MU", "DN", "VW", "TC", "CO", "SP", "UT", "BA" };
    
    foreach (var type in nftTypes)
    {
        await parliamentStub.RemoveNFTType.SendAsync(new StringValue { Value = type });
    }
    
    // Verify State.NFTTypes.Value is non-null but empty
    var retrievedTypes = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    retrievedTypes.ShouldNotBeNull(); // Object exists
    retrievedTypes.Value.Count.ShouldBe(0); // But map is empty
    
    // Step 3: Attempt to create another NFT - should fail permanently
    var secondCreateInput = new CreateInput
    {
        NftType = NFTType.Music.ToString(),
        ProtocolName = "TestNFT2",
        TotalSupply = 500,
        BaseUri = "https://test2.com/",
        IsBurnable = true
    };
    
    // This will throw: "Short name of NFT Type Music not found"
    var exception = await Assert.ThrowsAsync<AssertionException>(
        async () => await NFTContractStub.Create.SendAsync(secondCreateInput)
    );
    
    exception.Message.ShouldContain("Short name of NFT Type");
    
    // Verify CrossChainCreate also fails
    var crossChainInput = new CrossChainCreateInput
    {
        Symbol = "AR123456" // Assuming this format
    };
    
    var crossChainException = await Assert.ThrowsAsync<AssertionException>(
        async () => await NFTContractStub.CrossChainCreate.SendAsync(crossChainInput)
    );
    
    crossChainException.Message.ShouldContain("Full name of");
}
```

## Notes
This vulnerability demonstrates a critical edge case in state management where an object can exist but be functionally empty. The guard condition was designed to prevent redundant initialization but inadvertently blocks necessary reinitialization after legitimate governance actions. The issue is exacerbated because there's no automatic recovery mechanism - Parliament must manually re-add all types to restore functionality.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L28-33)
```csharp
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L39-41)
```csharp
    private NFTTypes InitialNFTTypeNameMap()
    {
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

**File:** protobuf/nft_contract.proto (L104-105)
```text
message NFTTypes {
    map<string, string> value = 1;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-20)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L152-163)
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
