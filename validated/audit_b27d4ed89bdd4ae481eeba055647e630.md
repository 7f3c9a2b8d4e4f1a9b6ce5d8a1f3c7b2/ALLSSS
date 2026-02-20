# Audit Report

## Title
NFT Type Namespace Collision Allows Conflicting Bidirectional Mappings

## Summary
The `AddNFTType()` function contains incomplete validation logic that fails to prevent namespace collisions between short names and full names in the NFT type system. This allows a single string to exist simultaneously as both a short name (mapping to one full name) and as a full name (mapped from a different short name), corrupting the bidirectional mapping invariant and causing incorrect symbol generation and cross-chain type resolution.

## Finding Description

The NFT contract maintains two bidirectional state mappings to link 2-character short names with their full names. [1](#0-0) 

These mappings are initialized with default types like "AR" ↔ "Art", "MU" ↔ "Music" through the `InitialNFTTypeNameMap()` function. [2](#0-1) 

The vulnerability exists in the `AddNFTType()` validation logic. [3](#0-2) 

**Root Cause:**

The validation at line 137 checks that `input.ShortName` doesn't already exist as a key in `NFTTypeFullNameMap` (preventing duplicate short names).

The validation at line 138 checks that `input.FullName` doesn't already exist as a key in `NFTTypeShortNameMap` (preventing duplicate full names).

**The Missing Check:** The code never validates whether `input.FullName` already exists as a **key** in `NFTTypeFullNameMap` (i.e., is already used as a short name in the opposite direction).

**Exploit Scenario:**

Given initial state after `InitialNFTTypeNameMap()`:
- `NFTTypeFullNameMap["AR"] = "Art"`
- `NFTTypeShortNameMap["Art"] = "AR"`

Parliament approves: `AddNFTType(shortName="MX", fullName="AR")`

The validation checks pass because:
- Line 137: `NFTTypeFullNameMap["MX"]` is null ✓
- Line 138: `NFTTypeShortNameMap["AR"]` is null ✓ (since "AR" is a key in the OTHER map, not this one)

Result after execution:
- `NFTTypeFullNameMap["AR"] = "Art"` (old - unchanged)
- `NFTTypeFullNameMap["MX"] = "AR"` (new)
- `NFTTypeShortNameMap["Art"] = "AR"` (old - unchanged)  
- `NFTTypeShortNameMap["AR"] = "MX"` (new)

Now "AR" serves dual roles: as a short name (for "Art") AND as a full name (for "MX").

## Impact Explanation

**Severity: Medium** - The vulnerability corrupts a critical system invariant without causing direct fund loss.

**Concrete Operational Impacts:**

1. **Incorrect Symbol Generation:** When creating an NFT protocol with `nftType="AR"`, the `GetSymbol()` function looks up `NFTTypeShortNameMap[nftType]`. [4](#0-3)  After the collision, this returns "MX" instead of the expected behavior, generating symbols like "MX123456" instead of "AR123456". The stored `NFTProtocolInfo.NftType` will be "AR" but the symbol prefix will be "MX", breaking the type-to-symbol correspondence.

2. **Cross-Chain Type Resolution Confusion:** When `CrossChainCreate()` processes symbols, it extracts the short name prefix and retrieves the full name. [5](#0-4)  For symbols starting with "MX", it retrieves `NFTTypeFullNameMap["MX"]` which returns "AR", treating "AR" as a full name when it was originally a short name.

3. **Type Categorization Inconsistency:** NFT protocols lose reliable type-based categorization, affecting marketplaces, explorers, and applications that filter or organize NFTs by type.

**Affected Parties:**
- NFT protocol creators expecting consistent type mappings
- Cross-chain operations relying on symbol-to-type resolution
- NFT applications and marketplaces using type-based filtering

## Likelihood Explanation

**Likelihood: Medium** - Realistic governance error scenario.

**Preconditions:**
- Requires Parliament default address authorization [6](#0-5) 

**Feasibility:**
- This represents a validation gap where the contract's validation logic is incomplete
- The presence of validation checks at lines 137-138 indicates the developers intended to prevent namespace collisions
- Parliament members may approve `AddNFTType(shortName="MX", fullName="AR")` without realizing "AR" is already used as a short name
- The existing line 138 check creates false confidence that all namespace collisions are prevented
- The contract provides no helper functions to detect existing short name usage when validating a proposed full name

**Detection Difficulty:**
Governance would need to manually cross-reference proposed full names against existing short names, which is error-prone without tooling support.

## Recommendation

Add an additional validation check to prevent using an existing short name as a full name:

```csharp
public override Empty AddNFTType(AddNFTTypeInput input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    var fullName = input.FullName;
    Assert(input.ShortName.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.ShortName] == null, $"Short name {input.ShortName} already exists.");
    Assert(State.NFTTypeShortNameMap[fullName] == null, $"Full name {fullName} already exists.");
    // ADD THIS CHECK:
    Assert(State.NFTTypeFullNameMap[fullName] == null, $"Full name {fullName} is already used as a short name.");
    
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

## Proof of Concept

```csharp
[Fact]
public async Task AddNFTType_NamespaceCollision_Test()
{
    // Get default Parliament organization
    var defaultOrganization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Create proposal to add NFT type with fullName="AR" (which is already a short name)
    var proposalId = await CreateProposalAsync(
        NFTContractAddress,
        defaultOrganization,
        nameof(NFTContractStub.AddNFTType),
        new AddNFTTypeInput
        {
            ShortName = "MX",
            FullName = "AR" // "AR" is already used as short name for "Art"
        });
    
    // Approve and execute
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Verify namespace collision occurred
    var nftTypes = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    
    // Now "AR" exists in both mappings:
    // NFTTypeFullNameMap["AR"] = "Art" (as short name)
    // NFTTypeFullNameMap["MX"] = "AR" (as full name)
    // This causes GetSymbol("AR") to return "MX" prefix instead of correct behavior
    
    // Demonstrate impact: Create protocol with nftType="AR" produces wrong symbol
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ELF",
        Amount = 1_00000000_00000000,
        To = DefaultAddress
    });
    
    var result = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://test/",
        NftType = "AR", // Using "AR" as type
        ProtocolName = "Test Protocol",
        TotalSupply = 1000
    });
    
    var symbol = result.Output.Value;
    
    // Symbol should start with "AR" but will start with "MX" due to collision
    symbol.Substring(0, 2).ShouldBe("MX"); // Demonstrates the bug
}
```

## Notes

This vulnerability represents incomplete validation logic where the contract fails to enforce the bidirectional mapping invariant it explicitly attempts to maintain. The presence of validation checks indicates this is not an intended design but rather a gap in the validation implementation. While requiring Parliament authorization, the incomplete validation allows accidental creation of invalid state that corrupts protocol operations.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L35-36)
```csharp
    public MappedState<string, string> NFTTypeShortNameMap { get; set; }
    public MappedState<string, string> NFTTypeFullNameMap { get; set; }
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L89-93)
```csharp
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
