# Audit Report

## Title
Missing Character Validation in AddNFTType Enables DoS of NFT Protocol Creation

## Summary
The `AddNFTType` method only validates the length of short names (exactly 2 characters) but does not validate the character content. This allows governance to add NFT types with special characters that will subsequently fail MultiToken contract symbol validation, making it impossible to create NFT protocols of that type and causing a denial-of-service for that NFT category.

## Finding Description

The vulnerability stems from insufficient input validation in the NFT contract's `AddNFTType` method compared to the strict symbol validation enforced by the MultiToken contract.

**Root Cause - Insufficient Validation in AddNFTType:**

The `AddNFTType` method only validates that the short name is exactly 2 characters long but accepts any characters including special characters: [1](#0-0) 

**Symbol Generation - Concatenation:**

When creating an NFT protocol, the `GetSymbol` method retrieves the short name from storage and concatenates it with a random number to generate the protocol symbol: [2](#0-1) 

**MultiToken Validation - Strict Regex:**

The generated symbol is then passed to the MultiToken contract's `Create` method, which calls `GetSymbolType` to validate the symbol: [3](#0-2) 

The `GetSymbolType` method enforces strict validation using `IsValidCreateSymbol`: [4](#0-3) 

The `IsValidCreateSymbol` method uses a regex pattern that only allows alphanumeric characters: [5](#0-4) 

**Exploit Scenario:**

1. Parliament governance calls `AddNFTType` with input `{ FullName: "CustomType", ShortName: "@@" }`
2. The method accepts it (only checks `Length == 2`)
3. The mapping is stored: `NFTTypeShortNameMap["CustomType"] = "@@"`
4. A user attempts to create an NFT protocol: `Create({ NftType: "CustomType", ... })`
5. `GetSymbol` generates symbol: `"@@123456789"`
6. MultiToken's `GetSymbolType` validates the prefix `"@@"` with `IsValidCreateSymbol("@@")`
7. Regex `^[a-zA-Z0-9]+$` fails to match `"@@"`
8. Assertion fails with "Invalid Symbol input"
9. NFT protocol creation is permanently blocked for this type

## Impact Explanation

This vulnerability causes a **Medium severity operational DoS**:

**Operational Impact:**
- Any NFT type added with special characters becomes permanently unusable
- All attempts to create NFT protocols of that type will fail with "Invalid Symbol input"
- The invalid NFT type entry wastes a governance action and requires remediation via `RemoveNFTType`
- Users cannot utilize that NFT category until governance fixes it through another proposal

**Affected Parties:**
- Users attempting to create NFT protocols of the invalid type
- Protocol operators who must coordinate additional governance actions
- Overall protocol usability and trust

**Why Medium Severity:**
- Clear DoS of specific functionality (NFT protocol creation for that type)
- Requires governance oversight (not direct attacker exploitation)
- Reversible through governance but causes disruption
- No direct fund loss but impacts protocol availability

## Likelihood Explanation

This is a **Medium likelihood** vulnerability:

**Attack Vector:**
- Requires Parliament governance to add an NFT type with special characters
- Can occur through malicious proposal or honest oversight/mistake
- No sophisticated exploitation techniques needed

**Feasibility:**
- Governance proposers may not be aware of downstream MultiToken validation requirements
- The default NFT types use alphanumeric characters (AR, MU, VW, TC, etc.) which don't alert governance to the restriction: [6](#0-5) 

- No automated pre-flight validation exists to catch this during proposal review
- The validation gap is easily overlooked

**Probability:**
Medium likelihood due to reliance on governance oversight, but the validation inconsistency is subtle and easily missed without specific knowledge of MultiToken symbol validation rules.

## Recommendation

Add character validation to `AddNFTType` to ensure short names only contain alphanumeric characters, matching the downstream MultiToken contract requirements:

```csharp
public override Empty AddNFTType(AddNFTTypeInput input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    var fullName = input.FullName;
    Assert(input.ShortName.Length == 2, "Incorrect short name.");
    // Add character validation
    Assert(Regex.IsMatch(input.ShortName, "^[a-zA-Z0-9]+$"), "Short name must contain only alphanumeric characters.");
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

This ensures consistency between NFT type registration and MultiToken symbol validation requirements.

## Proof of Concept

```csharp
[Fact]
public async Task AddNFTType_WithSpecialCharacters_CausesCreateToFail()
{
    // Step 1: Add NFT type with special characters via Parliament
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    var addNFTTypeInput = new AddNFTTypeInput
    {
        FullName = "SpecialType",
        ShortName = "@@"  // Special characters
    };
    
    var proposalId = await CreateProposalAsync(
        NFTContractAddress,
        defaultParliament,
        nameof(NFTContractStub.AddNFTType),
        addNFTTypeInput
    );
    
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Step 2: Verify NFT type was added (only length validation)
    var nftTypes = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    nftTypes.Value["@@"].ShouldBe("SpecialType");
    
    // Step 3: Attempt to create NFT protocol of this type
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.Create.SendAsync(new CreateInput
        {
            BaseUri = "ipfs://test/",
            Creator = DefaultAddress,
            IsBurnable = true,
            NftType = "SpecialType",  // Uses the invalid NFT type
            ProtocolName = "TEST",
            TotalSupply = 1000000
        });
    });
    
    // Step 4: Verify it fails with "Invalid Symbol input"
    exception.Message.ShouldContain("Invalid Symbol input");
    
    // This proves DoS: NFT protocols of type "SpecialType" cannot be created
}
```

**Notes:**

The vulnerability is confirmed through direct code analysis showing the validation inconsistency between `AddNFTType` (length-only check) and `IsValidCreateSymbol` (alphanumeric-only regex). The default NFT types all use alphanumeric short names, which may not alert governance to this validation requirement when adding custom types. While reversible via `RemoveNFTType`, this requires additional governance coordination and causes operational disruption for the affected NFT category.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L136-136)
```csharp
        Assert(input.ShortName.Length == 2, "Incorrect short name.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L28-36)
```csharp
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }

        return $"{shortName}{randomNumber}";
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L44-53)
```csharp
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L33-35)
```csharp
    public override Empty Create(CreateInput input)
    {
        var inputSymbolType = GetSymbolType(input.Symbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L10-10)
```csharp
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L28-31)
```csharp
    private bool IsValidCreateSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
    }
```
