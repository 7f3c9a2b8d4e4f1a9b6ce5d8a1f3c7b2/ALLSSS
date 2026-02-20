# Audit Report

## Title
Missing Character Validation in AddNFTType Enables DoS of NFT Protocol Creation

## Summary
The `AddNFTType` method validates only the length of short names but not their character content, allowing governance to add NFT types with special characters. These invalid types cause NFT protocol creation to fail at the MultiToken contract's symbol validation, resulting in a permanent DoS for that NFT category until governance removes it.

## Finding Description

The vulnerability exists due to a validation inconsistency between the NFT and MultiToken contracts.

The `AddNFTType` method performs only length validation on the short name: [1](#0-0) 

This validation accepts any 2-character string, including special characters like "@@", "!!", "**", etc. When an NFT protocol is subsequently created, the `GetSymbol` method concatenates this short name with a random number: [2](#0-1) 

The resulting symbol (e.g., "@@123456789") is passed to the MultiToken contract's `Create` method: [3](#0-2) 

The MultiToken contract routes the request through `GetSymbolType`, which validates the symbol prefix: [4](#0-3) 

The validation uses `IsValidCreateSymbol`, which enforces a strict alphanumeric-only regex pattern: [5](#0-4) [6](#0-5) 

When the symbol contains special characters, the regex `^[a-zA-Z0-9]+$` fails, throwing "Invalid Symbol input" and blocking NFT protocol creation.

## Impact Explanation

**Operational Denial-of-Service:**
- Any NFT type added with non-alphanumeric characters becomes permanently unusable
- All user attempts to create NFT protocols of that type fail with "Invalid Symbol input"
- The invalid NFT type remains in state until removed via `RemoveNFTType`
- Wastes governance resources as a new proposal is required to fix the issue
- Degrades user experience and prevents legitimate protocol creation for that category

**Severity:** Medium - Causes operational DoS for specific NFT categories without directly affecting funds. The issue is reversible through governance but impacts protocol availability and user operations.

## Likelihood Explanation

**Governance Oversight Scenario:**
- Requires Parliament default organization to submit and approve an `AddNFTType` proposal with special characters
- Can occur through honest mistake or lack of awareness of downstream validation requirements
- Default NFT types demonstrate alphanumeric patterns that may not alert governance to the strict requirement: [7](#0-6) 

- No automated validation exists during proposal creation or approval
- The issue only manifests when users attempt to create NFT protocols, not during the AddNFTType call itself

**Likelihood:** Medium - Relies on governance oversight rather than malicious intent, but the validation gap is easily overlooked without understanding the complete execution flow across both contracts.

## Recommendation

Add character validation to the `AddNFTType` method to ensure short names contain only alphanumeric characters, matching the MultiToken contract's requirements:

```csharp
public override Empty AddNFTType(AddNFTTypeInput input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    var fullName = input.FullName;
    Assert(input.ShortName.Length == 2, "Incorrect short name.");
    // Add character validation
    Assert(Regex.IsMatch(input.ShortName, "^[a-zA-Z0-9]+$"), 
        "Short name must contain only alphanumeric characters.");
    Assert(State.NFTTypeFullNameMap[input.ShortName] == null, 
        $"Short name {input.ShortName} already exists.");
    Assert(State.NFTTypeShortNameMap[fullName] == null, 
        $"Full name {fullName} already exists.");
    // ... rest of method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AddNFTType_WithSpecialCharacters_CausesCreateFailure()
{
    // Step 1: Add NFT type with special characters via governance
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var proposalId = await CreateProposalAsync(
        NFTContractAddress,
        defaultParliament,
        nameof(NFTContractStub.AddNFTType),
        new AddNFTTypeInput
        {
            ShortName = "@@",  // Special characters
            FullName = "InvalidType"
        });
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Step 2: Attempt to create NFT protocol with the invalid type
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.Create.SendAsync(new CreateInput
        {
            BaseUri = "ipfs://test/",
            NftType = "InvalidType",  // Uses the invalid type
            ProtocolName = "TEST",
            TotalSupply = 1000000
        });
    });
    
    // Verify it fails with MultiToken validation error
    exception.Message.ShouldContain("Invalid Symbol input");
}
```

## Notes

This vulnerability demonstrates a validation gap between two contracts that creates an operational DoS condition. While requiring governance action to trigger, the issue represents a legitimate security concern as it breaks the protocol invariant that NFT types should be usable for protocol creation. The fix is straightforward: align the validation rules between the NFT and MultiToken contracts by adding character validation to `AddNFTType`.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L34-34)
```csharp
        State.TokenContract.Create.Send(tokenCreateInput);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L136-136)
```csharp
        Assert(input.ShortName.Length == 2, "Incorrect short name.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L36-36)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L35-35)
```csharp
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
