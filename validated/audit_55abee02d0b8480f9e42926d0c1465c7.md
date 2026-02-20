# Audit Report

## Title
Missing Character Validation in AddNFTType Enables DoS of NFT Protocol Creation

## Summary
The `AddNFTType` method in the NFT contract only validates the length of short names (exactly 2 characters) but does not validate the character content. This allows governance to inadvertently add NFT types with special characters (e.g., "@@", "!!", "**") that will fail downstream MultiToken contract symbol validation, permanently preventing the creation of NFT protocols for that type and causing a denial-of-service for that NFT category.

## Finding Description

The vulnerability stems from insufficient input validation in the `AddNFTType` method. [1](#0-0) 

The method only checks that the short name is exactly 2 characters long (`Assert(input.ShortName.Length == 2, "Incorrect short name.")`) but accepts any characters, allowing special characters like "@", "!", "*", "#" to be stored in the NFT type mappings.

When a user later attempts to create an NFT protocol, the `GetSymbol` method retrieves the short name and concatenates it with a random number to generate the protocol symbol. [2](#0-1) 

This generated symbol (e.g., "@@123456789" if short name is "@@") is then passed to the MultiToken contract's `Create` method. [3](#0-2) 

The MultiToken contract's `Create` method calls `GetSymbolType` to validate the symbol. [4](#0-3) 

The `GetSymbolType` method validates the symbol prefix using `IsValidCreateSymbol` and throws "Invalid Symbol input" if validation fails. [5](#0-4) 

The `IsValidCreateSymbol` method uses a strict regex pattern (`^[a-zA-Z0-9]+$`) that only allows alphanumeric characters. [6](#0-5) 

When special characters are present in the symbol prefix, the regex validation fails, causing the assertion to throw and preventing the NFT protocol from being created.

The default NFT types initialized in the system all use alphanumeric characters (XX, AR, MU, DN, VW, TC, CO, SP, UT, BA), which may not alert governance to the validation requirements. [7](#0-6) 

## Impact Explanation

**Operational Impact - DoS:**
- Any NFT type added with special characters in its short name becomes permanently unusable
- All users attempting to create NFT protocols of that type will fail with "Invalid Symbol input" error
- The governance action to add the NFT type is wasted
- Requires another governance proposal to remove it via `RemoveNFTType` and add a corrected version
- Disrupts protocol functionality and user experience for that specific NFT category

**Affected Parties:**
- Users attempting to create NFT protocols of the invalid type
- Protocol operators who must coordinate additional governance actions to remediate
- Overall protocol usability and trust in governance processes

**Severity Assessment:**
This is a **Medium** severity issue because:
1. It causes clear operational DoS for specific NFT type categories
2. It requires governance oversight/error rather than direct attacker exploitation
3. It's reversible through governance actions but causes operational disruption
4. It doesn't directly affect funds but significantly impacts protocol functionality

## Likelihood Explanation

**Trigger Conditions:**
- Requires ability to submit and pass a Parliament governance proposal for `AddNFTType`
- Can occur through honest mistake or lack of awareness by governance proposers
- No automated validation exists to catch this during proposal review

**Attack Complexity:**
- Low complexity: Simply submit `AddNFTType` with special characters in the 2-character short name
- The validation gap is straightforward to trigger
- No sophisticated techniques required

**Probability Assessment:**
Medium likelihood because:
- Relies on governance oversight, but this is a realistic scenario
- Proposers may not be aware of downstream MultiToken validation requirements
- All default NFT types use alphanumeric characters, providing no indication of the constraint
- No validation exists at the point of adding the NFT type to catch the error early

## Recommendation

Add character validation to the `AddNFTType` method to ensure the short name only contains alphanumeric characters, matching the MultiToken contract's symbol validation requirements:

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
    // ... rest of the method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AddNFTType_WithSpecialCharacters_CausesProtocolCreationFailure()
{
    // Step 1: Parliament adds NFT type with special characters
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var addNFTTypeInput = new AddNFTTypeInput
    {
        ShortName = "@@",  // Special characters that pass length check
        FullName = "InvalidType"
    };
    
    var proposalId = await CreateProposalAsync(
        NFTContractAddress,
        defaultParliament,
        nameof(NFTContractStub.AddNFTType),
        addNFTTypeInput);
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Step 2: Attempt to create NFT protocol with this type
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.Create.SendAsync(new CreateInput
        {
            BaseUri = "ipfs://test/",
            NftType = "InvalidType",  // Uses the type with @@ short name
            ProtocolName = "TEST",
            TotalSupply = 1_000_000
        });
    });
    
    // Step 3: Verify it fails with symbol validation error
    exception.Message.ShouldContain("Invalid Symbol input");
}
```

**Notes:**
- The vulnerability is confirmed through code analysis of the complete execution path
- The issue represents a validation gap between NFT and MultiToken contracts
- While it requires governance action to trigger, governance oversight is a realistic threat scenario
- The DoS is specific to the misconfigured NFT type and doesn't affect existing valid types
- Remediation requires a governance proposal to remove the invalid type and add a corrected version

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-34)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
        var tokenExternalInfo = GetTokenExternalInfo(input);
        var creator = input.Creator ?? Context.Sender;
        var tokenCreateInput = new MultiToken.CreateInput
        {
            Symbol = symbol,
            Decimals = 0, // Fixed
            Issuer = creator,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId,
            TokenName = input.ProtocolName,
            TotalSupply = input.TotalSupply,
            ExternalInfo = tokenExternalInfo
        };
        State.TokenContract.Create.Send(tokenCreateInput);
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L33-46)
```csharp
    public override Empty Create(CreateInput input)
    {
        var inputSymbolType = GetSymbolType(input.Symbol);
        if (input.Owner == null)
        {
            input.Owner = input.Issuer;
        }
        return inputSymbolType switch
        {
            SymbolType.NftCollection => CreateNFTCollection(input),
            SymbolType.Nft => CreateNFTInfo(input),
            _ => CreateToken(input)
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L28-31)
```csharp
    private bool IsValidCreateSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
    }
```
