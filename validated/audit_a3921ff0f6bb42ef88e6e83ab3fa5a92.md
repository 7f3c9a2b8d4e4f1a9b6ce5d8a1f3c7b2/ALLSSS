# Audit Report

## Title
Missing Character Validation in AddNFTType Enables DoS of NFT Protocol Creation

## Summary
The `AddNFTType` method only validates the length of short names (exactly 2 characters) but does not validate the character content. This allows governance to add NFT types with special characters that will subsequently fail MultiToken contract symbol validation, making it impossible to create NFT protocols of that type and causing a denial-of-service for that NFT category.

## Finding Description

The vulnerability stems from insufficient input validation in the NFT contract's `AddNFTType` method compared to the strict symbol validation enforced by the MultiToken contract.

**Root Cause - Insufficient Validation in AddNFTType:**

The `AddNFTType` method only validates that the short name is exactly 2 characters long but accepts any characters including special characters. [1](#0-0) 

**Symbol Generation - Concatenation:**

When creating an NFT protocol, the `GetSymbol` method retrieves the short name from storage and concatenates it with a random number to generate the protocol symbol. [2](#0-1) 

**MultiToken Validation - Entry Point:**

The generated symbol is then passed to the MultiToken contract's `Create` method, which calls `GetSymbolType` to validate the symbol. [3](#0-2) 

**Symbol Type Validation:**

The `GetSymbolType` method enforces strict validation using `IsValidCreateSymbol` on the symbol prefix. [4](#0-3) 

**Regex Validation:**

The `IsValidCreateSymbol` method uses a regex pattern that only allows alphanumeric characters. [5](#0-4) 

**Exploit Scenario:**

1. Parliament governance calls `AddNFTType` with input `{ FullName: "CustomType", ShortName: "@@" }`
2. The method accepts it (only checks `Length == 2`)
3. The mapping is stored: `NFTTypeShortNameMap["CustomType"] = "@@"`
4. A user attempts to create an NFT protocol: `Create({ NftType: "CustomType", ... })`
5. `GetSymbol` generates symbol: `"@@123456789"`
6. MultiToken's `Create` calls `GetSymbolType("@@123456789")`
7. `GetSymbolType` validates the prefix `"@@"` with `IsValidCreateSymbol("@@")`
8. Regex `^[a-zA-Z0-9]+$` fails to match `"@@"`
9. Assertion fails with "Invalid Symbol input"
10. NFT protocol creation is permanently blocked for this type

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
- The default NFT types use alphanumeric characters which don't alert governance to the restriction [6](#0-5) 
- No automated pre-flight validation exists to catch this during proposal review
- The validation gap is easily overlooked

**Probability:**
Medium likelihood due to reliance on governance oversight, but the validation inconsistency is subtle and easily missed without specific knowledge of MultiToken symbol validation rules.

## Recommendation

Add character validation to the `AddNFTType` method to ensure short names only contain alphanumeric characters, matching the MultiToken contract's requirements:

```csharp
public override Empty AddNFTType(AddNFTTypeInput input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    var fullName = input.FullName;
    Assert(input.ShortName.Length == 2, "Incorrect short name.");
    // Add alphanumeric validation
    Assert(IsValidCreateSymbol(input.ShortName), "Short name must contain only alphanumeric characters.");
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

private bool IsValidCreateSymbol(string symbol)
{
    return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AddNFTType_WithSpecialCharacters_ShouldPreventProtocolCreation()
{
    // 1. Parliament adds NFT type with special characters
    var parliamentStub = GetParliamentContractTester(DefaultSenderKeyPair);
    var nftContractAddress = await GetNFTContractAddress();
    
    var addNftTypeProposal = await parliamentStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        ToAddress = nftContractAddress,
        ContractMethodName = nameof(NFTContractContainer.NFTContractStub.AddNFTType),
        Params = new AddNFTTypeInput
        {
            FullName = "InvalidType",
            ShortName = "@@"  // Special characters
        }.ToByteString(),
        OrganizationAddress = await parliamentStub.GetDefaultOrganizationAddress.CallAsync(new Empty()),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    await ApproveAndReleaseProposal(parliamentStub, addNftTypeProposal.Output);
    
    // 2. Attempt to create NFT protocol with the invalid type
    var nftStub = GetNFTContractStub(DefaultSenderKeyPair);
    var createResult = await nftStub.Create.SendWithExceptionAsync(new CreateInput
    {
        NftType = "InvalidType",
        ProtocolName = "Test Protocol",
        TotalSupply = 10000,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF"),
        BaseUri = "https://test.com/"
    });
    
    // 3. Verify the creation fails with "Invalid Symbol input"
    createResult.TransactionResult.Error.ShouldContain("Invalid Symbol input");
}
```

**Notes:**

This vulnerability represents a validation gap between two system contracts. The NFT contract's `AddNFTType` only validates length, while the MultiToken contract enforces strict alphanumeric-only validation on symbols. This mismatch allows governance to inadvertently create unusable NFT types. The fix is straightforward: apply the same alphanumeric validation in `AddNFTType` that the MultiToken contract expects, preventing the creation of NFT types that cannot be used for protocol creation.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L136-136)
```csharp
        Assert(input.ShortName.Length == 2, "Incorrect short name.");
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
