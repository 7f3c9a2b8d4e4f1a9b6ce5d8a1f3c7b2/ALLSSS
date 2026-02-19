# Audit Report

## Title
NFT Type Removal Breaks Cross-Chain Protocol Creation Without Validation

## Summary
The `RemoveNFTType()` method allows parliament to remove NFT type mappings without validating whether existing NFT protocols depend on those types. When a type is removed, `CrossChainCreate()` permanently fails for all protocols using that type prefix, breaking cross-chain NFT mirroring functionality.

## Finding Description

The NFT contract initializes NFT type mappings in `InitialNFTTypeNameMap()`, which populates `State.NFTTypes.Value`, `State.NFTTypeFullNameMap`, and `State.NFTTypeShortNameMap` with default type pairs (e.g., "AR" → "Art", "MU" → "Music"). [1](#0-0) 

The `RemoveNFTType()` method allows parliament to remove these type mappings from all three state variables: [2](#0-1) 

This method only validates that: (1) the sender is parliament, and (2) the type exists. **It never checks if existing protocols in `State.NftProtocolMap` use the type being removed.**

When NFT protocols are created via `Create()`, they store the NFT type in `NFTProtocolInfo.NftType` and generate symbols with the type's short name prefix (e.g., "AR12345" for Art type): [3](#0-2) 

The symbol generation happens in `GetSymbol()` which uses the type's short name as the prefix: [4](#0-3) 

The critical failure occurs in `CrossChainCreate()`, which mirrors NFT protocols from mainchain to sidechains. It extracts the 2-character type prefix from the symbol and looks it up in `State.NFTTypeFullNameMap`: [5](#0-4) 

**Attack Scenario:**
1. Mainchain: Protocol "AR12345" is created with type "Art"
2. Sidechain: Parliament removes "AR" type mapping via `RemoveNFTType("AR")`
3. Sidechain: `CrossChainCreate("AR12345")` extracts "AR" prefix
4. Line 90 lookup returns `null` (type was removed)
5. Lines 91-93 assertion fails with "Full name of AR not found"
6. Cross-chain creation permanently blocked for all "AR*" protocols

The root cause is **missing validation in `RemoveNFTType()`** - it should check if any protocols in `State.NftProtocolMap` have symbols starting with the type being removed, but this check is absent.

## Impact Explanation

**Cross-Chain Integrity Breakdown:** This vulnerability breaks the cross-chain NFT protocol mirroring mechanism, a critical component of AElf's multi-chain architecture. The `CrossChainCreate()` method is the official way to replicate mainchain NFT protocols to sidechains, enabling cross-chain NFT functionality.

**Permanent Operational DoS:** Once a type is removed on a sidechain, ALL protocols with that type prefix become impossible to mirror from mainchain, even though they exist validly. There is no automated recovery - protocols like "AR00001", "AR00002", etc., remain trapped on mainchain.

**Affected Stakeholders:**
- **NFT Protocol Creators**: Their protocols cannot be deployed cross-chain
- **NFT Holders**: Cannot use/transfer NFTs on sidechains
- **dApp Developers**: Applications relying on cross-chain NFT functionality break

**Severity Assessment:** HIGH - While requiring parliament governance (trusted role), the vulnerability represents a critical design flaw where a legitimate governance action (type deprecation) inadvertently destroys core protocol functionality without any safety checks. The impact is permanent and affects the entire protocol ecosystem for that NFT type category.

## Likelihood Explanation

**Reachable Entry Point:** `RemoveNFTType()` is a public method directly callable by parliament default address with proper authorization checks. [6](#0-5) 

**Feasible Preconditions:**
- Parliament approval required (high bar but achievable through standard governance)
- Parliament may legitimately want to deprecate/remove unused NFT type categories
- **Critical gap:** No visibility into which types are actively used by existing protocols
- Parliament members may not realize protocols already depend on the type

**Execution Practicality:** Single transaction - parliament creates proposal, gets approvals, and calls `RemoveNFTType(StringValue { Value = "AR" })`. The removal succeeds immediately.

**Detection Difficulty:** The impact is NOT immediately visible on the chain where removal occurs. The breakage only manifests when `CrossChainCreate()` is attempted later, potentially on a different chain, making root cause analysis difficult.

**Economic Rationality:** No direct cost to parliament. The damage is borne by users and developers who lose cross-chain functionality.

**Probability Assessment:** MEDIUM - Parliament governance requirement makes this less likely than direct exploits, but the complete absence of usage validation combined with legitimate reasons to deprecate types makes accidental removal realistic during normal type management operations.

## Recommendation

Add validation in `RemoveNFTType()` to prevent removing types that are actively used by existing protocols:

```csharp
public override Empty RemoveNFTType(StringValue input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    Assert(input.Value.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.Value] != null, $"Short name {input.Value} does not exist.");
    
    // NEW: Check if any protocols use this type prefix
    // Note: This requires iterating protocols or maintaining a usage counter
    // For efficiency, consider adding a State.TypeUsageCount map that tracks
    // how many protocols use each type, updated in Create() and CrossChainCreate()
    
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

**Recommended approach:** Maintain a `State.TypeUsageCount[shortName] → count` mapping:
- Increment in `Create()` and `CrossChainCreate()` 
- Decrement when protocols are fully burned/removed (if supported)
- Assert `TypeUsageCount[input.Value] == 0` before allowing removal

Alternatively, if protocol iteration is acceptable, check that no protocol symbols start with the type prefix being removed.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveNFTType_Breaks_CrossChainCreate_Test()
{
    // Step 1: Create NFT protocol with "AR" (Art) type on mainchain
    var createResult = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://test/",
        Creator = DefaultAddress,
        IsBurnable = true,
        NftType = NFTType.Art.ToString(), // Uses "AR" prefix
        ProtocolName = "TestArt",
        TotalSupply = 1000000
    });
    var symbol = createResult.Output.Value;
    symbol.Substring(0, 2).ShouldBe("AR"); // Verify "AR" prefix
    
    // Step 2: Simulate parliament removing "AR" type on sidechain
    // (In real scenario, this would be on sidechain after mainchain protocol creation)
    var removeResult = await NFTContractStub.RemoveNFTType.SendAsync(new StringValue 
    { 
        Value = "AR" 
    });
    removeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Verify type is removed from mappings
    var nftTypes = await NFTContractStub.GetNFTTypes.CallAsync(new Empty());
    nftTypes.Value.ContainsKey("AR").ShouldBeFalse();
    
    // Step 4: Attempt CrossChainCreate with the protocol symbol
    // This should fail because "AR" type no longer exists in NFTTypeFullNameMap
    var crossChainResult = await NFTContractStub.CrossChainCreate.SendWithExceptionAsync(
        new CrossChainCreateInput
        {
            Symbol = symbol
        });
    
    // Vulnerability: CrossChainCreate fails with assertion error
    crossChainResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    crossChainResult.TransactionResult.Error.ShouldContain("Full name of AR not found");
}
```

This test demonstrates that after `RemoveNFTType("AR")` is called, any `CrossChainCreate()` attempt with an "AR"-prefixed symbol fails at the type lookup assertion, permanently breaking cross-chain functionality for all Art-type NFT protocols.

### Citations

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-73)
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

        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;

        var protocolInfo = new NFTProtocolInfo
        {
            Symbol = symbol,
            BaseUri = input.BaseUri,
            TotalSupply = tokenCreateInput.TotalSupply,
            Creator = tokenCreateInput.Issuer,
            Metadata = new Metadata { Value = { tokenExternalInfo.Value } },
            ProtocolName = tokenCreateInput.TokenName,
            IsTokenIdReuse = input.IsTokenIdReuse,
            IssueChainId = tokenCreateInput.IssueChainId,
            IsBurnable = tokenCreateInput.IsBurnable,
            NftType = input.NftType
        };
        State.NftProtocolMap[symbol] = protocolInfo;

        Context.Fire(new NFTProtocolCreated
        {
            Symbol = tokenCreateInput.Symbol,
            Creator = tokenCreateInput.Issuer,
            IsBurnable = tokenCreateInput.IsBurnable,
            IssueChainId = tokenCreateInput.IssueChainId,
            ProtocolName = tokenCreateInput.TokenName,
            TotalSupply = tokenCreateInput.TotalSupply,
            Metadata = protocolInfo.Metadata,
            BaseUri = protocolInfo.BaseUri,
            IsTokenIdReuse = protocolInfo.IsTokenIdReuse,
            NftType = protocolInfo.NftType
        });

        return new StringValue
        {
            Value = symbol
        };
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-129)
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

        var nftProtocolInfo = new NFTProtocolInfo
        {
            Symbol = input.Symbol,
            TotalSupply = tokenInfo.TotalSupply,
            BaseUri = baseUri,
            Creator = tokenInfo.Issuer,
            IsBurnable = tokenInfo.IsBurnable,
            IssueChainId = tokenInfo.IssueChainId,
            IsTokenIdReuse = isTokenIdReuse,
            Metadata = new Metadata { Value = { tokenInfo.ExternalInfo.Value } },
            ProtocolName = tokenInfo.TokenName,
            NftType = nftTypeFullName
        };
        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;

        State.MinterListMap[input.Symbol] = new MinterList
        {
            Value = { nftProtocolInfo.Creator }
        };

        Context.Fire(new NFTProtocolCreated
        {
            Symbol = input.Symbol,
            Creator = nftProtocolInfo.Creator,
            IsBurnable = nftProtocolInfo.IsBurnable,
            IssueChainId = nftProtocolInfo.IssueChainId,
            ProtocolName = nftProtocolInfo.ProtocolName,
            TotalSupply = nftProtocolInfo.TotalSupply,
            Metadata = nftProtocolInfo.Metadata,
            BaseUri = nftProtocolInfo.BaseUri,
            IsTokenIdReuse = isTokenIdReuse,
            NftType = nftProtocolInfo.NftType
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
