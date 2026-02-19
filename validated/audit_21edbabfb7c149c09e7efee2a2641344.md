# Audit Report

## Title
NFT Protocol Creation Accepts Empty Address Values Leading to Permanent Protocol Bricking

## Summary
The NFT contract's `Create` method fails to validate that `input.Creator` has a non-empty `Address.Value` field before using it as the token issuer. Combined with insufficient validation in the MultiToken contract's `RegisterTokenInfo` method, this allows creation of NFT protocols with invalid issuer addresses (empty byte values), permanently bricking the protocol as no one can mint NFTs or manage the minter list.

## Finding Description

The vulnerability exists in the NFT creation flow across two contracts with a clear validation inconsistency:

**Insufficient Creator Validation in NFT Contract:**

The `Create` method uses a null-coalescing operator to set the creator. [1](#0-0)  This only checks if `input.Creator` is null, but does not validate whether the Address object has an empty `Value` field (ByteString). If a caller passes `new Address()` or `new Address { Value = ByteString.Empty }`, this is a non-null Address object that bypasses the null check, resulting in `creator` being set to an invalid empty-value address.

This invalid creator is then passed to the MultiToken contract as the `Issuer`. [2](#0-1) 

**Incomplete RegisterTokenInfo Validation:**

The `RegisterTokenInfo` method in the MultiToken contract only validates that the issuer is not null. [3](#0-2)  It does not check if the `Address.Value` field is empty. This is inconsistent with the proper validation pattern used elsewhere in the same contract, such as in `ModifyTokenIssuerAndOwner` which correctly validates both conditions. [4](#0-3) 

**Protocol Becomes Permanently Unusable:**

Once created with an empty-value issuer, the protocol cannot be used:

1. **Minting Fails**: The `GetMinterList` helper adds the empty-value issuer to the minter list. [5](#0-4)  However, the minting permission check fails because `Context.Sender` (a valid address) will never equal the empty-value address. [6](#0-5) 

2. **Minter Management Fails**: The `AddMinters` and `RemoveMinters` methods require the caller to equal the protocol creator, [7](#0-6) [8](#0-7)  which will always fail for any real sender when the creator has an empty value.

## Impact Explanation

**Severity: High/Critical**

This vulnerability enables permanent denial-of-service attacks against NFT protocol functionality:

1. **Complete Protocol Bricking**: Any NFT protocol created with an empty-value creator becomes permanently unusable - no NFTs can ever be minted, and the minter list cannot be modified.

2. **Economic Damage**: 
   - Attackers can intentionally brick protocols, wasting the creation fees/costs paid by legitimate users
   - If the attacker front-runs a legitimate NFT protocol creation, the intended creator loses their fees and must create under a different symbol

3. **Griefing Attack Vector**: Malicious actors can systematically brick popular NFT symbol names or types, causing operational disruption and user frustration.

4. **No Recovery Mechanism**: Unlike some protocol configuration issues that can be fixed through governance, there is no mechanism to recover from this state. The protocol creator address is immutably set in the NFTProtocolInfo structure. [9](#0-8) 

## Likelihood Explanation

**Probability: High**

This vulnerability is highly exploitable:

1. **Reachable Entry Point**: The `Create` method is a public function callable by any user. [10](#0-9) 

2. **Low Attack Complexity**: Exploitation requires only sending a `CreateInput` message with `Creator = new Address()` (an Address object with empty Value). This is trivial to construct in any AElf transaction.

3. **No Special Permissions Required**: Any user can call the Create method - the only barrier is passing the seed NFT check or being in the create whitelist, which is necessary for any protocol creation.

4. **Low Attack Cost**: The cost is merely the NFT creation fee/seed NFT, making griefing attacks economically viable.

5. **Undetectable Until Too Late**: The protocol appears to be created successfully - the vulnerability only manifests when users attempt to mint or manage minters, at which point the damage is already done.

## Recommendation

Add proper validation for empty `Address.Value` in both the NFT contract and MultiToken contract to match the validation pattern already used in `ModifyTokenIssuerAndOwner`:

**In NFTContract_Create.cs line 22**, change:
```csharp
var creator = input.Creator ?? Context.Sender;
```

To:
```csharp
var creator = (input.Creator != null && !input.Creator.Value.IsNullOrEmpty()) 
    ? input.Creator 
    : Context.Sender;
```

**In TokenContract_Helper.cs line 230**, change:
```csharp
Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
```

To:
```csharp
Assert(tokenInfo.Issuer != null && !tokenInfo.Issuer.Value.IsNullOrEmpty(), "Invalid issuer address.");
```

Similarly, update line 231 for the Owner validation:
```csharp
Assert(tokenInfo.Owner != null && !tokenInfo.Owner.Value.IsNullOrEmpty(), "Invalid owner address.");
```

## Proof of Concept

```csharp
[Fact]
public async Task NFT_Create_WithEmptyAddressValue_ShouldBrickProtocol()
{
    // Attacker creates an NFT protocol with empty-value creator
    var emptyCreator = new Address { Value = ByteString.Empty };
    
    var createInput = new CreateInput
    {
        NftType = "Art",
        ProtocolName = "BrickedNFT",
        TotalSupply = 10000,
        Creator = emptyCreator,  // Empty-value address, but NOT null
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF"),
        BaseUri = "https://example.com/",
        IsTokenIdReuse = false
    };
    
    // Protocol creation succeeds (shouldn't!)
    var result = await NFTContractStub.Create.SendAsync(createInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var symbol = result.Output.Value;
    
    // Now try to mint - this will FAIL permanently
    var mintInput = new MintInput
    {
        Symbol = symbol,
        Alias = "Test",
        Quantity = 1,
        Uri = "https://example.com/1"
    };
    
    // This assertion will fail because Context.Sender can never equal empty-value address
    var mintResult = await NFTContractStub.Mint.SendWithExceptionAsync(mintInput);
    mintResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    mintResult.TransactionResult.Error.ShouldContain("No permission to mint");
    
    // Try to add minters - also FAILS permanently
    var addMintersInput = new AddMintersInput
    {
        Symbol = symbol,
        MinterList = new MinterList { Value = { DefaultAddress } }
    };
    
    var addResult = await NFTContractStub.AddMinters.SendWithExceptionAsync(addMintersInput);
    addResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    addResult.TransactionResult.Error.ShouldContain("No permission");
    
    // Protocol is permanently bricked - no recovery possible
}
```

## Notes

The validation inconsistency between `RegisterTokenInfo` (which only checks `!= null`) and `ModifyTokenIssuerAndOwner` (which checks both `!= null` and `!Value.IsNullOrEmpty()`) clearly demonstrates this is an oversight rather than intentional design. The correct validation pattern already exists in the codebase but was not consistently applied to all address inputs during token/protocol creation.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-14)
```csharp
    public override StringValue Create(CreateInput input)
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L22-22)
```csharp
        var creator = input.Creator ?? Context.Sender;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L23-34)
```csharp
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L40-53)
```csharp
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L230-230)
```csharp
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L646-646)
```csharp
        Assert(input.Issuer != null && !input.Issuer.Value.IsNullOrEmpty(), "Invalid input issuer.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L338-338)
```csharp
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L358-358)
```csharp
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L375-381)
```csharp
    private MinterList GetMinterList(TokenInfo tokenInfo)
    {
        var minterList = State.MinterListMap[tokenInfo.Symbol] ?? new MinterList();
        if (!minterList.Value.Contains(tokenInfo.Issuer)) minterList.Value.Add(tokenInfo.Issuer);

        return minterList;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L399-399)
```csharp
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
