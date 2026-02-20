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

The `RegisterTokenInfo` method in the MultiToken contract only validates that the issuer is not null. [3](#0-2)  It does not check if the `Address.Value` field is empty. This is inconsistent with the proper validation pattern used elsewhere in the same contract, such as in `AssertValidInputAddress` [4](#0-3)  and `ModifyTokenIssuerAndOwner` which correctly validates both conditions. [5](#0-4) 

**Protocol Becomes Permanently Unusable:**

Once created with an empty-value issuer, the protocol cannot be used:

1. **Minting Fails**: The `GetMinterList` helper adds the empty-value issuer to the minter list. [6](#0-5)  However, the minting permission check in `PerformMint` fails because `Context.Sender` (a valid address) will never equal the empty-value address. [7](#0-6) 

2. **Minter Management Fails**: The `AddMinters` [8](#0-7)  and `RemoveMinters` methods [9](#0-8)  require the caller to equal the protocol creator, which will always fail for any real sender when the creator has an empty value.

3. **No Recovery Mechanism**: The `ModifyTokenIssuerAndOwner` method cannot be used to fix this issue because it requires the current issuer to equal the sender. [10](#0-9) 

## Impact Explanation

**Severity: High/Critical**

This vulnerability enables permanent denial-of-service attacks against NFT protocol functionality:

1. **Complete Protocol Bricking**: Any NFT protocol created with an empty-value creator becomes permanently unusable - no NFTs can ever be minted, and the minter list cannot be modified.

2. **Economic Damage**: 
   - Attackers can intentionally brick protocols, wasting the creation fees/costs paid by legitimate users
   - If the attacker front-runs a legitimate NFT protocol creation, the intended creator loses their fees and must create under a different symbol

3. **Griefing Attack Vector**: Malicious actors can systematically brick popular NFT symbol names or types, causing operational disruption and user frustration.

4. **No Recovery Mechanism**: Unlike some protocol configuration issues that can be fixed through governance, there is no mechanism to recover from this state. The protocol creator address is immutably set in the NFTProtocolInfo structure and all recovery methods require sender authentication against the invalid address.

## Likelihood Explanation

**Probability: High**

This vulnerability is highly exploitable:

1. **Reachable Entry Point**: The `Create` method is a public function callable by any user. [11](#0-10) 

2. **Low Attack Complexity**: Exploitation requires only sending a `CreateInput` message with `Creator = new Address()` (an Address object with empty Value). This is trivial to construct in any AElf transaction using the protobuf message definition. [12](#0-11) 

3. **No Special Permissions Required**: Any user can call the Create method - the only barrier is passing the seed NFT check or being in the create whitelist, which is necessary for any protocol creation.

4. **Low Attack Cost**: The cost is merely the NFT creation fee/seed NFT, making griefing attacks economically viable.

5. **Undetectable Until Too Late**: The protocol appears to be created successfully - the vulnerability only manifests when users attempt to mint or manage minters, at which point the damage is already done.

## Recommendation

Add proper validation to both check that the Address object is not null AND that the Address.Value field is not null or empty:

**In NFT Contract (`NFTContract_Create.cs`):**
```csharp
var creator = input.Creator ?? Context.Sender;
Assert(creator != null && !creator.Value.IsNullOrEmpty(), "Invalid creator address.");
```

**In MultiToken Contract (`TokenContract_Helper.cs`):**
```csharp
Assert(tokenInfo.Issuer != null && !tokenInfo.Issuer.Value.IsNullOrEmpty(), "Invalid issuer address.");
Assert(tokenInfo.Owner != null && !tokenInfo.Owner.Value.IsNullOrEmpty(), "Invalid owner address.");
```

This matches the existing validation pattern already used in `AssertValidInputAddress` and `ModifyTokenIssuerAndOwner`.

## Proof of Concept

```csharp
[Fact]
public async Task EmptyCreatorAddressBricksProtocol()
{
    // Create NFT protocol with empty creator address
    var emptyCreator = new Address { Value = ByteString.Empty };
    
    var executionResult = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://test/",
        Creator = emptyCreator, // Empty Address.Value bypasses null check
        IsBurnable = true,
        NftType = NFTType.Art.ToString(),
        ProtocolName = "BRICKED",
        TotalSupply = 1000
    });
    
    var symbol = executionResult.Output.Value;
    
    // Protocol appears created successfully
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = symbol });
    protocolInfo.Symbol.ShouldBe(symbol);
    
    // But minting fails - no one can mint
    var mintException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.Mint.SendAsync(new MintInput
        {
            Symbol = symbol,
            Owner = DefaultAddress
        });
    });
    mintException.Message.ShouldContain("No permission to mint");
    
    // And AddMinters fails - cannot manage minters
    var addMintersException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.AddMinters.SendAsync(new AddMintersInput
        {
            Symbol = symbol,
            MinterList = new MinterList { Value = { DefaultAddress } }
        });
    });
    addMintersException.Message.ShouldContain("No permission");
    
    // Protocol is permanently bricked
}
```

## Notes

This vulnerability arises from an inconsistency in validation patterns across the codebase. The same contract (MultiToken) correctly validates Address.Value in some methods but not in `RegisterTokenInfo`, creating a gap that can be exploited through the NFT contract's Create flow. The fix should align all address validation to use the same robust pattern that checks both null and empty Value fields.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L230-230)
```csharp
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L646-647)
```csharp
        Assert(input.Issuer != null && !input.Issuer.Value.IsNullOrEmpty(), "Invalid input issuer.");
        Assert(input.Owner != null && !input.Owner.Value.IsNullOrEmpty(), "Invalid input owner.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L652-652)
```csharp
        Assert(tokenInfo.Issuer == Context.Sender, "Only token issuer can set token issuer and owner.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L335-338)
```csharp
    public override Empty AddMinters(AddMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L355-358)
```csharp
    public override Empty RemoveMinters(RemoveMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L375-380)
```csharp
    private MinterList GetMinterList(TokenInfo tokenInfo)
    {
        var minterList = State.MinterListMap[tokenInfo.Symbol] ?? new MinterList();
        if (!minterList.Value.Contains(tokenInfo.Issuer)) minterList.Value.Add(tokenInfo.Issuer);

        return minterList;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```

**File:** protobuf/nft_contract.proto (L117-117)
```text
    aelf.Address creator = 4;
```
