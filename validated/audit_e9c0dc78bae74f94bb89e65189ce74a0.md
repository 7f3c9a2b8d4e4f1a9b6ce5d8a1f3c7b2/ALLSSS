# Audit Report

## Title
RemoveNFTType Breaks Cross-Chain Protocol Creation for Existing NFT Protocols

## Summary
The `RemoveNFTType()` function removes NFT type mappings without verifying whether existing protocols depend on those types. When protocols attempt cross-chain synchronization via `CrossChainCreate()`, the operation fails permanently if their type mapping has been removed, causing operational DoS of critical cross-chain NFT functionality.

## Finding Description

The vulnerability exists in the `RemoveNFTType()` function which removes NFT type mappings from state without any usage validation. [1](#0-0) 

The function only validates that the short name exists, then removes entries from both `NFTTypeFullNameMap` and `NFTTypeShortNameMap` without checking if any protocols currently use that type.

**Root Cause**: The contract stores protocols in a `MappedState<string, NFTProtocolInfo>` structure which does not support enumeration. [2](#0-1) 

Without the ability to iterate through all protocols, there is no mechanism to verify whether a type is actively in use before removing it.

**Execution Path**: When `CrossChainCreate()` attempts to synchronize a protocol to a sidechain, it extracts the 2-character short name from the protocol symbol and performs a lookup in `NFTTypeFullNameMap`: [3](#0-2) 

If the type has been removed, the lookup returns `null` and throws an `AssertionException`, permanently preventing the protocol from being created on any sidechain.

**Security Guarantee Broken**: The cross-chain protocol creation flow requires NFT type mappings to be available. Removing a type breaks this guarantee for all protocols using that type, violating the cross-chain operational integrity invariant.

## Impact Explanation

**Operational DoS**: All NFT protocols created on the mainchain with a removed type cannot be synchronized to sidechains. This breaks the cross-chain NFT protocol creation flow, which is a core feature of the AElf multi-chain ecosystem.

**Affected Parties**:
- Protocol creators who cannot expand their NFT collections to sidechains
- Users who cannot access NFT protocols on sidechains where they were expected
- The entire cross-chain NFT ecosystem functionality

**Severity: HIGH** - While existing protocols on already-synchronized chains continue functioning (they store their own `NftType` value locally), any protocol not yet created on a sidechain becomes permanently unable to synchronize until Parliament re-adds the type. This causes downtime, operational disruption, and potential confusion if different mappings are used during recovery.

## Likelihood Explanation

**Required Authorization**: Requires Parliament default organization authorization to call `RemoveNFTType()`. [4](#0-3) 

**Feasibility: MEDIUM** - This is not a traditional "attack" but rather a governance action with severe unintended consequences. Parliament could legitimately vote to remove a type they believe is unused (perhaps to clean up deprecated types or reorganize the type system), completely unaware that protocols on the mainchain depend on it for cross-chain synchronization. 

The lack of visibility into which types are actively used by existing protocols makes accidental removal realistic during protocol maintenance or type system reorganization. The attack complexity is LOW (single governance action), but the scenario requires a governance mistake rather than malicious intent.

## Recommendation

Implement one of the following solutions:

**Solution 1**: Maintain a usage counter or registry:
```csharp
public MappedState<string, int64> NFTTypeUsageCount { get; set; }

// In Create():
State.NFTTypeUsageCount[shortName] = State.NFTTypeUsageCount[shortName] + 1;

// In RemoveNFTType():
Assert(State.NFTTypeUsageCount[input.Value] == 0, 
    "Cannot remove NFT type that is currently in use by existing protocols.");
```

**Solution 2**: Add a view method to check usage before removal:
```csharp
public override Empty RemoveNFTType(StringValue input)
{
    AssertSenderIsParliamentDefaultAddress();
    InitialNFTTypeNameMap();
    Assert(input.Value.Length == 2, "Incorrect short name.");
    Assert(State.NFTTypeFullNameMap[input.Value] != null, 
        $"Short name {input.Value} does not exist.");
    
    // Add warning event for governance review
    Context.Fire(new NFTTypeRemovalRequested 
    {
        ShortName = input.Value,
        Warning = "Ensure no protocols use this type before proceeding"
    });
    
    // ... rest of removal logic
}
```

**Solution 3**: Implement a two-step removal with deprecation period:
- First call marks type as deprecated (prevents new protocol creation)
- Second call after a grace period removes the type (allows time for cross-chain synchronization)

## Proof of Concept

```csharp
[Fact]
public async Task RemoveNFTType_Breaks_CrossChainCreate()
{
    // Step 1: Create NFT protocol on mainchain with Art type
    var createResult = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        NftType = NFTType.Art.ToString(), // Uses "AR" short name
        ProtocolName = "TestNFT",
        BaseUri = "ipfs://test/",
        TotalSupply = 1000,
        IsBurnable = true
    });
    var symbol = createResult.Output.Value;
    symbol.Substring(0, 2).ShouldBe("AR"); // Symbol starts with "AR"
    
    // Step 2: Parliament removes Art type
    var removeResult = await ParliamentNFTContractStub.RemoveNFTType.SendAsync(
        new StringValue { Value = "AR" }
    );
    removeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Attempt CrossChainCreate on sidechain - should fail
    var crossChainResult = await SideChainNFTContractStub.CrossChainCreate
        .SendWithExceptionAsync(new CrossChainCreateInput { Symbol = symbol });
    
    crossChainResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    crossChainResult.TransactionResult.Error.ShouldContain(
        "Full name of AR not found. Use AddNFTType to add this new pair."
    );
    
    // Demonstrates permanent DoS of cross-chain creation for this protocol
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L89-93)
```csharp
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L24-24)
```csharp
    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }
```
