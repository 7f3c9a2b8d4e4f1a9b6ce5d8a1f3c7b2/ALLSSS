# Audit Report

## Title
NFT Metadata Loss When Re-minting Burned Tokens with IsTokenIdReuse Enabled

## Summary
When `IsTokenIdReuse` is true and all tokens of a specific token ID are burned (quantity reaches 0), subsequent re-minting of the same token ID ignores the new minter's Uri, Metadata, and Alias inputs, causing permanent loss of intended NFT data. Additionally, the `NFTMinted` event emits the new metadata values while the actual on-chain state retains the old metadata, creating a critical state-event inconsistency.

## Finding Description

The vulnerability exists in the `PerformMint` function when handling re-minting scenarios for protocols with `IsTokenIdReuse = true` (ERC-1155 style NFTs).

**Root Cause:**

When burning tokens in a protocol with `IsTokenIdReuse = true`, if the quantity reaches 0, the NFTInfo entry remains in `NftInfoMap` with quantity=0 but the `IsBurned` flag is NOT set. [1](#0-0) 

**Execution Path:**

1. On re-minting, `PerformMint` retrieves the existing NFTInfo from state. [2](#0-1) 

2. The uniqueness check is skipped when `IsTokenIdReuse` is true. [3](#0-2) 

3. Fresh metadata is prepared by merging protocol metadata with input metadata. [4](#0-3) 

4. **CRITICAL BUG:** When `nftInfo` is not null (existing entry), the code enters the else block which ONLY updates Quantity and Minters, completely ignoring the prepared metadata, uri, and alias. [5](#0-4) 

5. The NFTInfo with old metadata is saved to state. [6](#0-5) 

6. **STATE-EVENT MISMATCH:** The `NFTMinted` event uses the NEW metadata values from input, creating a critical discrepancy between what events report and what is actually stored on-chain. [7](#0-6) 

**Why Protections Fail:**

The code prepares fresh metadata but never applies it when `nftInfo` already exists. There is no check for whether the existing NFTInfo has quantity=0 (fully burned state), which should trigger metadata updates rather than just quantity additions.

## Impact Explanation

**Direct Harm:**
- **Data Loss:** Minters lose their intended NFT metadata, URI, and alias completely. This data cannot be recovered through normal minting operations, only through the separate `Recast` function which requires specific conditions (ownership of all tokens).
- **Financial Loss:** Users pay transaction fees to mint NFTs but receive tokens with incorrect/unintended metadata that doesn't match their expectations or input parameters.
- **State-Event Inconsistency:** Off-chain systems, NFT marketplaces, and blockchain explorers reading `NFTMinted` events will display different metadata than what exists on-chain. This breaks the fundamental AElf guarantee that events accurately reflect state changes.

**Attack Scenario:**
1. Attacker creates an NFT protocol with `IsTokenIdReuse = true`
2. Attacker mints tokenId 1 with malicious metadata (e.g., fake rarity claims, misleading artwork URLs, inappropriate content)
3. Attacker burns all tokens (quantity = 0)
4. Victim attempts to mint tokenId 1 with legitimate metadata
5. Victim's mint succeeds but inherits attacker's malicious metadata on-chain
6. Events show victim's metadata, but all on-chain queries return attacker's metadata
7. NFT marketplaces display victim's metadata from events while actual token state contains malicious data

**Affected Parties:**
- NFT minters who re-mint burned token IDs lose their intended token data
- NFT marketplaces and explorers display inconsistent information
- NFT buyers receive misrepresented assets
- Protocol creators lose user trust due to data integrity issues

**Severity:** Medium-High due to guaranteed data loss on realistic user flows (burn-then-remint operations), state corruption, and potential for malicious exploitation.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Minting permissions in an NFT protocol (normal user privilege granted by protocol creator)
- Ability to burn tokens (standard protocol feature when `IsBurnable = true`)
- No special privileges, governance control, or system access needed

**Attack Complexity:**
- Simple 3-step process: mint → burn all → wait for victim to remint same token ID
- No timing windows or complex state manipulation required
- Executable entirely through standard public contract methods
- Can even occur accidentally when multiple minters in a protocol independently mint/burn/remint the same token IDs

**Feasibility Conditions:**
- Protocols with `IsTokenIdReuse = true` are affected (ERC-1155 style is a common NFT pattern)
- Token IDs being fully burned and then re-minted is a realistic scenario in dynamic NFT systems
- The vulnerability is triggered automatically without requiring any special conditions

**Detection Constraints:**
- The state-event inconsistency makes detection extremely difficult
- No error or warning is generated during the transaction
- Contract execution succeeds normally with a successful return value
- Off-chain systems have no indication that the stored metadata differs from event metadata

**Probability:** HIGH - This occurs naturally whenever anyone re-mints a fully burned token ID in any protocol with `IsTokenIdReuse = true`. The vulnerability is triggered by normal user operations, not malicious actions.

## Recommendation

Modify the `PerformMint` function to check if the existing NFTInfo has quantity=0 (fully burned state), and if so, update the metadata, uri, and alias fields in addition to quantity and minters:

```csharp
else
{
    nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
    if (!nftInfo.Minters.Contains(Context.Sender)) 
        nftInfo.Minters.Add(Context.Sender);
    
    // If token was fully burned, allow updating metadata
    if (nftInfo.Quantity == quantity) // Previous quantity was 0
    {
        nftInfo.Metadata = nftMetadata;
        nftInfo.Uri = input.Uri ?? string.Empty;
        nftInfo.Alias = input.Alias;
    }
}
```

Alternatively, add a check to detect when quantity was previously 0 and treat it as a new mint rather than an increment.

## Proof of Concept

```csharp
[Fact]
public async Task NFT_Metadata_Loss_On_Remint_After_Burn()
{
    // Create protocol with IsTokenIdReuse = true
    var symbol = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://test/",
        Creator = DefaultAddress,
        IsBurnable = true,
        IsTokenIdReuse = true, // Enable token ID reuse
        NftType = NFTType.Collectables.ToString(),
        ProtocolName = "TEST",
        TotalSupply = 1000000
    });
    
    await NFTContractStub.AddMinters.SendAsync(new AddMintersInput
    {
        Symbol = symbol.Output.Value,
        MinterList = new MinterList { Value = { MinterAddress } }
    });
    
    // Minter A mints with metadata "Original"
    var tokenHash = await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol.Output.Value,
        TokenId = 1,
        Metadata = new Metadata { Value = { { "Key", "Original" } } },
        Uri = "ipfs://original",
        Alias = "Original Alias",
        Quantity = 10
    });
    
    // Burn all tokens (quantity = 0)
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol.Output.Value,
        TokenId = 1,
        Amount = 10
    });
    
    // Minter A remints with NEW metadata "Updated"
    await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol.Output.Value,
        TokenId = 1,
        Metadata = new Metadata { Value = { { "Key", "Updated" } } },
        Uri = "ipfs://updated",
        Alias = "Updated Alias",
        Quantity = 5
    });
    
    // Query NFTInfo from state
    var nftInfo = await NFTContractStub.GetNFTInfo.CallAsync(new GetNFTInfoInput
    {
        Symbol = symbol.Output.Value,
        TokenId = 1
    });
    
    // BUG: Metadata is NOT updated - still shows "Original"
    nftInfo.Metadata.Value["Key"].ShouldBe("Updated"); // FAILS - shows "Original"
    nftInfo.Uri.ShouldBe("ipfs://updated"); // FAILS - shows "ipfs://original"
    nftInfo.Alias.ShouldBe("Updated Alias"); // FAILS - shows "Original Alias"
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L99-99)
```csharp
        if (nftInfo.Quantity == 0 && !nftProtocolInfo.IsTokenIdReuse) nftInfo.IsBurned = true;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L394-394)
```csharp
        var nftInfo = State.NftInfoMap[tokenHash];
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L395-396)
```csharp
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L408-413)
```csharp
        // Inherit from protocol info.
        var nftMetadata = protocolInfo.Metadata.Clone();
        if (input.Metadata != null)
            foreach (var pair in input.Metadata.Value)
                if (!nftMetadata.Value.ContainsKey(pair.Key))
                    nftMetadata.Value[pair.Key] = pair.Value;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L433-437)
```csharp
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
        }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L439-439)
```csharp
        State.NftInfoMap[tokenHash] = nftInfo;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L443-460)
```csharp
        var nftMinted = new NFTMinted
        {
            Symbol = input.Symbol,
            ProtocolName = protocolInfo.ProtocolName,
            TokenId = tokenId,
            Metadata = nftMetadata,
            Owner = owner,
            Minter = Context.Sender,
            Quantity = quantity,
            Alias = input.Alias,
            BaseUri = protocolInfo.BaseUri,
            Uri = input.Uri ?? string.Empty,
            Creator = protocolInfo.Creator,
            NftType = protocolInfo.NftType,
            TotalQuantity = nftInfo.Quantity,
            TokenHash = tokenHash
        };
        Context.Fire(nftMinted);
```
