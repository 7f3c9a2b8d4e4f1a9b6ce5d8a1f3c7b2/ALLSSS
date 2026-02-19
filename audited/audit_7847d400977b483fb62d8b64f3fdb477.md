# Audit Report

## Title
Missing Cross-Chain Verification in NFT Protocol Creation Allows Unauthorized Protocol Registration

## Summary
The `CrossChainCreate` method in the NFT contract lacks cross-chain verification, allowing attackers to create unauthorized NFT protocols on sidechains by exploiting legitimately synced tokens. This grants them Creator privileges and minting rights for protocols that never existed on the source chain, breaking cross-chain integrity guarantees.

## Finding Description

The NFT contract's `CrossChainCreate` method creates NFT protocols on sidechains without verifying that the protocol actually exists on the source chain. [1](#0-0) 

**Root Cause:**

The method only performs two checks:
1. Whether the protocol already exists locally [2](#0-1) 
2. Whether the token exists in the local TokenContract state [3](#0-2) 

It then directly assigns the Creator from the token issuer and adds them to the MinterList without any cross-chain proof verification. [4](#0-3) 

**Contrast with Secure Implementation:**

The TokenContract's `CrossChainCreateToken` method properly validates cross-chain operations by calling `CrossChainVerify` with merkle path verification. [5](#0-4) 

This verification method calls the CrossChainContract's `VerifyTransaction` to cryptographically prove the transaction occurred on the source chain. [6](#0-5) 

The input structures further demonstrate this disparity. `CrossChainCreateTokenInput` contains fields for source chain ID, parent chain height, transaction bytes, and merkle path. [7](#0-6) 

In contrast, `CrossChainCreateInput` only contains a symbol field with no verification data. [8](#0-7) 

**Attack Execution:**

1. Attacker creates a token on mainchain via `TokenContract.Create` with themselves as issuer, including NFT metadata in ExternalInfo [9](#0-8) 

2. Token is synced to sidechain via legitimate `CrossChainCreateToken` (with proper verification)

3. Attacker calls `NFTContract.CrossChainCreate` on sidechain with the token symbol

4. NFT protocol is created with attacker as Creator and sole minter, despite no corresponding NFT protocol existing on mainchain

The attacker then has full control over minting for that protocol, as the minter check verifies against the MinterList. [10](#0-9) 

Only the Creator can add or remove minters, cementing the attacker's control. [11](#0-10) 

## Impact Explanation

**Severity: High/Critical**

This vulnerability breaks the fundamental cross-chain security guarantee that sidechain NFT protocols are legitimate synchronizations from the mainchain.

**Concrete Harms:**
1. **Unauthorized Minter Privileges**: Attackers gain exclusive minting rights for NFT protocols that shouldn't exist on sidechains
2. **Protocol Integrity Violation**: Sidechain NFT state diverges from mainchain without any legitimate cross-chain operation
3. **User Deception**: Sidechain users interact with fake NFT protocols believing they're authentic cross-chain synced assets
4. **Economic Losses**: Fake NFTs could be minted, traded, and cause financial harm to users who believe they're acquiring legitimate cross-chain assets
5. **Ecosystem Trust Damage**: Undermines confidence in the entire cross-chain NFT infrastructure

**Affected Parties:**
- Legitimate NFT protocol creators whose brands/symbols could be spoofed on sidechains
- Users on sidechains who cannot distinguish fake from legitimate protocols
- The overall integrity of AElf's cross-chain ecosystem

## Likelihood Explanation

**Probability: High**

**Attacker Requirements:**
- Ability to create a token on mainchain (requires seed NFT or whitelist status - seed NFTs are obtainable through normal market operations) [12](#0-11) 
- Ability to call public contract methods (no special privileges required)

**Attack Complexity: Low**
The attack requires only two standard operations:
1. Create a token on mainchain with NFT metadata
2. Call `CrossChainCreate` on sidechain after token synchronization

**Feasibility Conditions:**
- NFT type prefix must be registered (e.g., "AR" for art) - these are governance-registered and publicly available
- Token must be synced to sidechain first (can be done by attacker or any third party)
- Protocol with that symbol must not already exist on sidechain

**Detection Difficulty:**
The attack is difficult to detect because:
- The transaction succeeds normally
- Events are fired as expected
- The token genuinely exists
- Only off-chain comparison with mainchain state would reveal the discrepancy

## Recommendation

Implement cross-chain verification in `CrossChainCreate` similar to `CrossChainCreateToken`:

1. **Modify Input Structure**: Add fields to `CrossChainCreateInput` for chain ID, parent chain height, transaction bytes, and merkle path

2. **Add Verification Logic**: Call a verification helper method that:
   - Parses the original NFT protocol creation transaction
   - Verifies it using the CrossChainContract's `VerifyTransaction` method
   - Validates that the protocol properties match the verified transaction

3. **Implementation Pattern**: Follow the exact pattern used in `TokenContract_Actions.cs` lines 478-534 for `CrossChainCreateToken`

This ensures that NFT protocols can only be created on sidechains if they genuinely exist on the source chain and have been properly indexed through the cross-chain infrastructure.

## Proof of Concept

```csharp
// PoC Test: Demonstrates unauthorized NFT protocol creation on sidechain
[Fact]
public async Task UnauthorizedCrossChainNFTProtocolCreation()
{
    // Setup: Attacker controls a token on mainchain as issuer
    // Token has been synced to sidechain via legitimate CrossChainCreateToken
    
    // Execute: Attacker calls CrossChainCreate on sidechain
    var result = await NFTContractStub.CrossChainCreate.SendAsync(
        new CrossChainCreateInput { Symbol = "ARTEST-1" }
    );
    
    // Verify: NFT protocol created with attacker as Creator
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = "ARTEST-1" }
    );
    
    // Attacker is the Creator despite no NFT protocol existing on mainchain
    protocolInfo.Creator.ShouldBe(AttackerAddress);
    
    // Attacker has minting privileges
    var minterList = await NFTContractStub.GetMinterList.CallAsync(
        new StringValue { Value = "ARTEST-1" }
    );
    minterList.Value.ShouldContain(AttackerAddress);
    
    // Attacker can now mint unauthorized NFTs
    await NFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = "ARTEST-1",
        TokenId = 1,
        Owner = AttackerAddress
    });
}
```

## Notes

This vulnerability represents a critical cross-chain security flaw where the NFT contract fails to maintain the security invariant that sidechain state is a verified reflection of mainchain state. The TokenContract demonstrates the correct implementation pattern with merkle proof verification, making this omission particularly concerning as it suggests an architectural inconsistency between related contracts.

The attack is economically viable because token creation costs are minimal (only transaction fees plus seed NFT cost, which can be recovered), while the potential gains from minting unauthorized NFTs could be substantial if users are deceived into believing they're legitimate cross-chain assets.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-65)
```csharp
            if (!IsAddressInCreateWhiteList(Context.Sender) &&
                input.Symbol != TokenContractConstants.SeedCollectionSymbol)
            {
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-79)
```csharp
        var tokenInfo = new TokenInfo
        {
            Symbol = input.Symbol,
            TokenName = input.TokenName,
            TotalSupply = input.TotalSupply,
            Decimals = input.Decimals,
            Issuer = input.Issuer,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
            Owner = input.Owner
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L488-488)
```csharp
        CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L236-250)
```csharp
    private void CrossChainVerify(Hash transactionId, long parentChainHeight, int chainId, MerklePath merklePath)
    {
        var verificationInput = new VerifyTransactionInput
        {
            TransactionId = transactionId,
            ParentChainHeight = parentChainHeight,
            VerifiedChainId = chainId,
            Path = merklePath
        };
        var address = Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName);

        var verificationResult = Context.Call<BoolValue>(address,
            nameof(ACS7Container.ACS7ReferenceState.VerifyTransaction), verificationInput);
        Assert(verificationResult.Value, "Cross chain verification failed.");
    }
```

**File:** protobuf/token_contract.proto (L571-580)
```text
message CrossChainCreateTokenInput {
    // The chain id of the chain on which the token was created.
    int32 from_chain_id = 1;
    // The height of the transaction that created the token.
    int64 parent_chain_height = 2;
    // The transaction that created the token.
    bytes transaction_bytes = 3;
    // The merkle path created from the transaction that created the transaction.
    aelf.MerklePath merkle_path = 4;
}
```

**File:** protobuf/nft_contract.proto (L132-134)
```text
message CrossChainCreateInput {
    string symbol = 1;
}
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L337-338)
```csharp
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
