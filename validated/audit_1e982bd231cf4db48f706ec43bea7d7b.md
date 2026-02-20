# Audit Report

## Title
Missing Cross-Chain Verification in NFT Protocol Creation Allows Unauthorized Protocol Registration

## Summary
The `CrossChainCreate` method in the NFT contract creates NFT protocols on sidechains without cryptographic cross-chain verification, unlike `TokenContract.CrossChainCreateToken` which validates merkle proofs. This allows attackers to create unauthorized NFT protocols on sidechains and gain minting privileges without corresponding protocols existing on the mainchain.

## Finding Description

The vulnerability exists in the NFT contract's `CrossChainCreate` method, which synchronizes NFT protocols from mainchain to sidechain without verifying that the protocol actually exists on the source chain. [1](#0-0) 

The method only checks if the protocol already exists locally, retrieves token information from the local TokenContract state, and validates the NFT type is registered. Critically, it assigns the Creator from the token's Issuer without any cross-chain proof verification: [2](#0-1) 

This contrasts with `TokenContract.CrossChainCreateToken`, which implements proper cross-chain verification by calling `CrossChainVerify` with merkle proofs: [3](#0-2) 

The `CrossChainVerify` method validates cross-chain state by calling the CrossChain contract's `VerifyTransaction` method: [4](#0-3) 

The input structure differences reveal the design flaw. NFT's `CrossChainCreateInput` contains only a symbol: [5](#0-4) 

While `TokenContract.CrossChainCreateTokenInput` includes comprehensive cross-chain verification data: [6](#0-5) 

**Attack Execution Path:**

1. Attacker creates a token on mainchain via `TokenContract.Create`, setting themselves as issuer and including NFT metadata (NftBaseUriMetadataKey, NftTokenIdReuseMetadataKey) in ExternalInfo. The token creation allows arbitrary ExternalInfo: [7](#0-6) 

2. Token is legitimately synced to sidechain via `CrossChainCreateToken` (which properly validates cross-chain state)

3. Attacker calls `NFTContract.CrossChainCreate` on sidechain with the token symbol

4. NFT protocol is created on sidechain with attacker as Creator and automatically added to MinterList

The MinterList authorization is properly enforced for minting operations: [8](#0-7) 

However, the vulnerability allows unauthorized entry into this MinterList.

The design intent is clear that NFT protocols should only be created on mainchain: [9](#0-8) 

## Impact Explanation

**Cross-Chain Integrity Violation:** The fundamental security guarantee of cross-chain synchronization is broken. NFT protocols on sidechains should only exist if they legitimately exist on the source chain with cryptographic verification. This vulnerability allows creation of protocols that exist only on sidechains, violating the design invariant that NFT protocols can only be created on mainchain.

**Unauthorized Privilege Escalation:** Attackers gain minting rights on sidechains for NFT protocols they control, without those protocols existing on the mainchain. This bypasses the intended authorization model.

**User Deception Risk:** Sidechain users may reasonably assume that NFT protocols exist because they were legitimately synchronized from mainchain, leading to potential economic harm if they trade NFTs believing them to be authentic cross-chain assets.

The severity is HIGH because it enables significant authorization bypass and breaks cross-chain state consistency, though it doesn't directly drain existing funds.

## Likelihood Explanation

**Attack Feasibility:** The attack has low complexity requiring only:
- Token creation on mainchain (requires seed NFT, obtainable through normal market operations)
- Calling public `CrossChainCreate` method with no authorization checks
- Two simple transaction steps

**Preconditions:** All preconditions are realistic:
- NFT types are registered (standard system configuration)
- Token sync to sidechain is a standard cross-chain operation anyone can trigger
- First-come-first-served for protocol symbols

**Detection Difficulty:** The attack is difficult to detect because all transactions appear legitimate on the surface, with proper events fired and the token genuinely existing on both chains.

The likelihood is HIGH due to low attack complexity, realistic preconditions, and lack of authorization checks.

## Recommendation

Modify `CrossChainCreate` to accept the same verification parameters as `CrossChainCreateToken` and validate the NFT protocol creation transaction on the source chain using merkle proofs:

```csharp
public override Empty CrossChainCreate(CrossChainCreateInput input)
{
    MakeSureTokenContractAddressSet();
    
    // Verify the NFT protocol exists on source chain
    var tokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
    Assert(tokenContractAddress != null, "Token contract address not registered.");
    
    var originalTransaction = Transaction.Parser.ParseFrom(input.TransactionBytes);
    AssertCrossChainTransaction(originalTransaction, /* NFT contract address */, nameof(Create));
    
    var originalTransactionId = originalTransaction.GetHash();
    CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
    
    // Extract and validate NFT protocol info from verified transaction
    var createInput = CreateInput.Parser.ParseFrom(originalTransaction.Params);
    
    // Continue with protocol creation using verified data...
}
```

Update the `CrossChainCreateInput` protobuf definition to match `CrossChainCreateTokenInput`:

```protobuf
message CrossChainCreateInput {
    int32 from_chain_id = 1;
    int64 parent_chain_height = 2;
    bytes transaction_bytes = 3;
    aelf.MerklePath merkle_path = 4;
}
```

## Proof of Concept

This vulnerability can be demonstrated by:

1. Creating a token on mainchain with NFT metadata via `TokenContract.Create` without calling `NFTContract.Create`
2. Syncing the token to sidechain via `CrossChainCreateToken`
3. Calling `NFTContract.CrossChainCreate` on sidechain
4. Verifying the NFT protocol was created on sidechain but does NOT exist on mainchain
5. Successfully calling `NFTContract.Mint` on sidechain with the attacker as authorized minter

The test would verify that `State.NftProtocolMap[symbol]` exists on sidechain while not existing on mainchain, and that the attacker is in the MinterList despite never creating a legitimate NFT protocol on mainchain.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L16-17)
```csharp
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L478-534)
```csharp
    public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
    {
        var tokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        Assert(tokenContractAddress != null,
            $"Token contract address of chain {ChainHelper.ConvertChainIdToBase58(input.FromChainId)} not registered.");

        var originalTransaction = Transaction.Parser.ParseFrom(input.TransactionBytes);

        AssertCrossChainTransaction(originalTransaction, tokenContractAddress, nameof(ValidateTokenInfoExists));
        var originalTransactionId = originalTransaction.GetHash();
        CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
        var validateTokenInfoExistsInput =
            ValidateTokenInfoExistsInput.Parser.ParseFrom(originalTransaction.Params);
        AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
        var tokenInfo = new TokenInfo
        {
            Symbol = validateTokenInfoExistsInput.Symbol,
            TokenName = validateTokenInfoExistsInput.TokenName,
            TotalSupply = validateTokenInfoExistsInput.TotalSupply,
            Decimals = validateTokenInfoExistsInput.Decimals,
            Issuer = validateTokenInfoExistsInput.Issuer,
            IsBurnable = validateTokenInfoExistsInput.IsBurnable,
            IssueChainId = validateTokenInfoExistsInput.IssueChainId,
            ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
            Owner = validateTokenInfoExistsInput.Owner ?? validateTokenInfoExistsInput.Issuer
        };

        var isSymbolAliasSet = SyncSymbolAliasFromTokenInfo(tokenInfo);
        if (State.TokenInfos[tokenInfo.Symbol] == null)
        {
            RegisterTokenInfo(tokenInfo);
            Context.Fire(new TokenCreated
            {
                Symbol = validateTokenInfoExistsInput.Symbol,
                TokenName = validateTokenInfoExistsInput.TokenName,
                TotalSupply = validateTokenInfoExistsInput.TotalSupply,
                Decimals = validateTokenInfoExistsInput.Decimals,
                Issuer = validateTokenInfoExistsInput.Issuer,
                IsBurnable = validateTokenInfoExistsInput.IsBurnable,
                IssueChainId = validateTokenInfoExistsInput.IssueChainId,
                ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
                Owner = tokenInfo.Owner,
            });
        }
        else
        {
            if (isSymbolAliasSet &&
                validateTokenInfoExistsInput.ExternalInfo.TryGetValue(TokenContractConstants.TokenAliasExternalInfoKey,
                    out var tokenAliasSetting))
            {
                State.TokenInfos[tokenInfo.Symbol].ExternalInfo.Value
                    .Add(TokenContractConstants.TokenAliasExternalInfoKey, tokenAliasSetting);
            }
        }

        return new Empty();
    }
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

**File:** protobuf/nft_contract.proto (L132-134)
```text
message CrossChainCreateInput {
    string symbol = 1;
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
