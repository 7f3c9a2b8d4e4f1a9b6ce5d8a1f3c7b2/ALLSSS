# Audit Report

## Title
Missing Cross-Chain Verification in NFT Protocol Creation Allows Unauthorized Protocol Registration

## Summary
The `CrossChainCreate()` function in the NFT contract lacks cryptographic verification mechanisms required by AElf's cross-chain security model. Any address can call this function to create NFT protocols for tokens existing in the local TokenContract, bypassing the mainchain-only creation requirement enforced by the standard `Create()` method.

## Finding Description

The NFT contract's `CrossChainCreate()` method accepts only a symbol parameter and performs no cross-chain verification. [1](#0-0) 

The input message structure contains only a single string field, lacking all verification parameters: [2](#0-1) 

This contrasts with MultiToken's secure `CrossChainCreateToken()` implementation, which properly invokes cross-chain verification: [3](#0-2) 

The MultiToken contract accepts comprehensive verification parameters including merkle path: [4](#0-3) 

The `CrossChainVerify` helper performs cryptographic merkle proof validation through the CrossChain contract: [5](#0-4) 

Additionally, the standard `Create()` method enforces mainchain-only protocol creation: [6](#0-5) 

However, `CrossChainCreate()` contains no chain ID validation, allowing invocation on any chain despite the function executing on lines 75-129 without any chain verification.

The function is publicly accessible as a standard RPC method: [7](#0-6) 

## Impact Explanation

This vulnerability breaks multiple security guarantees:

1. **Mainchain-Only Invariant Bypass**: The `Create()` method explicitly restricts NFT protocol creation to the AELF mainchain. `CrossChainCreate()` allows this security boundary to be circumvented on sidechains without authorization.

2. **Cross-Chain Security Model Violation**: AElf's cross-chain architecture requires merkle proof validation for all cross-chain operations to ensure cryptographic verification of source chain transactions. This function completely bypasses that model despite its naming suggesting cross-chain functionality.

3. **Unauthorized Protocol Creation**: Any address can trigger protocol creation for any token existing in the local TokenContract. While the token issuer becomes the protocol creator, the lack of authorization check means anyone can force this state transition without the token creator's consent.

4. **Front-Running Vulnerability**: Since the protocol duplicate check prevents recreation, attackers can front-run legitimate protocol creation transactions, causing them to fail.

The severity is critical because it undermines fundamental architectural guarantees about where NFT protocols can exist and how cross-chain operations should be verified.

## Likelihood Explanation

The attack is highly feasible:

**Attacker Requirements:**
- Standard transaction capability (any address)
- No special privileges required
- Token must exist in local TokenContract (common on sidechains through `CrossChainCreateToken`)

**Attack Complexity:**
- Single function call with one parameter
- No timing dependencies
- No economic barriers beyond gas costs
- Easily reproducible

**Realistic Scenario:**
1. Token "FOO" created on mainchain and cross-chain transferred to sidechain (standard operation)
2. Attacker calls `CrossChainCreate("FOO")` on sidechain
3. NFT protocol created without verification
4. Legitimate protocol synchronization now blocked

The complete absence of authorization checks combined with public RPC accessibility makes this exploit trivial to execute.

## Recommendation

Implement proper cross-chain verification matching MultiToken's security pattern:

1. **Add verification parameters** to `CrossChainCreateInput`:
   - `from_chain_id`
   - `parent_chain_height`
   - `transaction_bytes`
   - `merkle_path`

2. **Add CrossChainVerify call** before protocol creation to validate merkle proof against CrossChain contract

3. **Add chain ID validation** if protocols should remain mainchain-only, or explicitly document sidechain support with proper verification

4. **Add authorization check** requiring approval from token issuer or governance before protocol creation

5. **Add comprehensive test coverage** for cross-chain protocol creation scenarios

## Proof of Concept

```csharp
// Test demonstrating unauthorized protocol creation
[Fact]
public async Task CrossChainCreate_Unauthorized_Protocol_Creation()
{
    // Setup: Token exists on sidechain via proper CrossChainCreateToken
    var tokenSymbol = "TEST";
    
    // Attacker calls CrossChainCreate without authorization
    var result = await NFTContractStub.CrossChainCreate.SendAsync(
        new CrossChainCreateInput { Symbol = tokenSymbol });
    
    // Verify: Protocol created without merkle proof verification
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Protocol now exists, blocking legitimate creation
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = tokenSymbol });
    protocolInfo.ShouldNotBeNull();
    
    // Attempting to create again fails
    var secondAttempt = await NFTContractStub.CrossChainCreate.SendWithExceptionAsync(
        new CrossChainCreateInput { Symbol = tokenSymbol });
    secondAttempt.TransactionResult.Error.ShouldContain("already created");
}
```

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

**File:** protobuf/nft_contract.proto (L25-26)
```text
    rpc CrossChainCreate (CrossChainCreateInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/nft_contract.proto (L132-134)
```text
message CrossChainCreateInput {
    string symbol = 1;
}
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L478-488)
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
