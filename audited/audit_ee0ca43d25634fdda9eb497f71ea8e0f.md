### Title
Protocol Impersonation via Unvalidated Cross-Chain Token Creation in NFT Contract

### Summary
The `CrossChainCreate` function in the NFT contract directly trusts token information from the local MultiToken contract state without performing any cross-chain verification or merkle proof validation. An attacker can create a malicious token on the mainchain with themselves as the issuer, sync it to a sidechain via the legitimate `CrossChainCreateToken` mechanism, then call `CrossChainCreate` to gain complete control over an NFT protocol on the sidechain, including exclusive minting rights and creator privileges.

### Finding Description

The vulnerability exists in the NFT contract's `CrossChainCreate` method, which is intended to synchronize NFT protocols from mainchain to sidechains. [1](#0-0) 

**Root Cause:**

The function retrieves token information by directly calling the local MultiToken contract's `GetTokenInfo` method. [2](#0-1) 

It then unconditionally trusts the `tokenInfo.Issuer` field as the NFT protocol Creator without any validation. [3](#0-2) 

This Creator is immediately set as the sole minter for the NFT protocol. [4](#0-3) 

**Why Existing Protections Fail:**

1. The function only checks that the NFT protocol doesn't already exist locally, not whether it was legitimately created on mainchain. [5](#0-4) 

2. Unlike the MultiToken contract's proper `CrossChainCreateToken` method which requires transaction bytes and merkle path verification, the NFT's `CrossChainCreate` performs no cryptographic verification. [6](#0-5) 

3. The proper cross-chain flow includes calling `CrossChainVerify` to cryptographically validate the transaction occurred on the source chain. [7](#0-6) 

4. The NFT contract's `Create` method correctly restricts creation to mainchain only, but `CrossChainCreate` bypasses this by not validating the token origin. [8](#0-7) 

5. When creating tokens via MultiToken, arbitrary ExternalInfo metadata can be set, allowing an attacker to include the required NFT metadata keys. [9](#0-8) 

### Impact Explanation

**Direct Authority Takeover:**

The Creator role grants exclusive rights to add and remove minters from the NFT protocol. Only the Creator can execute these privileged operations. [10](#0-9) [11](#0-10) 

**Minting Control:**

The attacker becomes the sole minter and can mint NFTs without restriction. Only addresses in the minter list have permission to mint. [12](#0-11) 

**Concrete Harm:**
- **Protocol Impersonation**: An attacker can create NFT protocols on sidechains that impersonate legitimate brands or projects
- **Economic Fraud**: Minted NFTs appear as legitimate protocol NFTs, potentially defrauding users who purchase or trade them
- **Irreversible Control**: No mechanism exists for legitimate creators to reclaim control once the malicious protocol is created
- **Race Condition Exploitation**: Attackers can front-run legitimate protocol deployments to sidechains

**Affected Parties:**
- Users who trust and purchase NFTs from the fake protocol
- Legitimate protocol creators who lose the ability to deploy to that sidechain
- Ecosystem reputation and trust

### Likelihood Explanation

**Attacker Capabilities Required:**

1. Ability to create a token on mainchain (requires Seed NFT or being whitelisted, but this is publicly accessible through market mechanisms). [13](#0-12) 

2. Knowledge of required NFT metadata keys, which are publicly visible constants. [14](#0-13) 

3. Ability to execute `CrossChainCreateToken` with valid merkle proofs (standard cross-chain operation, publicly documented)

4. Ability to call the public `CrossChainCreate` function on sidechain

**Attack Complexity:** Low to Medium
- All required steps use public interfaces
- No special privileges needed beyond initial token creation capability
- Merkle proof generation is standard cross-chain functionality

**Feasibility Conditions:**
- NFT type must be registered via governance (but common types like "Art", "Game" etc. are likely pre-registered)
- Target protocol symbol must not already exist on sidechain
- All conditions are easily met for new protocols or race conditions

**Economic Rationality:**
- Cost: Minimal (seed NFT purchase + transaction fees)
- Potential gain: Unlimited through fraudulent NFT sales
- Risk/Reward ratio strongly favors the attacker

### Recommendation

**Immediate Fix:**

Modify `CrossChainCreate` to require cross-chain verification similar to MultiToken's implementation:

1. Change the function signature to accept `CrossChainCreateTokenInput` with transaction bytes, merkle path, parent chain height, and source chain ID

2. Add validation that the original transaction was a call to the NFT contract's `Create` method on mainchain (or a whitelisted source chain)

3. Implement merkle proof verification by calling the CrossChain contract's verification method before trusting any token information

4. Parse and validate the CreateInput from the verified transaction bytes rather than reading from local state

**Invariant Checks to Add:**

1. Verify `IssueChainId` matches expected mainchain ID before accepting token info
2. Validate that token ExternalInfo contains proper NFT metadata that could only come from NFT.Create
3. Check that the source transaction's sender matches expected creator authorization patterns

**Test Cases:**

1. Attempt to call `CrossChainCreate` with a token created via MultiToken.Create directly (should fail)
2. Verify legitimate NFT protocol created on mainchain can be synced with proper merkle proofs (should succeed)
3. Test that protocol creation fails without valid cross-chain proof
4. Verify Creator permissions are correctly enforced after legitimate cross-chain creation

### Proof of Concept

**Initial State:**
- Mainchain (AELF) has MultiToken and NFT contracts deployed
- Sidechain has MultiToken and NFT contracts deployed
- NFT type "AT" (Art) is registered via governance on both chains
- Attacker controls address `AttackerAddr` and owns a Seed NFT for symbol "AT-FAKE"

**Attack Sequence:**

1. **On Mainchain**: Attacker calls `MultiToken.Create()`:
   - Symbol: "AT-FAKE"
   - Issuer: AttackerAddr
   - ExternalInfo: 
     - "aelf_nft_type": "Art"
     - "aelf_nft_base_uri": "https://attacker-nft.com/"
     - "aelf_nft_token_id_reuse": "false"
   - Result: Token created with AttackerAddr as Issuer

2. **Cross-Chain Sync**: Attacker calls `MultiToken.CrossChainCreateToken()` on sidechain:
   - Provides valid transaction bytes and merkle path from mainchain
   - Result: Token "AT-FAKE" now exists on sidechain with AttackerAddr as Issuer

3. **On Sidechain**: Attacker calls `NFT.CrossChainCreate()`:
   - Input: Symbol = "AT-FAKE"
   - Result: NFT protocol created with:
     - Creator: AttackerAddr
     - Sole minter: AttackerAddr
     - Protocol appears legitimate

4. **Exploitation**: Attacker calls `NFT.Mint()`:
   - Mints NFTs that appear as legitimate "AT-FAKE" protocol NFTs
   - Users cannot distinguish from legitimate NFTs
   - Attacker profits from selling fake NFTs

**Expected vs Actual:**
- **Expected**: CrossChainCreate should reject tokens not created through NFT.Create on mainchain
- **Actual**: CrossChainCreate accepts any token with proper metadata, granting attacker full control

**Success Condition:**
Attacker successfully becomes Creator and sole minter of an NFT protocol on sidechain without going through the legitimate NFT.Create flow on mainchain.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L77-77)
```csharp
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L399-399)
```csharp
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L7-9)
```csharp
    private const string NftTypeMetadataKey = "aelf_nft_type";
    private const string NftBaseUriMetadataKey = "aelf_nft_base_uri";
    private const string NftTokenIdReuseMetadataKey = "aelf_nft_token_id_reuse";
```
