### Title
NFT Collection Impersonation via Front-Running CrossChainCreateToken

### Summary
The `CrossChainCreateToken` function validates NFT collection existence but fails to verify that the collection properties match between source and destination chains. An attacker can front-run legitimate collection synchronization by creating a fake collection with the same symbol, causing cross-chain NFT items to reference the attacker's collection. This grants the attacker unauthorized control over collection-owner-gated operations for NFTs they don't own.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** At line 491, `AssertNftCollectionExist` only verifies that a collection symbol exists on the destination chain, but does not validate that the collection's properties (IssueChainId, Issuer, Owner) match those from the source chain. The return value containing collection info is discarded and never compared against the cross-chain NFT's properties. [2](#0-1) 

The function returns collection TokenInfo but CrossChainCreateToken doesn't use it for validation.

**Why Protections Fail:**

1. **No Property Validation:** CrossChainCreateToken creates NFT items with properties from the source chain (lines 492-503) but never validates these match the destination chain's collection properties.

2. **Token Already Exists Handling:** When a token symbol already exists, CrossChainCreateToken only updates alias information and returns without overwriting (lines 506-531), allowing a fake collection to persist. [3](#0-2) 

3. **Main Chain Creation Allowed:** On the main chain (where `State.SideChainCreator.Value == null`), anyone with a seed NFT can create NFT collections locally, enabling the attack. [4](#0-3) 

**Contrast with Local NFT Creation:** When creating NFTs locally through the standard flow, `CreateNFTInfo` properly validates collection properties: [5](#0-4) 

Lines 18-21 validate IssueChainId matches, and line 36 validates the owner matches the collection owner. CrossChainCreateToken performs NONE of these checks.

### Impact Explanation

**Harm:** An attacker gains unauthorized control over NFT operations that check collection ownership, while legitimate owners lose control of their cross-chain NFTs.

**Specific Damage:**
- **Permission Bypass:** Operations like `SetSymbolAlias` check the collection owner/issuer for permission. With a fake collection, the attacker controls these permissions for NFTs they don't own. [6](#0-5) 

Line 760 checks `collectionTokenInfo.Owner == Context.Sender || collectionTokenInfo.Issuer == Context.Sender`, which will validate against the fake collection's owner (the attacker), not the legitimate NFT owner.

- **Loss of Legitimate Control:** The real NFT collection owner from the source chain cannot perform collection-owner-gated operations on their own NFTs on the destination chain.

- **Cross-Chain Integrity Violation:** NFT items reference collections with mismatched IssueChainId, breaking the fundamental NFT hierarchy invariant where items must belong to collections from the same issuance context.

**Who is Affected:** All NFT creators synchronizing their collections and items cross-chain from side chains to main chain, particularly valuable NFT collections where alias control or other collection-owner operations have economic significance.

**Severity Justification:** Medium - This allows unauthorized access to collection-owner-gated operations and breaks cross-chain NFT integrity, but requires front-running timing and doesn't directly result in fund theft. However, it permanently breaks the relationship between NFTs and their legitimate collections.

### Likelihood Explanation

**Attacker Capabilities:**
- Must monitor cross-chain synchronization transactions to detect when collections are being synced
- Must have a valid seed NFT to create collections on main chain
- Must be able to front-run the legitimate CrossChainCreateToken transaction

**Attack Complexity:** Medium
1. Monitor for CrossChainCreateToken calls for NFT collections
2. Create fake collection with same symbol before legitimate sync completes
3. Wait for NFT items to be synced, which will reference the fake collection

**Feasibility Conditions:**
- Attack only works when syncing FROM side chain TO main chain (side chains prevent local collection creation)
- Requires mempool visibility or the ability to submit transactions before legitimate synchronization
- Seed NFT acquisition cost is the main barrier

**Detection Constraints:** The fake collection appears legitimate on-chain. Only by comparing collection properties across chains would the discrepancy be noticed. No automatic validation alerts the discrepancy.

**Probability:** Medium-High once NFT cross-chain synchronization becomes active. The cost (seed NFT) is bounded, the timing window exists during any collection sync, and the attack is undetectable by automated systems.

### Recommendation

**Code-Level Mitigation:**

1. **Retrieve and Validate Collection Info:** Modify `CrossChainCreateToken` to use the returned collection info from `AssertNftCollectionExist` and validate it matches the cross-chain token info:

```csharp
var collectionInfo = AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
if (collectionInfo != null) {
    // Validate collection properties match
    Assert(collectionInfo.IssueChainId == validateTokenInfoExistsInput.IssueChainId,
        "NFT issue ChainId must match collection's issue chainId");
    Assert(collectionInfo.Issuer == validateTokenInfoExistsInput.Issuer,
        "NFT issuer must match collection's issuer");
    // Optionally validate Owner consistency
}
```

2. **Add Collection Property Validation:** Before creating the NFT item, verify that if the collection already exists, it was also created via CrossChainCreateToken (check IssueChainId matches the FromChainId or the NFT's IssueChainId).

3. **Prevent Local Collection Creation for Cross-Chain Symbols:** Consider adding metadata to track which collections were synced cross-chain and prevent local creation of collections with symbols that match cross-chain patterns.

**Invariant Checks:**
- NFT item IssueChainId == Collection IssueChainId (for same-chain relationships)
- NFT item Issuer should be authorized by Collection Owner/Issuer
- Collection Owner on destination chain must match source chain for cross-chain synced collections

**Test Cases:**
1. Attempt to create fake collection, then sync real collection - should fail or overwrite
2. Attempt to sync NFT item when collection properties don't match - should fail validation
3. Verify SetSymbolAlias and other collection-owner operations check correct collection after cross-chain sync

### Proof of Concept

**Initial State:**
- Side Chain A: Collection "TESTNFT-0" exists with IssueChainId=SideChainA, Issuer=Alice, Owner=Alice
- Side Chain A: NFT "TESTNFT-1" exists belonging to "TESTNFT-0"
- Main Chain: No "TESTNFT-0" collection exists yet
- Attacker Eve has a valid seed NFT on Main Chain

**Exploitation Steps:**

1. **Attacker Creates Fake Collection:**
   - Eve calls `Create` on Main Chain with symbol "TESTNFT-0", setting Issuer=Eve, Owner=Eve, IssueChainId=MainChain
   - Fake collection is created and registered

2. **Legitimate Collection Sync Attempt:**
   - Alice calls `CrossChainCreateToken` for collection "TESTNFT-0" from Side Chain A
   - Line 506 detects token already exists
   - Line 523-530: Only updates alias, doesn't overwrite fake collection
   - Fake collection persists with Eve as owner

3. **NFT Item Sync:**
   - Alice calls `CrossChainCreateToken` for "TESTNFT-1" from Side Chain A
   - Line 491: `AssertNftCollectionExist("TESTNFT-1")` checks "TESTNFT-0" exists → Returns fake collection info (discarded)
   - Lines 492-503: Creates "TESTNFT-1" with IssueChainId=SideChainA, Issuer=Alice, Owner=Alice
   - "TESTNFT-1" now exists but references the fake collection

4. **Permission Bypass Demonstration:**
   - Alice attempts `SetSymbolAlias` for "TESTNFT-1"
   - Line 747: Gets collection "TESTNFT-0" → Returns fake collection with Owner=Eve
   - Line 760: Checks if Alice == Eve → FAILS
   - Alice cannot set alias for her own NFT
   
   - Eve calls `SetSymbolAlias` for "TESTNFT-1" (Alice's NFT)
   - Line 760: Checks if Eve == Eve → SUCCESS
   - Eve can control aliases for NFTs she doesn't own

**Expected Result:** Alice should have full control over her NFT "TESTNFT-1" including setting aliases.

**Actual Result:** Eve (attacker) has collection-owner privileges over Alice's NFT. Alice is locked out of collection-owner operations on her own NFT.

**Success Condition:** Eve successfully calls SetSymbolAlias for "TESTNFT-1", while Alice's identical call fails with "No permission."

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L51-55)
```csharp
        if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
        {
            // can not call create on side chain
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L738-779)
```csharp
    public override Empty SetSymbolAlias(SetSymbolAliasInput input)
    {
        // Alias setting can only work for NFT Item for now.
        // And the setting exists on the TokenInfo of the NFT Collection.

        // Can only happen on Main Chain.
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "Symbol alias setting only works on MainChain.");

        var collectionSymbol = GetNftCollectionSymbol(input.Symbol, true);

        // For now, token alias can only be set once.
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");

        CheckTokenAlias(input.Alias, collectionSymbol);

        var collectionTokenInfo = GetTokenInfo(collectionSymbol);
        if (collectionTokenInfo == null)
        {
            throw new AssertionException($"NFT Collection {collectionSymbol} not found.");
        }

        Assert(collectionTokenInfo.Owner == Context.Sender || collectionTokenInfo.Issuer == Context.Sender,
            "No permission.");

        collectionTokenInfo.ExternalInfo.Value[TokenContractConstants.TokenAliasExternalInfoKey]
            = $"{{\"{input.Symbol}\":\"{input.Alias}\"}}";

        SetTokenInfo(collectionTokenInfo);

        State.SymbolAliasMap[input.Alias] = input.Symbol;

        Context.LogDebug(() => $"Token alias added: {input.Symbol} -> {input.Alias}");

        Context.Fire(new SymbolAliasAdded
        {
            Symbol = input.Symbol,
            Alias = input.Alias
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L15-36)
```csharp
    private Empty CreateNFTInfo(CreateInput input)
    {
        var nftCollectionInfo = AssertNftCollectionExist(input.Symbol);
        input.IssueChainId = input.IssueChainId == 0 ? nftCollectionInfo.IssueChainId : input.IssueChainId;
        Assert(
            input.IssueChainId == nftCollectionInfo.IssueChainId,
            "NFT issue ChainId must be collection's issue chainId");
        if (nftCollectionInfo.ExternalInfo != null && nftCollectionInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.NftCreateChainIdExternalInfoKey,
                out var nftCreateChainId) && long.TryParse(nftCreateChainId, out var nftCreateChainIdLong))
        {
            Assert(nftCreateChainIdLong == Context.ChainId,
                "NFT create ChainId must be collection's NFT create chainId");
        }
        else
        {
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
        }
        
        var owner = nftCollectionInfo.Owner ?? nftCollectionInfo.Issuer;
        Assert(Context.Sender == owner && owner == input.Owner, "NFT owner must be collection's owner");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L163-170)
```csharp
    private TokenInfo AssertNftCollectionExist(string symbol)
    {
        var collectionSymbol = GetNftCollectionSymbol(symbol);
        if (collectionSymbol == null) return null;
        var collectionInfo = GetTokenInfo(collectionSymbol);
        Assert(collectionInfo != null, "NFT collection not exist");
        return collectionInfo;
    }
```
