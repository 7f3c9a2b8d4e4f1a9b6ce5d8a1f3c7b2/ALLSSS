# Audit Report

## Title
Cross-Chain Token Creation Bypasses Symbol Namespace Collision Protection

## Summary
The `CrossChainCreateToken` method allows both a token (e.g., "ABC") and its corresponding NFT collection (e.g., "ABC-0") to coexist on the same chain by creating them on different chains first and then syncing them via cross-chain operations. This bypasses the `CheckTokenAndCollectionExists` protection that enforces namespace exclusivity during local token creation, violating the design intent and undermining the SEED NFT system's exclusive symbol rights.

## Finding Description

The token contract enforces a namespace collision protection during local token creation. The `GetSymbolType` function distinguishes between regular tokens (e.g., "ABC"), NFT collections (e.g., "ABC-0"), and NFT items (e.g., "ABC-1") based on symbol format. [1](#0-0) 

When creating tokens or NFT collections locally via the `Create` method, the `AssertValidCreateInput` validation calls `CheckTokenAndCollectionExists` to ensure that both the token symbol and its corresponding collection symbol don't already exist. [2](#0-1) 

The `CheckTokenAndCollectionExists` method validates both the base token symbol and the collection symbol (base + "-0") to prevent namespace collisions. [3](#0-2) 

This protection is confirmed by test cases demonstrating that creating "XYZ" blocks creation of "XYZ-0", and vice versa. [4](#0-3) 

**Root Cause:** The `CrossChainCreateToken` method only calls `AssertNftCollectionExist` to validate NFT items (not tokens or collections) and checks if the exact symbol already exists. It does NOT call `CheckTokenAndCollectionExists` to verify that the related symbol doesn't exist. [5](#0-4) 

The `AssertNftCollectionExist` method only validates NFT items (symbols like "ABC-1"), returning null without performing any validation for regular tokens or NFT collections. [6](#0-5) 

The `GetNftCollectionSymbol` helper method returns null for both regular tokens (single-part symbols) and NFT collections (when `isAllowCollection` is false, which is the default), causing `AssertNftCollectionExist` to skip validation entirely for these symbol types. [7](#0-6) 

## Impact Explanation

**Namespace Invariant Violation:** The explicit design intent that tokens and their corresponding collections cannot coexist on the same chain is violated. This fundamental invariant is enforced during local creation but bypassed during cross-chain creation.

**SEED NFT System Bypass:** The SEED NFT system grants exclusive rights to create specific symbols. Users who own a SEED NFT burn it to create their token, expecting exclusive control over that symbol namespace. [8](#0-7)  If a SEED owner creates token "ABC" on Chain A, an attacker can create collection "ABC-0" on Chain B and sync it to Chain A, polluting the namespace that should be exclusively controlled by the SEED owner. The SEED NFT validation and exclusive rights enforcement in `CreateNFTInfo` is completely bypassed. [9](#0-8) 

**User Confusion and Trust Degradation:** The presence of both "ABC" and "ABC-0" on the same chain creates ambiguity about their relationship, potentially misleading users into believing they're related when they're controlled by different entities with conflicting interests.

**Protocol Integrity:** This breaks a core security guarantee of the token system, undermining trust in the namespace protection mechanism and the value proposition of SEED NFTs.

## Likelihood Explanation

**Public Entry Point:** `CrossChainCreateToken` is a public RPC method accessible to any user after cross-chain token contract registration. [10](#0-9) 

**No Special Privileges Required:** The attack only requires:
1. Ability to create tokens on two different chains (standard functionality available to all users)
2. Valid cross-chain verification (attacker provides legitimate proof for tokens they legitimately created)
3. No governance approval or special permissions needed

**Feasible Attack Scenario:**
1. **Chain A:** User creates token "ABC" via `Create()` (passes local validation including `CheckTokenAndCollectionExists`)
2. **Chain B:** Attacker creates collection "ABC-0" via `Create()` (passes local validation on Chain B since "ABC" doesn't exist there)
3. **Chain A:** Attacker calls `CrossChainCreateToken` to sync "ABC-0" from Chain B to Chain A
   - Cross-chain verification passes (legitimate proof from Chain B)
   - `AssertNftCollectionExist("ABC-0")` returns null without validation (collection symbol)
   - Only checks `State.TokenInfos["ABC-0"] == null` (doesn't check if "ABC" exists)
4. **Result:** Both "ABC" and "ABC-0" coexist on Chain A

The same attack works in reverse: create collection first, then sync the token.

**Economic Rationality:** Attack cost is minimal (gas fees for token creation and cross-chain transactions), while benefits include namespace squatting, undermining SEED NFT value, and potential exploitation of user confusion.

## Recommendation

Add the same namespace collision check used in local token creation to the cross-chain creation flow. Modify `CrossChainCreateToken` to call `CheckTokenAndCollectionExists` before registering the token:

```csharp
public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
{
    // ... existing validation code ...
    
    AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
    
    // ADD THIS: Check for namespace collision
    var symbolType = GetSymbolType(validateTokenInfoExistsInput.Symbol);
    if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
    {
        CheckTokenAndCollectionExists(validateTokenInfoExistsInput.Symbol);
    }
    
    var tokenInfo = new TokenInfo { ... };
    
    // ... rest of the method ...
}
```

This ensures that cross-chain token creation enforces the same namespace collision protection as local token creation, maintaining the protocol's security invariants across all creation paths.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChain_TokenCollectionNamespaceCollision_Test()
{
    // Setup: Generate side chain and register cross-chain addresses
    var sideChainId = await GenerateSideChainAsync();
    await RegisterMainChainTokenContractAddressOnSideChainAsync(sideChainId);

    // Step 1: Create token "VULN" on main chain (Chain A)
    var mainChainCreateTx = await CreateTransactionForTokenCreation(
        TokenContractStub, DefaultAccount.Address, "VULN", TokenContractAddress);
    var mainBlock = await MineAsync(new List<Transaction> { mainChainCreateTx });
    mainBlock.TransactionResultMap[mainChainCreateTx.GetHash()].Status
        .ShouldBe(TransactionResultStatus.Mined);

    // Step 2: Create collection "VULN-0" on side chain (Chain B)
    var sideChainCreateTx = await CreateTransactionForTokenCreation(
        SideChainTokenContractStub, SideChainTestKit.DefaultAccount.Address, 
        "VULN-0", SideTokenContractAddress);
    var sideBlock = await SideChainTestKit.MineAsync(new List<Transaction> { sideChainCreateTx });
    sideBlock.TransactionResultMap[sideChainCreateTx.GetHash()].Status
        .ShouldBe(TransactionResultStatus.Mined);

    // Step 3: Prepare cross-chain sync of "VULN-0" from side chain to main chain
    var sideTokenInfo = await SideChainTokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "VULN-0" });
    var validateTx = CreateTokenInfoValidationTransaction(sideTokenInfo, SideChainTokenContractStub);
    var sideValidateBlock = await SideChainTestKit.MineAsync(new List<Transaction> { validateTx });
    
    var merklePath = GetTransactionMerklePathAndRoot(validateTx, out var blockRoot);
    await MainAndSideIndexAsync(sideChainId, sideValidateBlock.Height, blockRoot);
    var boundHeight = await GetBoundParentChainHeightAndMerklePathByHeight(sideValidateBlock.Height);

    // Step 4: Execute CrossChainCreateToken to sync "VULN-0" to main chain (where "VULN" exists)
    var crossChainInput = new CrossChainCreateTokenInput
    {
        FromChainId = sideChainId,
        ParentChainHeight = boundHeight.BoundParentChainHeight,
        TransactionBytes = validateTx.ToByteString(),
        MerklePath = merklePath
    };

    var result = await TokenContractStub.CrossChainCreateToken.SendAsync(crossChainInput);
    
    // VULNERABILITY: This should fail but succeeds
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify both "VULN" and "VULN-0" now exist on main chain
    var vulnToken = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "VULN" });
    var vulnCollection = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "VULN-0" });
    
    vulnToken.Symbol.ShouldBe("VULN");
    vulnCollection.Symbol.ShouldBe("VULN-0");
    
    // PROOF: Both symbols coexist, violating the namespace collision protection
}
```

## Notes

This vulnerability represents a critical security gap in the cross-chain token creation flow. While the local `Create` method properly enforces namespace collision protection through `CheckTokenAndCollectionExists`, the `CrossChainCreateToken` method lacks this validation, creating an inconsistency in security guarantees between local and cross-chain token creation paths.

The existing test suite validates that the same symbol cannot be created twice via `CrossChainCreateToken` [11](#0-10)  but does not test for the namespace collision between related symbols (token and its collection).

The fix is straightforward: apply the same `CheckTokenAndCollectionExists` validation in `CrossChainCreateToken` that is already used in the local `Create` method. This ensures consistent namespace protection across all token creation paths and preserves the integrity of the SEED NFT system's exclusive symbol rights.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-283)
```csharp
    private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
    {
        Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
               && input.Symbol.Length > 0
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

        CheckSymbolLength(input.Symbol, symbolType);
        if (symbolType == SymbolType.Nft) return;
        CheckTokenAndCollectionExists(input.Symbol);
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L285-293)
```csharp
    private void CheckTokenAndCollectionExists(string symbol)
    {
        var symbols = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        var tokenSymbol = symbols.First();
        CheckTokenExists(tokenSymbol);
        var collectionSymbol = symbols.First() + TokenContractConstants.NFTSymbolSeparator +
                               TokenContractConstants.CollectionSymbolSuffix;
        CheckTokenExists(collectionSymbol);
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/NftApplicationTests.cs (L735-781)
```csharp
        var exceptionRes = await CreateSeedNftWithExceptionAsync(TokenContractStub, new CreateInput
        {
            Symbol = "XYZ",
            TokenName = "Trump Digital Trading Cards #1155",
            TotalSupply = TotalSupply,
            Decimals = 0,
            Issuer = DefaultAddress,
            IssueChainId = _chainId,
        });
        exceptionRes.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        exceptionRes.TransactionResult.Error.ShouldContain("Token already exists");
        // check collection symbol prefix duplicated
        var failCollection = await CreateSeedNftWithExceptionAsync(TokenContractStub, new CreateInput
        {
            TokenName = "Trump Digital Trading Cards #1155",
            TotalSupply = TotalSupply,
            Decimals = 0,
            Issuer = DefaultAddress,
            IssueChainId = _chainId,
            Symbol = "XYZ-0"
        });
        failCollection.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        failCollection.TransactionResult.Error.ShouldContain("Token already exists.");

        var successCollection = await CreateMutiTokenAsync(TokenContractStub, new CreateInput
        {
            TokenName = "Trump Digital Trading Cards #1155",
            TotalSupply = TotalSupply,
            Decimals = 0,
            Issuer = DefaultAddress,
            Owner = DefaultAddress,
            IssueChainId = _chainId,
            Symbol = "GHJ-0"
        });
        successCollection.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        // check ft symbol prefix duplicated
        var fTokenAsync = await CreateSeedNftWithExceptionAsync(TokenContractStub, new CreateInput
        {
            TokenName = "Trump Digital Trading Cards #1155",
            TotalSupply = TotalSupply,
            Decimals = 0,
            Issuer = DefaultAddress,
            IssueChainId = _chainId,
            Symbol = "GHJ"
        });
        fTokenAsync.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        fTokenAsync.TransactionResult.Error.ShouldContain("Token already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-66)
```csharp
    private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
    {
        AssertValidCreateInput(input, symbolType);
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L37-50)
```csharp
        if (nftCollectionInfo.Symbol == TokenContractConstants.SeedCollectionSymbol)
        {
            Assert(input.Decimals == 0 && input.TotalSupply == 1, "SEED must be unique.");
            Assert(input.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedOwnedSymbolExternalInfoKey,
                    out var ownedSymbol), "OwnedSymbol does not exist.");
            Assert(input.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                       out var expirationTime)
                   && long.TryParse(expirationTime, out var expirationTimeLong) &&
                   Context.CurrentBlockTime.Seconds <= expirationTimeLong, "Invalid ownedSymbol.");
            var ownedSymbolType = GetSymbolType(ownedSymbol);
            Assert(ownedSymbolType != SymbolType.Nft, "Invalid OwnedSymbol.");
            CheckSymbolLength(ownedSymbol, ownedSymbolType);
            CheckTokenAndCollectionExists(ownedSymbol);
            CheckSymbolSeed(ownedSymbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L153-161)
```csharp
    private string GetNftCollectionSymbol(string inputSymbol, bool isAllowCollection = false)
    {
        var symbol = inputSymbol;
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        const int tokenSymbolLength = 1;
        if (words.Length == tokenSymbolLength) return null;
        Assert(words.Length == 2 && IsValidItemId(words[1]), "Invalid NFT Symbol Input");
        return symbol == $"{words[0]}-0" ? (isAllowCollection ? $"{words[0]}-0" : null) : $"{words[0]}-0";
    }
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

**File:** protobuf/token_contract.proto (L75-77)
```text
    // The side chain creates tokens.
    rpc CrossChainCreateToken(CrossChainCreateTokenInput) returns (google.protobuf.Empty) {
    }
```

**File:** test/AElf.Contracts.MultiTokenCrossChainTransfer.Tests/MultiTokenContractCrossChainTest.cs (L330-367)
```csharp
    {
        await GenerateSideChainAsync();
        await RegisterSideChainContractAddressOnMainChainAsync();

        await BootMinerChangeRoundAsync(AEDPoSContractStub, true);
        var createTransaction = await CreateTransactionForTokenCreation(TokenContractStub,
            DefaultAccount.Address, SymbolForTesting, TokenContractAddress);
        var blockExecutedSet = await MineAsync(new List<Transaction> { createTransaction });
        var createResult = blockExecutedSet.TransactionResultMap[createTransaction.GetHash()];
        Assert.True(createResult.Status == TransactionResultStatus.Mined, createResult.Error);
        var sideCreateTransaction = await CreateTransactionForTokenCreation(SideChainTokenContractStub,
            SideChainTestKit.DefaultAccount.Address, SymbolForTesting, SideTokenContractAddress);
        blockExecutedSet = await SideChainTestKit.MineAsync(new List<Transaction> { sideCreateTransaction });
        var sideCreateResult = blockExecutedSet.TransactionResultMap[sideCreateTransaction.GetHash()];
        Assert.True(sideCreateResult.Status == TransactionResultStatus.Mined, sideCreateResult.Error);

        var createdTokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
        {
            Symbol = SymbolForTesting
        });
        var tokenValidationTransaction = CreateTokenInfoValidationTransaction(createdTokenInfo, TokenContractStub);
        var executedSet = await MineAsync(new List<Transaction> { tokenValidationTransaction });
        var merklePath = GetTransactionMerklePathAndRoot(tokenValidationTransaction, out var blockRoot);
        await IndexMainChainTransactionAsync(executedSet.Height, blockRoot, blockRoot);
        var crossChainCreateTokenInput = new CrossChainCreateTokenInput
        {
            FromChainId = MainChainId,
            ParentChainHeight = executedSet.Height,
            TransactionBytes = tokenValidationTransaction.ToByteString(),
            MerklePath = merklePath
        };

        var executionResult =
            await SideChainTokenContractStub.CrossChainCreateToken.SendWithExceptionAsync(
                crossChainCreateTokenInput);
        Assert.True(executionResult.TransactionResult.Status == TransactionResultStatus.Failed);
        Assert.Contains("Token already exists.", executionResult.TransactionResult.Error);
    }
```
