# Audit Report

## Title
Cross-Chain Token Property Inconsistency Allows Denial of Service on Cross-Chain Transfers

## Summary
The `CrossChainCreateToken` function fails to update critical token properties when a token already exists on the destination chain, only modifying the ExternalInfo field. This enables an attacker to front-run legitimate cross-chain token deployments by creating tokens with mismatched properties (particularly `IssueChainId`), permanently breaking cross-chain transfer functionality for that token symbol.

## Finding Description

The vulnerability exists in the `CrossChainCreateToken` function's handling of existing tokens. When a token with the target symbol already exists on the destination chain, the function only updates the ExternalInfo field for NFT alias information, leaving all critical security properties unchanged: [1](#0-0) 

All critical security properties remain unchanged:
- **IssueChainId**: Required for cross-chain transfer validation
- **TotalSupply**: Controls maximum token issuance  
- **Decimals**: Defines token precision
- **Issuer**: Controls who can issue tokens
- **Owner**: Controls token management rights

The `ValidateTokenInfoExists` function explicitly validates all these properties as security-critical, confirming they must match between chains for proper cross-chain operation: [2](#0-1) 

**Attack Vector: Front-Running Cross-Chain Token Creation**

On the main chain, anyone can create tokens by burning seed NFTs. The `CreateToken` function allows callers to specify arbitrary `IssueChainId` values: [3](#0-2) 

The `CreateInput` protobuf definition confirms the `issue_chain_id` field is caller-controlled: [4](#0-3) 

An attacker can exploit this by:
1. Monitoring for planned cross-chain token deployments
2. Burning a seed NFT to create the token on the main chain with incorrect `IssueChainId`
3. When legitimate `CrossChainCreateToken` is called, it finds the token exists and fails to update properties
4. The `IssueChainId` mismatch permanently breaks cross-chain transfers

The `CrossChainReceiveToken` function enforces strict `IssueChainId` validation, causing all subsequent transfers to fail: [5](#0-4) 

Unlike `CrossChainReceiveToken` which implements replay protection at line 596-597, `CrossChainCreateToken` has no mechanism to track synchronized tokens or prevent property conflicts when tokens already exist.

## Impact Explanation

**Critical Cross-Chain Transfer Failure**

When properties diverge between chains (especially `IssueChainId`), the protocol's cross-chain transfer mechanism becomes permanently inoperable for that token:
- Users on the source chain cannot transfer tokens to the destination chain
- Users on the destination chain cannot transfer tokens to the source chain
- The token loses all cross-chain utility, severely limiting its value

**Economic Impact**
- Token holders lose cross-chain functionality and liquidity
- DApps expecting cross-chain operations fail
- DEXs and TokenConverter contracts may operate with incorrect decimal precision
- The cost to the attacker is one seed NFT, making this economically viable for disrupting valuable tokens

**No Recovery Mechanism**

Once a token is created with wrong properties, there is no protocol mechanism to update the properties to match the legitimate source chain, remove the malicious token registration, or override the existing token data.

The `Issue` function also enforces supply constraints based on the local `TotalSupply` value, which may differ from the legitimate chain: [6](#0-5) 

## Likelihood Explanation

**Public Entry Point with Minimal Guards**

`CrossChainCreateToken` is a public function with no authorization checks beyond whitelist registration: [7](#0-6) 

Once the source chain's token contract is registered (a one-time administrative action), anyone can call this function with valid merkle proofs.

**Economically Feasible Attack**

The main chain allows token creation for anyone who burns a seed NFT. The attacker needs to:
1. Obtain a seed NFT for the target symbol (available through the SEED NFT system)
2. Call `Create()` before `CrossChainCreateToken` is called
3. Set malicious properties (wrong `IssueChainId`)

For high-value tokens, the cost of one seed NFT is negligible compared to the disruption caused.

**Test Evidence of Intentional Behavior**

A test explicitly shows this behavior was intentionally changed to "allow" calling `CrossChainCreateToken` when the token exists, but without considering the security implications: [8](#0-7) 

## Recommendation

The `CrossChainCreateToken` function should validate that existing token properties match the cross-chain token info before allowing the operation. When a token already exists, either:

1. **Validate all properties match** - Compare all critical fields (IssueChainId, TotalSupply, Decimals, Issuer, Owner) and revert if any mismatch is detected
2. **Implement idempotency tracking** - Similar to `CrossChainReceiveToken`'s replay protection, track which tokens have been synchronized from which chains
3. **Restrict token creation on main chain** - Require authorization for tokens that will be used cross-chain, preventing front-running

The fix should ensure that once a token is registered via `CrossChainCreateToken` with specific properties, those properties cannot be circumvented by prior local token creation with different values.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task CrossChainCreateToken_FrontRunning_Attack_Test()
{
    // 1. Attacker creates token on main chain with wrong IssueChainId
    var maliciousIssueChainId = 999; // Wrong chain ID
    await CreateTokenWithSeed(SymbolForTesting, maliciousIssueChainId);
    
    // 2. Legitimate CrossChainCreateToken is called with correct IssueChainId
    var correctIssueChainId = MainChainId;
    await LegitimatelyCallCrossChainCreateToken(SymbolForTesting, correctIssueChainId);
    
    // 3. Verify token has wrong IssueChainId (attack succeeded)
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = SymbolForTesting });
    Assert.Equal(maliciousIssueChainId, tokenInfo.IssueChainId); // Attack confirmed
    
    // 4. Attempt cross-chain receive - will fail permanently
    var receiveResult = await CrossChainReceiveTokenAsync(
        SymbolForTesting, correctIssueChainId);
    Assert.Contains("Incorrect issue chain id.", receiveResult.Error);
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-116)
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

        if (IsAliasSettingExists(tokenInfo))
        {
            Assert(symbolType == SymbolType.NftCollection, "Token alias can only be set for NFT Item.");
            SetTokenAlias(tokenInfo);
        }

        CheckTokenExists(tokenInfo.Symbol);
        RegisterTokenInfo(tokenInfo);
        if (string.IsNullOrEmpty(State.NativeTokenSymbol.Value))
        {
            Assert(Context.Variables.NativeSymbol == input.Symbol, "Invalid native token input.");
            State.NativeTokenSymbol.Value = input.Symbol;
        }

        var systemContractAddresses = Context.GetSystemContractNameToAddressMapping().Select(m => m.Value);
        var isSystemContractAddress = input.LockWhiteList.All(l => systemContractAddresses.Contains(l));
        Assert(isSystemContractAddress, "Addresses in lock white list should be system contract addresses");
        foreach (var address in input.LockWhiteList) State.LockWhiteLists[input.Symbol][address] = true;

        Context.LogDebug(() => $"Token created: {input.Symbol}");

        Context.Fire(new TokenCreated
        {
            Symbol = tokenInfo.Symbol,
            TokenName = tokenInfo.TokenName,
            TotalSupply = tokenInfo.TotalSupply,
            Decimals = tokenInfo.Decimals,
            Issuer = tokenInfo.Issuer,
            IsBurnable = tokenInfo.IsBurnable,
            IssueChainId = tokenInfo.IssueChainId,
            ExternalInfo = tokenInfo.ExternalInfo,
            Owner = tokenInfo.Owner
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L154-178)
```csharp
    public override Empty Issue(IssueInput input)
    {
        Assert(input.To != null, "To address not filled.");
        AssertValidMemo(input.Memo);
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
        Assert(tokenInfo.Issuer == Context.Sender || Context.Sender == Context.GetZeroSmartContractAddress(),
            $"Sender is not allowed to issue token {input.Symbol}.");

        tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);

        Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(input.To, input.Symbol, input.Amount);

        Context.Fire(new Issued
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = input.To,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L438-460)
```csharp
    public override Empty ValidateTokenInfoExists(ValidateTokenInfoExistsInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo == null) throw new AssertionException("Token validation failed.");

        var validationResult = tokenInfo.TokenName == input.TokenName &&
                               tokenInfo.IsBurnable == input.IsBurnable && tokenInfo.Decimals == input.Decimals &&
                               tokenInfo.Issuer == input.Issuer && tokenInfo.TotalSupply == input.TotalSupply &&
                               tokenInfo.IssueChainId == input.IssueChainId && tokenInfo.Owner == input.Owner;

        if (tokenInfo.ExternalInfo != null && tokenInfo.ExternalInfo.Value.Count > 0 ||
            input.ExternalInfo != null && input.ExternalInfo.Count > 0)
        {
            validationResult = validationResult && tokenInfo.ExternalInfo.Value.Count == input.ExternalInfo.Count;
            if (tokenInfo.ExternalInfo.Value.Any(keyPair =>
                    !input.ExternalInfo.ContainsKey(keyPair.Key) || input.ExternalInfo[keyPair.Key] != keyPair.Value))
                throw new AssertionException("Token validation failed.");
        }

        Assert(validationResult, "Token validation failed.");
        return new Empty();
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-630)
```csharp
    public override Empty CrossChainReceiveToken(CrossChainReceiveTokenInput input)
    {
        var transferTransaction = Transaction.Parser.ParseFrom(input.TransferTransactionBytes);
        var transferTransactionId = transferTransaction.GetHash();

        Assert(!State.VerifiedCrossChainTransferTransaction[transferTransactionId],
            "Token already claimed.");

        var crossChainTransferInput =
            CrossChainTransferInput.Parser.ParseFrom(transferTransaction.Params.ToByteArray());
        var symbol = crossChainTransferInput.Symbol;
        var amount = crossChainTransferInput.Amount;
        var receivingAddress = crossChainTransferInput.To;
        var targetChainId = crossChainTransferInput.ToChainId;
        var transferSender = transferTransaction.From;

        var tokenInfo = AssertValidToken(symbol, amount);
        var issueChainId = GetIssueChainId(tokenInfo.Symbol);
        Assert(issueChainId == crossChainTransferInput.IssueChainId, "Incorrect issue chain id.");
        Assert(targetChainId == Context.ChainId, "Unable to claim cross chain token.");
        var registeredTokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        AssertCrossChainTransaction(transferTransaction, registeredTokenContractAddress,
            nameof(CrossChainTransfer));
        Context.LogDebug(() =>
            $"symbol == {tokenInfo.Symbol}, amount == {amount}, receivingAddress == {receivingAddress}, targetChainId == {targetChainId}");

        CrossChainVerify(transferTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);

        State.VerifiedCrossChainTransferTransaction[transferTransactionId] = true;
        tokenInfo.Supply = tokenInfo.Supply.Add(amount);
        Assert(tokenInfo.Supply <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(receivingAddress, tokenInfo.Symbol, amount);

        Context.Fire(new CrossChainReceived
        {
            From = transferSender,
            To = receivingAddress,
            Symbol = tokenInfo.Symbol,
            Amount = amount,
```

**File:** protobuf/token_contract.proto (L279-300)
```text
message CreateInput {
    // The symbol of the token.
    string symbol = 1;
    // The full name of the token.
    string token_name = 2;
    // The total supply of the token.
    int64 total_supply = 3;
    // The precision of the token
    int32 decimals = 4;
    // The address that has permission to issue the token.
    aelf.Address issuer = 5;
    // A flag indicating if this token is burnable.
    bool is_burnable = 6;
    // A whitelist address list used to lock tokens.
    repeated aelf.Address lock_white_list = 7;
    // The chain id of the token.
    int32 issue_chain_id = 8;
    // The external information of the token.
    ExternalInfo external_info = 9;
    // The address that owns the token.
    aelf.Address owner = 10;
}
```

**File:** test/AElf.Contracts.MultiTokenCrossChainTransfer.Tests/MultiTokenContractCrossChainTest.cs (L328-367)
```csharp
    [Fact(Skip = "Now we allow this.")]
    public async Task SideChain_CrossChainCreateToken_WithAlreadyCreated_Test()
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
