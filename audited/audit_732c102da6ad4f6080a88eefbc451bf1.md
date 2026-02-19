### Title
Cross-Chain Token Property Inconsistency Allows Token State Desynchronization

### Summary
The `CrossChainCreateToken` function fails to update critical token properties when a token already exists, only modifying the ExternalInfo field. This allows token properties to diverge between chains, breaking cross-chain transfer validation and enabling potential unauthorized token control through property manipulation.

### Finding Description

In `CrossChainCreateToken`, when a token with the target symbol already exists on the destination chain, the function takes the else branch and only updates the ExternalInfo field with alias information: [1](#0-0) 

This means critical token properties are never synchronized:
- **TotalSupply**: Controls maximum token issuance
- **Decimals**: Defines token precision and economics
- **Issuer**: Controls who can issue tokens
- **IsBurnable**: Controls burn capability
- **IssueChainId**: Required for cross-chain transfer validation
- **TokenName**: Token identity
- **Owner**: Controls token management rights

The `ValidateTokenInfoExists` function explicitly validates all these properties, confirming they are security-critical: [2](#0-1) 

**Attack Vector 1: Main Chain Pre-creation**
On the main chain (where `State.SideChainCreator.Value == null`), users can call `Create()` to register tokens before cross-chain creation: [3](#0-2) 

An attacker who burns a seed NFT can create a token with malicious properties (wrong issuer, supply, decimals, IssueChainId). When legitimate `CrossChainCreateToken` is later called, it will fail to overwrite these properties.

**Attack Vector 2: Property Updates Not Propagated**
If token properties are legitimately updated on the source chain (e.g., via `ModifyTokenIssuerAndOwner`), a subsequent `CrossChainCreateToken` call will not propagate these changes to the destination chain. [4](#0-3) 

**No Replay Protection**
Unlike `CrossChainReceiveToken`, which implements replay protection, `CrossChainCreateToken` has no mechanism to prevent reusing proofs or track which tokens have been synchronized: [5](#0-4) 

### Impact Explanation

**Cross-Chain Transfer Failures**
The most immediate impact is broken cross-chain transfers. The `CrossChainReceiveToken` function validates that `IssueChainId` matches between chains. If `CrossChainCreateToken` leaves the wrong `IssueChainId`, all subsequent cross-chain transfers will fail: [6](#0-5) 

**Supply Constraint Violations**
Wrong `TotalSupply` values can allow exceeding intended limits or prevent legitimate issuance. The `Issue` function enforces supply constraints: [7](#0-6) 

**Unauthorized Token Control**
If an attacker sets themselves as the `Issuer`, they can mint tokens arbitrarily. Wrong `Decimals` values fundamentally break token economics and pricing across all integrated contracts.

**Affected Parties**
- Token holders on both chains experience broken cross-chain transfers
- DApps relying on token properties receive incorrect data
- DEXs and TokenConverter contracts use wrong decimal precision
- Economic contracts distribute rewards with wrong calculations

### Likelihood Explanation

**Public Entry Point**
`CrossChainCreateToken` is a public method with no authorization checks beyond requiring the source chain's token contract to be registered in the whitelist: [8](#0-7) 

Once registration occurs (a one-time administrative action), anyone can call this function with valid merkle proofs.

**Feasible Attack on Main Chain**
The main chain allows token creation via `Create()` for users who burn a seed NFT. While this has a cost, seed NFTs are obtainable and the attack is economically rational for valuable tokens: [9](#0-8) 

**No Protective Mechanisms**
The code lacks:
1. Validation that existing token properties match the cross-chain data
2. Replay protection to prevent multiple synchronization attempts
3. Authorization checks to restrict who can initiate cross-chain token creation
4. Consistency checks between chains before accepting tokens

**High Probability Scenarios**
- Legitimate tokens created on both chains independently (race condition)
- Attacker front-running known cross-chain token deployments
- Property updates on source chain not propagating to destination
- Accidental double-creation during cross-chain setup

### Recommendation

**Immediate Fix: Validate or Update Existing Tokens**

Modify `CrossChainCreateToken` to validate existing token properties match the cross-chain data, or update them:

```solidity
if (State.TokenInfos[tokenInfo.Symbol] == null)
{
    RegisterTokenInfo(tokenInfo);
    // ... fire event
}
else
{
    // Validate critical properties match
    var existing = State.TokenInfos[tokenInfo.Symbol];
    Assert(existing.TotalSupply == tokenInfo.TotalSupply, "TotalSupply mismatch");
    Assert(existing.Decimals == tokenInfo.Decimals, "Decimals mismatch");
    Assert(existing.Issuer == tokenInfo.Issuer, "Issuer mismatch");
    Assert(existing.IsBurnable == tokenInfo.IsBurnable, "IsBurnable mismatch");
    Assert(existing.IssueChainId == tokenInfo.IssueChainId, "IssueChainId mismatch");
    Assert(existing.Owner == tokenInfo.Owner, "Owner mismatch");
    
    // Only then update ExternalInfo and alias
    if (isSymbolAliasSet && ...)
    {
        // ... update alias
    }
}
```

**Alternative: Allow Property Updates with Authorization**

If property synchronization is intended, require explicit authorization and add replay protection:

```solidity
// Track synchronized tokens
State.CrossChainSynchronizedTokens[input.FromChainId][tokenInfo.Symbol] = originalTransactionId;

// Check for replay
Assert(!State.CrossChainSynchronizedTokens[input.FromChainId][tokenInfo.Symbol].Value.Any(),
    "Token already synchronized from this chain");

// Update all properties when authorized
if (State.TokenInfos[tokenInfo.Symbol] != null)
{
    // Require authorization for property updates
    AssertSenderIsAuthorized();
    
    // Update all properties
    SetTokenInfo(tokenInfo);
}
```

**Add Test Coverage**

Add test cases for:
1. CrossChainCreateToken called twice with same symbol
2. Token created locally then synchronized cross-chain
3. Token properties updated on source chain then re-synchronized
4. IssueChainId mismatch causing CrossChainReceiveToken failure

### Proof of Concept

**Setup:**
1. Deploy contracts on main chain and side chain
2. Register cross-chain token contract addresses
3. Create token on side chain: Symbol="TEST", TotalSupply=1000, Decimals=18, IssueChainId=SideChainId

**Attack Step 1: Pre-create Token on Main Chain**
```
MainChainTokenContract.Create({
    Symbol: "TEST",
    TotalSupply: 999999999,
    Decimals: 8,
    Issuer: AttackerAddress,
    IssueChainId: MainChainId,
    // ... burn seed NFT
})
```

**Attack Step 2: Attempt Cross-Chain Creation**
```
ValidatedTokenInfo = SideChainTokenContract.ValidateTokenInfoExists(TEST token)
MerklePath = GenerateMerkleProof(ValidatedTokenInfo)

MainChainTokenContract.CrossChainCreateToken({
    FromChainId: SideChainId,
    TransactionBytes: ValidatedTokenInfo,
    MerklePath: MerklePath,
    ParentChainHeight: Height
})
```

**Result:**
- Function succeeds but only updates ExternalInfo
- Token on main chain keeps: TotalSupply=999999999, Decimals=8, Issuer=AttackerAddress, IssueChainId=MainChainId
- Token on side chain has: TotalSupply=1000, Decimals=18, IssueChainId=SideChainId

**Impact Verification:**
Attempt cross-chain transfer from side chain to main chain:
```
CrossChainReceiveToken will fail at line 609:
Assert(issueChainId == crossChainTransferInput.IssueChainId, "Incorrect issue chain id.")
// Because main chain token has IssueChainId=MainChainId
// But transfer specifies IssueChainId=SideChainId
```

All cross-chain transfers permanently broken for this token.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-638)
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
            Memo = crossChainTransferInput.Memo,
            FromChainId = input.FromChainId,
            ParentChainHeight = input.ParentChainHeight,
            IssueChainId = issueChainId,
            TransferTransactionId = transferTransactionId
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L642-659)
```csharp
    public override Empty ModifyTokenIssuerAndOwner(ModifyTokenIssuerAndOwnerInput input)
    {
        Assert(!State.TokenIssuerAndOwnerModificationDisabled.Value, "Set token issuer and owner disabled.");
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        Assert(input.Issuer != null && !input.Issuer.Value.IsNullOrEmpty(), "Invalid input issuer.");
        Assert(input.Owner != null && !input.Owner.Value.IsNullOrEmpty(), "Invalid input owner.");

        var tokenInfo = GetTokenInfo(input.Symbol);

        Assert(tokenInfo != null, "Token is not found.");
        Assert(tokenInfo.Issuer == Context.Sender, "Only token issuer can set token issuer and owner.");
        Assert(tokenInfo.Owner == null, "Can only set token which does not have owner.");
        
        tokenInfo.Issuer = input.Issuer;
        tokenInfo.Owner = input.Owner;

        return new Empty();
    }
```
