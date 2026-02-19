### Title
Cross-Chain Token Creation Bypasses TokenName Length Validation Allowing Unbounded Names

### Summary
The `CrossChainCreateToken` method does not validate the `TokenName` length against the 80-character limit enforced by `AssertValidCreateInput`, allowing tokens with arbitrarily large names to be created via cross-chain transfers. This creates an inconsistency where locally-created tokens have strict name length limits while cross-chain imported tokens do not, leading to storage bloat and potential denial-of-service through state growth.

### Finding Description

The vulnerability exists due to missing validation in the cross-chain token creation path:

**Vulnerable Path (CrossChainCreateToken):** [1](#0-0) 

This method constructs a `TokenInfo` object directly from the cross-chain input at lines 492-503 and then calls `RegisterTokenInfo` at line 508 without any length validation on `TokenName`.

**Protected Path (CreateToken):** [2](#0-1) 

The local token creation path calls `AssertValidCreateInput` at line 50, which validates: [3](#0-2) 

This enforces `input.TokenName.Length <= TokenContractConstants.TokenNameLength` at line 274, where the constant is defined as 80: [4](#0-3) 

**Insufficient Validation (RegisterTokenInfo):** [5](#0-4) 

The `RegisterTokenInfo` method only validates that `TokenName` is not empty at line 228, but does not check the maximum length. Since `CrossChainCreateToken` calls this method directly without prior length validation, oversized token names can be registered.

**Root Cause:**
The cross-chain verification at line 488 only validates the merkle proof cryptographically, not the semantic validity of token parameters against local chain rules. The protobuf definition has no length constraint: [6](#0-5) 

### Impact Explanation

**Direct Impacts:**
1. **Storage Bloat**: Token names of unlimited length (e.g., 10,000+ characters) consume excessive contract storage, increasing state size permanently
2. **Gas Inefficiency**: Reading/writing oversized token names costs significantly more gas, affecting all subsequent token operations
3. **UI/Display Issues**: Frontend applications and block explorers may crash or malfunction when attempting to display extremely long token names
4. **Inconsistent Security Model**: Creates two classes of tokens with different validation rules, breaking the invariant that all tokens follow the same constraints

**Severity Justification:**
- Medium severity due to operational impact and state growth DoS potential
- Cannot directly steal funds but can degrade system performance significantly
- Affects all users interacting with the malicious token
- Permanent state pollution that cannot be easily remediated

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Control or compromise a side chain registered in the cross-chain whitelist
2. Ability to create tokens on that side chain
3. Ability to submit cross-chain merkle proofs to the main chain

**Attack Complexity:**
- Low complexity once side chain control is achieved
- Cross-chain infrastructure is already in place and operational
- No sophisticated cryptographic or economic manipulation required

**Feasibility Conditions:**
- The `CrossChainCreateToken` method is a public override method callable by anyone with valid merkle proofs
- The cross-chain token contract registration system already exists and is actively used
- Side chains may have relaxed validation or could be compromised through governance attacks

**Probability Reasoning:**
- While full side chain compromise is significant, governance attacks or malicious side chain operators are realistic threat vectors
- The cost of creating oversized token names is minimal once side chain access is obtained
- No economic disincentive exists to prevent this attack
- Detection is delayed until the malicious token is already registered on the main chain

### Recommendation

**Code-Level Mitigation:**

Add validation in `CrossChainCreateToken` before calling `RegisterTokenInfo`:

```csharp
public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
{
    // ... existing code ...
    
    var validateTokenInfoExistsInput =
        ValidateTokenInfoExistsInput.Parser.ParseFrom(originalTransaction.Params);
    
    // ADD THIS VALIDATION:
    Assert(validateTokenInfoExistsInput.TokenName.Length <= TokenContractConstants.TokenNameLength,
        "Token name exceeds maximum length.");
    Assert(validateTokenInfoExistsInput.Symbol.Length > 0 &&
           validateTokenInfoExistsInput.Decimals >= 0 &&
           validateTokenInfoExistsInput.Decimals <= TokenContractConstants.MaxDecimals,
        "Invalid token parameters.");
    
    AssertNftCollectionExist(validateTokenInfoExistsInput.Symbol);
    // ... rest of existing code ...
}
```

**Invariant Checks to Add:**
- Enforce that all cross-chain imported tokens must satisfy the same validation rules as locally-created tokens
- Add length checks for all string fields in `ValidateTokenInfoExistsInput` (Symbol, TokenName, ExternalInfo keys/values)

**Test Cases:**
1. Test `CrossChainCreateToken` with TokenName exceeding 80 characters - should fail
2. Test `CrossChainCreateToken` with TokenName at exactly 80 characters - should succeed
3. Test that extremely long TokenName (e.g., 10,000 characters) is rejected with clear error message
4. Regression test ensuring local `CreateToken` path still enforces the 80-character limit

### Proof of Concept

**Required Initial State:**
1. Side chain (ChainId: SideChain1) is registered in `State.CrossChainTransferWhiteList`
2. Side chain's token contract address is whitelisted via `RegisterCrossChainTokenContractAddress`

**Attack Steps:**

1. **On Side Chain:** Create a token with oversized name (1000 characters)
   - Symbol: "EVIL"
   - TokenName: "A" repeated 1000 times
   - Create token through normal flow (may require modified side chain validation)

2. **On Side Chain:** Call `ValidateTokenInfoExists` with the oversized token parameters
   - Transaction is recorded with merkle proof

3. **On Main Chain:** Submit `CrossChainCreateToken` with:
   - FromChainId: SideChain1
   - TransactionBytes: ValidateTokenInfoExists transaction
   - MerklePath: Valid merkle proof from side chain
   - ParentChainHeight: Current height

4. **Result:**
   - Cross-chain verification passes (merkle proof is valid)
   - `AssertNftCollectionExist` passes (not an NFT or collection exists)
   - `RegisterTokenInfo` called with 1000-character TokenName
   - Only checks TokenName is not empty at line 228 - **PASSES**
   - No check for length <= 80 - **BYPASSED**
   - Token "EVIL" is registered with 1000-character name in `State.TokenInfos`

**Expected vs Actual:**
- Expected: Transaction should fail with "Token name exceeds maximum length" error
- Actual: Transaction succeeds, storing 1000-character TokenName permanently in contract state

**Success Condition:**
Query `GetTokenInfo("EVIL")` returns a TokenInfo with TokenName.Length == 1000, demonstrating the validation bypass and confirming the vulnerability.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L224-234)
```csharp
    private void RegisterTokenInfo(TokenInfo tokenInfo)
    {
        Assert(!string.IsNullOrEmpty(tokenInfo.Symbol) && IsValidSymbol(tokenInfo.Symbol),
            "Invalid symbol.");
        Assert(!string.IsNullOrEmpty(tokenInfo.TokenName), "Token name can neither be null nor empty.");
        Assert(tokenInfo.TotalSupply > 0, "Invalid total supply.");
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
        Assert(tokenInfo.Owner != null, "Invalid owner address.");
        State.TokenInfos[tokenInfo.Symbol] = tokenInfo;
        State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()] = true;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L5-5)
```csharp
    public const int TokenNameLength = 80;
```

**File:** protobuf/token_contract_impl.proto (L251-270)
```text
message ValidateTokenInfoExistsInput{
    // The symbol of the token.
    string symbol = 1;
    // The full name of the token.
    string token_name = 2;
    // The total supply of the token.
    int64 total_supply = 3;
    // The precision of the token.
    int32 decimals = 4;
    // The address that has permission to issue the token.
    aelf.Address issuer = 5;
    // A flag indicating if this token is burnable.
    bool is_burnable = 6;
    // The chain id of the token.
    int32 issue_chain_id = 7;
    // The external information of the token.
    map<string, string> external_info = 8;
    // The address that owns the token.
    aelf.Address owner = 9;
}
```
