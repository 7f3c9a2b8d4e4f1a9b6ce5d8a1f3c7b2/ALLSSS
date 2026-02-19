# Audit Report

## Title
Case-Insensitive Token Uniqueness Bypass via CrossChainCreateToken

## Summary
The `CrossChainCreateToken` method in the MultiToken contract bypasses case-insensitive token uniqueness validation by performing only a case-sensitive existence check before registering tokens. This allows an attacker controlling a registered side-chain to create tokens that differ only in case (e.g., "token" after "TOKEN"), violating the protocol's fundamental design invariant enforced by `State.InsensitiveTokenExisting`.

## Finding Description

The AElf MultiToken contract implements case-insensitive token uniqueness through the `State.InsensitiveTokenExisting` mapped state, which stores uppercased token symbols to prevent creation of tokens differing only in case. [1](#0-0) 

**Secure Path (Normal Token Creation):**

The standard token creation flow properly enforces this invariant. The `CreateToken` method calls `CheckTokenExists` before registering the token. [2](#0-1) 

The `CheckTokenExists` method validates case-insensitive uniqueness by checking the uppercased symbol against `State.InsensitiveTokenExisting`. [3](#0-2) 

**Vulnerable Path (Cross-Chain Token Creation):**

The `CrossChainCreateToken` method bypasses this validation. After verifying cross-chain proofs, it calls `AssertNftCollectionExist` which returns null for non-NFT tokens, providing no validation. [4](#0-3) 

It then performs only a case-sensitive check before calling `RegisterTokenInfo`. [5](#0-4) 

**Root Cause:**

The case-sensitive check `if (State.TokenInfos[tokenInfo.Symbol] == null)` is insufficient because `State.TokenInfos` uses case-sensitive string keys. If "TOKEN" exists, checking for "token" returns null, allowing the duplicate registration. [6](#0-5) 

The `RegisterTokenInfo` method unconditionally sets both states without validation. [7](#0-6) 

**Attack Scenario:**
1. Legitimate token "TOKEN" exists on the destination chain
2. Attacker controls a registered side-chain token contract
3. Attacker creates token "token" (lowercase) on their side-chain
4. Attacker calls `CrossChainCreateToken` with valid merkle proofs
5. Line 506 check passes (case-sensitive: `State.TokenInfos["token"]` is null)
6. `RegisterTokenInfo` creates `State.TokenInfos["token"]` as a separate entry
7. Both "TOKEN" and "token" now exist as independent tokens with separate balances, supplies, and issuers

## Impact Explanation

**Protocol Integrity Violation:**
The protocol explicitly designed case-insensitive token uniqueness enforcement through the `State.InsensitiveTokenExisting` mechanism. This vulnerability completely undermines that design.

**Concrete Harms:**
1. **Token Impersonation:** An attacker can create "elf" to impersonate the legitimate "ELF" token, or "usdt" to impersonate "USDT"
2. **User Financial Loss:** Users and applications relying on symbol-based token identification will interact with the wrong token, leading to financial losses
3. **Independent Token State:** Both tokens exist with completely separate `State.TokenInfos` entries, meaning separate balances, total supplies, issuers, and all other token properties
4. **Symbol Resolution Confusion:** `GetTokenInfo("TOKEN")` and `GetTokenInfo("token")` return different tokens since lookups are case-sensitive, breaking assumptions in DApps and user interfaces

**Affected Parties:**
- Token holders who may receive or purchase the wrong token
- DApps and smart contracts using symbol-based token operations
- Cross-chain bridge users
- DEX and marketplace platforms that assume token symbol uniqueness

**Severity:** HIGH - This violates a fundamental protocol invariant, enables targeted impersonation attacks against high-value tokens, and causes direct financial harm to users.

## Likelihood Explanation

**Reachable Entry Point:**
`CrossChainCreateToken` is a public method callable by any user with valid cross-chain merkle proofs. [8](#0-7) 

**Attacker Requirements:**
1. Control or deploy a side-chain in the AElf ecosystem
2. Register their side-chain's token contract address (requires Parliament approval but is achievable through standard governance)
3. Create a token with different case on their side-chain  
4. Generate valid cross-chain merkle proofs (standard functionality)

**Execution Practicality:**
- Cross-chain token creation is actively used and tested functionality in the codebase
- The attack follows the normal cross-chain token creation flow
- No exceptional permissions required beyond a registered token contract address
- Technical barriers are low once side-chain registration is achieved

**Economic Rationality:**
- Cost: Side-chain deployment and Parliament approval for registration
- Benefit: Ability to impersonate high-value tokens (stablecoins, governance tokens) for profit through user confusion
- For high-value targets, the attack is economically rational

**Probability Assessment:** MEDIUM-HIGH likelihood, especially in environments with permissionless or semi-permissionless side-chain creation. The technical execution is straightforward once governance approval is obtained.

## Recommendation

Add the `CheckTokenExists` validation call in `CrossChainCreateToken` before calling `RegisterTokenInfo`, consistent with the normal token creation flow:

```csharp
if (State.TokenInfos[tokenInfo.Symbol] == null)
{
    CheckTokenExists(tokenInfo.Symbol); // ADD THIS LINE
    RegisterTokenInfo(tokenInfo);
    Context.Fire(new TokenCreated { ... });
}
```

This ensures case-insensitive uniqueness is enforced for all token creation paths, not just the standard `Create` method.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainCreateToken_CaseInsensitive_Bypass_Test()
{
    await GenerateSideChainAsync();
    await RegisterSideChainContractAddressOnMainChainAsync();
    await BootMinerChangeRoundAsync(AEDPoSContractStub, true);
    
    // Step 1: Create uppercase token "TOKEN" on main chain
    var createTransaction = await CreateTransactionForTokenCreation(
        TokenContractStub, 
        DefaultAccount.Address, 
        "TOKEN", // UPPERCASE
        TokenContractAddress);
    var blockExecutedSet = await MineAsync(new List<Transaction> { createTransaction });
    var createResult = blockExecutedSet.TransactionResultMap[createTransaction.GetHash()];
    Assert.True(createResult.Status == TransactionResultStatus.Mined, createResult.Error);
    
    // Step 2: Create lowercase token "token" on side chain
    var sideCreateTransaction = await CreateTransactionForTokenCreation(
        SideChainTokenContractStub,
        SideChainTestKit.DefaultAccount.Address, 
        "token", // lowercase - different case!
        SideTokenContractAddress);
    blockExecutedSet = await SideChainTestKit.MineAsync(new List<Transaction> { sideCreateTransaction });
    var sideCreateResult = blockExecutedSet.TransactionResultMap[sideCreateTransaction.GetHash()];
    Assert.True(sideCreateResult.Status == TransactionResultStatus.Mined, sideCreateResult.Error);
    
    // Step 3: Get token info from side chain and validate it
    var sideTokenInfo = await SideChainTokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "token" });
    var tokenValidationTransaction = CreateTokenInfoValidationTransaction(
        sideTokenInfo, 
        SideChainTokenContractStub);
    var executedSet = await SideChainTestKit.MineAsync(new List<Transaction> { tokenValidationTransaction });
    
    // Step 4: Index side chain transaction on main chain
    var merklePath = GetTransactionMerklePathAndRoot(tokenValidationTransaction, out var blockRoot);
    await IndexSideChainTransactionAsync(executedSet.Height, blockRoot, blockRoot);
    
    // Step 5: Call CrossChainCreateToken with lowercase "token" on main chain
    var crossChainCreateTokenInput = new CrossChainCreateTokenInput
    {
        FromChainId = SideChainId,
        ParentChainHeight = executedSet.Height,
        TransactionBytes = tokenValidationTransaction.ToByteString(),
        MerklePath = merklePath
    };
    
    var executionResult = await TokenContractStub.CrossChainCreateToken.SendAsync(
        crossChainCreateTokenInput);
    
    // VULNERABILITY: This should fail but succeeds
    Assert.True(executionResult.TransactionResult.Status == TransactionResultStatus.Mined);
    
    // Verify both tokens now exist independently
    var upperToken = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "TOKEN" });
    var lowerToken = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "token" });
    
    Assert.NotNull(upperToken);
    Assert.NotNull(lowerToken);
    Assert.NotEqual(upperToken, lowerToken); // Different tokens!
    
    // This violates case-insensitive uniqueness invariant
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L17-17)
```csharp
    public MappedState<string, bool> InsensitiveTokenExisting { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L87-88)
```csharp
        CheckTokenExists(tokenInfo.Symbol);
        RegisterTokenInfo(tokenInfo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L478-479)
```csharp
    public override Empty CrossChainCreateToken(CrossChainCreateTokenInput input)
    {
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L506-508)
```csharp
        if (State.TokenInfos[tokenInfo.Symbol] == null)
        {
            RegisterTokenInfo(tokenInfo);
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L295-303)
```csharp
    private void CheckTokenExists(string symbol)
    {
        var empty = new TokenInfo();
        // check old token
        var existing = GetTokenInfo(symbol);
        Assert(existing == null || existing.Equals(empty), "Token already exists.");
        // check new token
        Assert(!State.InsensitiveTokenExisting[symbol.ToUpper()], "Token already exists.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L407-408)
```csharp
        var tokenInfo = State.TokenInfos[symbolOrAlias];
        if (tokenInfo != null) return tokenInfo;
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
