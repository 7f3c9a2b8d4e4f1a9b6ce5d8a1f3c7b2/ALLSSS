### Title
Cross-Chain Token Metadata Confusion via Unchecked IssueChainId Parameter

### Summary
The `CreateToken()` function allows creating tokens with arbitrary `IssueChainId` values without validating that it matches the current `Context.ChainId`. This enables attackers to front-run legitimate cross-chain token synchronization by creating tokens with matching symbols and IssueChainIds but malicious metadata (Issuer, Owner, TotalSupply), causing permanent metadata confusion since `CrossChainCreateToken()` does not overwrite existing tokens.

### Finding Description

**Root Cause:**
At line 76 in `CreateToken()`, the IssueChainId is set without validation: [1](#0-0) 

The function accepts any non-zero `input.IssueChainId` value without asserting it equals `Context.ChainId`. This allows creating tokens that claim to be issued from a different chain.

**Why Existing Protections Fail:**

1. **Issue() protection is insufficient:** While the `Issue()` function prevents issuing tokens with mismatched IssueChainId: [2](#0-1) 

This only prevents local issuance but doesn't prevent the token from being created and receiving cross-chain transfers.

2. **CrossChainCreateToken doesn't overwrite:** When legitimate cross-chain sync occurs via `CrossChainCreateToken()`, if the token already exists, it only updates alias information and does NOT overwrite the token metadata: [3](#0-2) 

The else branch (lines 522-531) only adds alias information, leaving the attacker's Issuer, Owner, and TotalSupply intact.

3. **CrossChainReceiveToken accepts squatted tokens:** When cross-chain transfers arrive, only the IssueChainId is validated, not the Issuer/Owner metadata: [4](#0-3) 

The function uses the local token info (potentially attacker's version) and only checks IssueChainId match, allowing tokens with wrong metadata to receive cross-chain transfers.

**Exploitation Path:**
1. Attacker on Main Chain obtains Seed NFT for target symbol (e.g., "LEGIT")
2. Attacker calls `Create()` with Symbol="LEGIT", IssueChainId=SideChainAId (not MainChainId), and attacker's addresses for Issuer/Owner
3. Token is created on Main Chain with IssueChainId=SideChainAId but cannot be issued locally
4. Legitimate issuer creates "LEGIT" on Side Chain A with IssueChainId=SideChainAId
5. When legitimate `CrossChainCreateToken` is called on Main Chain, it finds the token exists and only updates alias (lines 522-531)
6. Cross-chain transfers via `CrossChainReceiveToken` succeed because IssueChainId matches, but use the squatted token's metadata

### Impact Explanation

**Concrete Harm:**
- **Token Metadata Spoofing**: Users on the destination chain see incorrect Issuer and Owner addresses for received tokens, breaking trust and token identification
- **TotalSupply Confusion**: The squatted token can have arbitrary TotalSupply (e.g., 1,000 vs legitimate 100,000,000), causing supply tracking inconsistencies
- **Cross-Chain Integrity Violation**: Legitimate cross-chain token synchronization is permanently blocked for affected symbols
- **Governance Impact**: If tokens are used for governance/voting, wrong Owner information misdirects control and authority

**Who is Affected:**
- Users receiving cross-chain transfers see wrong token metadata
- DApps querying token info get incorrect Issuer/Owner/TotalSupply
- Legitimate issuers cannot properly register their tokens cross-chain

**Severity Justification:**
High severity due to:
- Permanent metadata corruption for cross-chain tokens
- Breaks fundamental cross-chain token identification and trust
- No recovery mechanism once tokens are squatted
- Affects all users of cross-chain token transfers

### Likelihood Explanation

**Attacker Capabilities Required:**
- Obtain Seed NFT for target symbol on destination chain (requires either marketplace purchase or Seed creation mechanism access) [5](#0-4) 

**Attack Complexity:**
- Low - Straightforward call to `Create()` with specific parameters
- Requires front-running cross-chain sync, but cross-chain operations have latency making timing feasible
- No specialized technical knowledge beyond understanding the IssueChainId parameter

**Feasibility Conditions:**
- Attacker must acquire Seed NFT before legitimate cross-chain sync completes
- More feasible for newly created tokens or tokens with public Seed NFT availability
- Economic cost: Seed NFT acquisition cost (market dependent)

**Detection Constraints:**
- Attack leaves permanent state: token exists with wrong metadata
- Observable via GetTokenInfo queries showing mismatched Issuer/Owner
- No automated prevention mechanism exists

**Probability Reasoning:**
Medium-to-High likelihood because:
- Attack vector is straightforward once Seed NFT obtained
- Cross-chain sync latency provides timing window
- Economic incentive exists for governance tokens or valuable symbols
- No existing validation prevents the attack

### Recommendation

**Code-Level Mitigation:**

1. **Add IssueChainId validation in CreateToken()**: After line 76, add:
```csharp
Assert(tokenInfo.IssueChainId == Context.ChainId, 
    "IssueChainId must match current chain. Use CrossChainCreateToken for cross-chain tokens.");
``` [1](#0-0) 

2. **Enhance CrossChainCreateToken() validation**: At line 506, before the null check, validate existing token metadata matches if token exists:
```csharp
var existingToken = State.TokenInfos[tokenInfo.Symbol];
if (existingToken != null)
{
    Assert(existingToken.IssueChainId == tokenInfo.IssueChainId &&
           existingToken.Issuer == tokenInfo.Issuer &&
           existingToken.Owner == tokenInfo.Owner &&
           existingToken.TotalSupply == tokenInfo.TotalSupply,
           "Existing token metadata mismatch with cross-chain source.");
}
``` [6](#0-5) 

**Invariant Check to Add:**
- `tokenInfo.IssueChainId == Context.ChainId` must hold for all tokens created via `Create()` (not `CrossChainCreateToken()`)

**Test Cases:**
1. Test creating token with IssueChainId != Context.ChainId should fail
2. Test CrossChainCreateToken rejects when existing token has different metadata
3. Test legitimate token creation and cross-chain sync succeeds without conflicts

### Proof of Concept

**Required Initial State:**
- Main Chain and Side Chain A both operational
- Attacker has Seed NFT for symbol "LEGIT" on Main Chain
- Legitimate issuer controls LegitAddress

**Transaction Steps:**

1. **On Side Chain A (Legitimate):**
   - LegitAddress calls `Create()`: Symbol="LEGIT", IssueChainId=SideChainAId, Issuer=LegitAddress, Owner=LegitAddress, TotalSupply=100000000
   - LegitAddress calls `Issue()`: issues 50000000 LEGIT

2. **On Main Chain (Attack - executed before cross-chain sync):**
   - AttackerAddress calls `Create()`: Symbol="LEGIT", IssueChainId=SideChainAId (note: NOT MainChainId!), Issuer=AttackerAddress, Owner=AttackerAddress, TotalSupply=1000
   - Token created successfully with wrong metadata

3. **Cross-Chain Sync Attempt:**
   - Call `ValidateTokenInfoExists` on Side Chain A with legitimate metadata
   - Call `CrossChainCreateToken` on Main Chain with proof
   - Result: Lines 522-531 executed (else branch), legitimate metadata NOT registered

4. **Cross-Chain Transfer:**
   - User calls `CrossChainTransfer` on Side Chain A: 1000 LEGIT to Main Chain
   - User calls `CrossChainReceiveToken` on Main Chain
   - Line 609 check passes (IssueChainId matches)
   - Balance credited successfully

**Expected vs Actual Result:**
- **Expected**: Main Chain token "LEGIT" shows Issuer=LegitAddress, Owner=LegitAddress, TotalSupply=100000000
- **Actual**: Main Chain token "LEGIT" shows Issuer=AttackerAddress, Owner=AttackerAddress, TotalSupply=1000

**Success Condition:**
Query `GetTokenInfo` for "LEGIT" on Main Chain returns AttackerAddress as Issuer/Owner despite legitimate token existing on Side Chain A, demonstrating metadata confusion vulnerability.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L76-76)
```csharp
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L159-159)
```csharp
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L607-609)
```csharp
        var tokenInfo = AssertValidToken(symbol, amount);
        var issueChainId = GetIssueChainId(tokenInfo.Symbol);
        Assert(issueChainId == crossChainTransferInput.IssueChainId, "Incorrect issue chain id.");
```
