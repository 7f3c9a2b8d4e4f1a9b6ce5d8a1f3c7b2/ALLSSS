# Audit Report

## Title
Cross-Chain Token Creation Bypasses Case-Insensitive Duplicate Check, Enabling Phishing Token Creation

## Summary
The `CrossChainCreateToken` function fails to perform case-insensitive duplicate token validation before registering tokens from other chains. While normal token creation prevents case variants like "TOKEN" and "token" from coexisting, the cross-chain path only checks exact symbol matches, allowing case-variant phishing tokens to be imported from other chains.

## Finding Description

The MultiToken contract implements case-insensitive duplicate prevention through the `CheckTokenExists` helper function. This function validates both exact symbol matches and checks the `State.InsensitiveTokenExisting[symbol.ToUpper()]` mapping to prevent tokens that differ only in case from coexisting. [1](#0-0) 

When tokens are created normally via the `Create` method, this validation is properly enforced through the call chain: `CreateToken` → `AssertValidCreateInput` → `CheckTokenAndCollectionExists` → `CheckTokenExists`. [2](#0-1) [3](#0-2) 

The `RegisterTokenInfo` function stores tokens in `State.TokenInfos` and sets the case-insensitive flag `State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()] = true` to track that a token with this case-insensitive symbol exists. [4](#0-3) 

However, the `CrossChainCreateToken` function bypasses this protection entirely. At line 506, it only checks if the exact symbol exists in `State.TokenInfos` without calling `CheckTokenExists` or verifying the case-insensitive mapping, then directly calls `RegisterTokenInfo` at line 508. [5](#0-4) 

**Attack Flow:**
1. Legitimate token "TOKEN" exists on Chain A with `State.InsensitiveTokenExisting["TOKEN"] = true`
2. Attacker creates token "token" (lowercase) on Chain B using a seed NFT or whitelist access
3. Attacker calls `CrossChainCreateToken` on Chain A with a valid cross-chain proof from Chain B
4. The check `State.TokenInfos["token"] == null` passes (exact match not found)
5. `RegisterTokenInfo` is called, creating the duplicate token without case-insensitive validation
6. Both "TOKEN" and "token" now coexist on Chain A as separate tokens

## Impact Explanation

**Direct Financial Impact:**
Users interacting with case-insensitive interfaces (common in wallets and blockchain explorers) cannot distinguish between "TOKEN" and "token", leading to:
- Accidental transfers to the wrong token
- Approval of allowances for phishing tokens instead of legitimate ones
- Direct loss of funds through user confusion

**Protocol Integrity Impact:**
- Breaks the fundamental token uniqueness guarantee enforced by the `State.InsensitiveTokenExisting` state variable [6](#0-5) 
- dApps performing case-insensitive symbol lookups will exhibit unpredictable behavior
- Token pricing and trading on DEXs becomes unreliable
- Erosion of user trust in the token system

The severity is **HIGH** because it violates a core security invariant (token case-insensitive uniqueness), enables direct financial loss through user confusion, and affects multiple ecosystem participants.

## Likelihood Explanation

**Attack Complexity: MEDIUM**

Prerequisites for exploitation:
1. Access to token creation on at least one chain (requires seed NFT purchase or whitelist access - obtainable through normal means)
2. Ability to generate valid cross-chain proofs (standard cross-chain operation requiring no special privileges)
3. Target chain must have a legitimate token to impersonate

**Feasibility Assessment:**
- Entry point `CrossChainCreateToken` is publicly accessible with no special authorization
- Seed NFTs can be purchased through normal channels
- Cross-chain proofs are generated through legitimate mechanisms that any user can access
- The exploit follows the normal cross-chain token creation flow, making it indistinguishable from legitimate operations
- Economic cost (seed NFT price + transaction fees) is reasonable compared to potential gains from phishing high-value tokens

The likelihood is **MEDIUM to HIGH** because while the attack requires multi-chain setup and initial investment, it is definitively feasible for motivated attackers targeting valuable tokens. The exploit leverages legitimate cross-chain infrastructure, making detection and prevention difficult.

## Recommendation

Add case-insensitive duplicate checking to the `CrossChainCreateToken` function before calling `RegisterTokenInfo`. The fix should call `CheckTokenExists` similar to the normal token creation path:

```csharp
if (State.TokenInfos[tokenInfo.Symbol] == null)
{
    CheckTokenExists(tokenInfo.Symbol); // Add this line
    RegisterTokenInfo(tokenInfo);
    // ... rest of the code
}
```

This ensures consistent validation across all token creation paths and prevents case-variant tokens from being imported via cross-chain operations.

## Proof of Concept

A proof of concept would involve:
1. Setting up two test chains (Chain A and Chain B)
2. Creating token "TOKEN" on Chain A
3. Creating token "token" (lowercase) on Chain B
4. Generating a valid cross-chain proof for the token from Chain B
5. Calling `CrossChainCreateToken` on Chain A with the proof
6. Verifying both "TOKEN" and "token" exist as separate tokens on Chain A
7. Confirming that `State.TokenInfos["TOKEN"]` and `State.TokenInfos["token"]` both return valid TokenInfo objects

The test would demonstrate that the case-insensitive uniqueness guarantee is violated through the cross-chain creation path.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-293)
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-88)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L506-509)
```csharp
        if (State.TokenInfos[tokenInfo.Symbol] == null)
        {
            RegisterTokenInfo(tokenInfo);
            Context.Fire(new TokenCreated
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L17-17)
```csharp
    public MappedState<string, bool> InsensitiveTokenExisting { get; set; }
```
