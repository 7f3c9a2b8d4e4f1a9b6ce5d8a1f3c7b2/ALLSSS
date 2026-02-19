### Title
Missing Dictionary Key Validation in CrossChainCreate Causes KeyNotFoundException and DoS

### Summary
The `CrossChainCreate` function in the NFT contract directly accesses `tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey]` and `tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]` without checking if these keys exist in the dictionary. This causes a `KeyNotFoundException` when a token exists without the required NFT metadata keys, enabling a DoS attack that prevents legitimate NFT protocol creation on sidechains.

### Finding Description

The vulnerability exists in the `CrossChainCreate` method where dictionary keys are accessed without validation: [1](#0-0) 

The method only checks if the token exists but does not validate that the `ExternalInfo` contains the required NFT metadata keys: [2](#0-1) 

**Root Cause:**

The normal NFT creation flow through `Create()` guarantees these keys are added to `ExternalInfo`: [3](#0-2) 

However, the `MultiToken` contract's `Create` method accepts arbitrary `ExternalInfo` without requiring NFT-specific metadata: [4](#0-3) 

This allows anyone with token creation permissions (via whitelist or seed NFT ownership) to create tokens with NFT collection symbol formats (e.g., "ABART-0") but incomplete `ExternalInfo`. When such tokens are synced to sidechains via `CrossChainCreateToken`: [5](#0-4) 

The incomplete `ExternalInfo` is preserved, and subsequent calls to `NFT.CrossChainCreate()` will throw `KeyNotFoundException`.

**Why Existing Protections Fail:**

The `CrossChainCreate` method has no authorization checks and can be called by anyone: [6](#0-5) 

The `MultiToken` contract itself uses the correct pattern (`ContainsKey` checks before access): [7](#0-6) [8](#0-7) 

But the NFT contract does not follow this defensive pattern.

### Impact Explanation

**Concrete Harm:**
- **DoS of NFT Protocol Creation**: Attackers can permanently block legitimate NFT protocols from being created on sidechains by pre-creating tokens with matching symbols but incomplete metadata
- **Cross-Chain Griefing**: Any token created on the mainchain (or any chain) without proper NFT metadata will cause failures when users attempt to call `CrossChainCreate` on sidechains
- **Operational Disruption**: All calls to `CrossChainCreate` for affected symbols will throw unhandled exceptions, breaking the cross-chain NFT protocol synchronization flow

**Who is Affected:**
- NFT protocol creators attempting to sync their protocols to sidechains
- Sidechain users unable to access NFT protocols due to blocked creation
- The broader AElf ecosystem's cross-chain NFT functionality

**Severity Justification:**
High severity due to:
1. Complete DoS of cross-chain NFT protocol creation for affected symbols
2. No recovery mechanism - once a token with incomplete metadata exists, the NFT protocol cannot be created on sidechains for that symbol
3. Low barrier to exploit - only requires seed NFT ownership or whitelist access
4. Permanent impact - the malicious token remains indefinitely

### Likelihood Explanation

**Attacker Capabilities:**
- Must have permission to call `TokenContract.Create()` by either:
  - Being in the create whitelist, OR
  - Owning a seed NFT for the desired symbol [9](#0-8) 

**Attack Complexity:**
Low - The attack requires only:
1. One call to `TokenContract.Create()` with an NFT collection symbol format and empty/incomplete `ExternalInfo`
2. Natural cross-chain token synchronization occurs automatically
3. Any user calling `CrossChainCreate()` triggers the exception

**Feasibility Conditions:**
- Attacker must obtain seed NFT (can be purchased/obtained through normal means)
- Victim must attempt to call `CrossChainCreate()` for the affected symbol (normal operation)
- No special timing or state requirements

**Detection/Operational Constraints:**
- Attack is difficult to detect until `CrossChainCreate()` is called
- No alerts or validation prevent the malicious token creation
- Standard cross-chain synchronization propagates the vulnerability automatically

**Probability Reasoning:**
Medium-High likelihood because:
- Seed NFTs are obtainable through normal protocol mechanisms
- The attack is straightforward with clear motivation (griefing competitors' NFT protocols)
- No technical sophistication required beyond understanding the token creation flow

### Recommendation

**Code-Level Mitigation:**

Add dictionary key existence validation before accessing `ExternalInfo.Value`:

```csharp
public override Empty CrossChainCreate(CrossChainCreateInput input)
{
    MakeSureTokenContractAddressSet();
    InitialNFTTypeNameMap();
    Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
    var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
    {
        Symbol = input.Symbol
    });
    if (string.IsNullOrEmpty(tokenInfo.Symbol))
        throw new AssertionException($"Token info {input.Symbol} not exists.");

    // ADD VALIDATION HERE
    if (!tokenInfo.ExternalInfo.Value.ContainsKey(NftBaseUriMetadataKey))
        throw new AssertionException($"Token {input.Symbol} missing required NFT metadata: {NftBaseUriMetadataKey}");
    if (!tokenInfo.ExternalInfo.Value.ContainsKey(NftTokenIdReuseMetadataKey))
        throw new AssertionException($"Token {input.Symbol} missing required NFT metadata: {NftTokenIdReuseMetadataKey}");
    
    var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
    var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
    // ... rest of method
}
```

Alternatively, use `TryGetValue` pattern:

```csharp
if (!tokenInfo.ExternalInfo.Value.TryGetValue(NftBaseUriMetadataKey, out var baseUri))
    throw new AssertionException($"Token {input.Symbol} missing required NFT metadata: {NftBaseUriMetadataKey}");
if (!tokenInfo.ExternalInfo.Value.TryGetValue(NftTokenIdReuseMetadataKey, out var isTokenIdReuseStr))
    throw new AssertionException($"Token {input.Symbol} missing required NFT metadata: {NftTokenIdReuseMetadataKey}");
var isTokenIdReuse = bool.Parse(isTokenIdReuseStr);
```

**Test Cases to Add:**

1. Test `CrossChainCreate` with token missing `NftBaseUriMetadataKey` - should fail gracefully
2. Test `CrossChainCreate` with token missing `NftTokenIdReuseMetadataKey` - should fail gracefully
3. Test `CrossChainCreate` with token having both required keys - should succeed
4. Test that tokens created via direct `TokenContract.Create()` without NFT metadata cannot be used with `CrossChainCreate`

### Proof of Concept

**Initial State:**
- Mainchain: AElf mainchain with deployed NFT and MultiToken contracts
- Sidechain: Sidechain with deployed NFT and MultiToken contracts, cross-chain token sync enabled
- Attacker: Address with seed NFT for symbol "ABART"

**Attack Steps:**

1. **Attacker creates malicious token on mainchain:**
   ```
   Call: TokenContract.Create({
       Symbol: "ABART-0",
       TokenName: "Malicious Art Collection",
       TotalSupply: 10000,
       Decimals: 0,
       Issuer: attackerAddress,
       IsBurnable: true,
       IssueChainId: mainChainId,
       ExternalInfo: {}  // Empty - missing NFT metadata keys
   })
   ```

2. **Token automatically syncs to sidechain via CrossChainCreateToken** (normal cross-chain operation)

3. **Legitimate user attempts to create NFT protocol on sidechain:**
   ```
   Call: NFTContract.CrossChainCreate({
       Symbol: "ABART-0"
   })
   ```

**Expected Result:**
NFT protocol created successfully on sidechain

**Actual Result:**
Transaction fails with `KeyNotFoundException` at line 87:
```
System.Collections.Generic.KeyNotFoundException: The given key 'aelf_nft_base_uri' was not present in the dictionary.
```

**Success Condition for Attack:**
The `CrossChainCreate` call fails with exception, permanently preventing the NFT protocol from being created on the sidechain for symbol "ABART-0".

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-79)
```csharp
    public override Empty CrossChainCreate(CrossChainCreateInput input)
    {
        MakeSureTokenContractAddressSet();
        InitialNFTTypeNameMap();
        Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L84-85)
```csharp
        if (string.IsNullOrEmpty(tokenInfo.Symbol))
            throw new AssertionException($"Token info {input.Symbol} not exists.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L87-88)
```csharp
        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L196-199)
```csharp
        tokenExternalInfo.Value[NftTypeMetadataKey] = input.NftType;
        // Add Uri to external info.
        tokenExternalInfo.Value[NftBaseUriMetadataKey] = input.BaseUri;
        tokenExternalInfo.Value[NftTokenIdReuseMetadataKey] = input.IsTokenIdReuse.ToString();
```

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L77-77)
```csharp
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L501-501)
```csharp
            ExternalInfo = new ExternalInfo { Value = { validateTokenInfoExistsInput.ExternalInfo } },
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L705-706)
```csharp
        if (tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                out var oldExpireTime))
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L326-330)
```csharp
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.LockCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.LockCallbackExternalInfoKey]);
```
