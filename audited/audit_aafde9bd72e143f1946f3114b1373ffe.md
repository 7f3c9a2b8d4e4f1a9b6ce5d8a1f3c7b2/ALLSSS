### Title
NFT Collection ExternalInfo Poisoning Enables Permanent Symbol Squatting and DoS

### Summary
An attacker can create NFT collections with malicious `__nft_create_chain_id` values in ExternalInfo during collection creation, permanently blocking NFT creation for desirable symbols. Since ExternalInfo cannot be updated post-creation and collection symbols are unique, this enables irrevocable symbol squatting attacks.

### Finding Description

The vulnerability exists in the NFT creation flow where collection ExternalInfo is set without validation and later enforced during NFT minting.

**Collection Creation Path:** [1](#0-0) 

During collection creation via `CreateToken`, the `input.ExternalInfo` is directly assigned to `tokenInfo.ExternalInfo` without any validation of its contents or values. An attacker can set arbitrary key-value pairs, including `__nft_create_chain_id`. [2](#0-1) 

**NFT Creation Enforcement:** [3](#0-2) 

When creating NFTs, the system reads `__nft_create_chain_id` from the collection's ExternalInfo and enforces that `Context.ChainId` must match this value. If an attacker sets this to a non-existent chain ID (e.g., 999999), the assertion at line 26 always fails, permanently blocking NFT creation.

**No Recovery Mechanism:** [4](#0-3) 

The only method that updates ExternalInfo (`ExtendSeedExpirationTime`) is restricted to updating only the `__seed_exp_time` key for Seed NFTs. There is no mechanism to correct malicious `__nft_create_chain_id` values after collection creation.

**Symbol Uniqueness:** [5](#0-4) 

Collection symbols must be unique. Once a collection exists, it cannot be recreated, making the poisoning attack permanent.

**No Owner Validation:** [6](#0-5) 

The Create method does not validate that `input.Owner` or `input.Issuer` match `Context.Sender`, allowing attackers to create collections with arbitrary ownership while setting malicious ExternalInfo.

### Impact Explanation

**Direct Operational Impact:**
- Permanent DoS of NFT creation functionality for specific symbols
- Valuable symbol names (e.g., "GOLD", "DIAMOND", "RARE") can be permanently blocked from NFT use
- Legitimate projects cannot create NFT collections for targeted symbols

**Ecosystem Harm:**
- Symbol squatting enables ransom scenarios where attackers demand payment to not poison desirable symbols
- Griefing attacks can target competitors or specific projects
- Erosion of trust in the NFT ecosystem as users cannot reliably secure desired symbols

**Severity: HIGH** - This vulnerability enables permanent, unrecoverable DoS attacks on critical protocol functionality with widespread ecosystem impact. The inability to fix poisoned collections makes this particularly severe.

### Likelihood Explanation

**Attacker Capabilities:**
- Must acquire a SEED NFT for the target symbol (publicly available mechanism)
- Requires only basic knowledge of contract parameters and ExternalInfo structure
- No special privileges or insider access needed

**Attack Complexity:**
- Simple single transaction: Call `Create` with crafted ExternalInfo
- No timing requirements or race conditions
- No complex state manipulation needed

**Feasibility:**
- Entry point is public `Create` method accessible to all users
- SEED NFTs are obtainable through normal protocol mechanisms
- Attack is repeatable and deterministic

**Economic Rationality:**
- Cost: One SEED NFT per symbol (potentially significant but limited)
- Benefit: Permanent control/blocking of valuable symbols
- Ransom potential: Demand payment to not poison symbols before legitimate users
- Strategic value: Block competitors from using desirable brand symbols

**Detection Constraints:**
- Attack appears as legitimate collection creation
- Malicious ExternalInfo values are not obviously detectable until NFT creation is attempted
- No inherent red flags in transaction structure

**Likelihood: HIGH** - The attack is straightforward to execute, economically rational for valuable symbols, and faces no significant technical barriers.

### Recommendation

**Immediate Mitigation:**
1. Add validation in `CreateToken` for collection creation:
   ```
   In TokenContract_Actions.cs CreateToken method, after line 50:
   - Validate ExternalInfo keys against whitelist
   - For __nft_create_chain_id specifically:
     * Verify it matches Context.ChainId if set
     * Or enforce that it can only be set by authorized addresses
     * Or disallow setting it entirely during creation
   ```

2. Add ExternalInfo update capability:
   ```
   New method: UpdateCollectionExternalInfo
   - Restricted to collection owner
   - Only allows updating specific whitelisted keys
   - Includes __nft_create_chain_id correction
   - Emits event for transparency
   ```

3. Enforce ownership alignment:
   ```
   In Create method:
   - Assert that input.Owner == Context.Sender (or default to Context.Sender)
   - Prevent setting arbitrary ownership during creation
   ```

**Invariant Checks:**
- `__nft_create_chain_id` in ExternalInfo must either be unset or match a valid, existing chain ID
- Collection creator must be the initial owner (no arbitrary owner assignment)
- ExternalInfo keys should be validated against an allowed list during creation

**Test Cases:**
1. Attempt to create collection with invalid `__nft_create_chain_id` - should fail
2. Attempt to create collection with Owner != Sender - should fail or default Owner to Sender
3. Successfully update correctable ExternalInfo keys after creation via new update method
4. Verify NFT creation succeeds for collections with valid or unset `__nft_create_chain_id`

### Proof of Concept

**Initial State:**
- Attacker acquires SEED NFT for symbol "RARE" (symbol to be squatted)
- Target: Block "RARE" symbol from legitimate NFT use

**Attack Execution:**

**Step 1:** Attacker calls `Create` with:
```
Symbol: "RARE-0"
Owner: AttackerAddress (or any address)
Issuer: AttackerAddress
ExternalInfo: { "__nft_create_chain_id": "999999" }
```

**Step 2:** Collection creation succeeds:
- SEED NFT is burned
- Collection "RARE-0" is registered with poisoned ExternalInfo
- Symbol "RARE" is now reserved

**Step 3:** Anyone attempts to create NFT "RARE-1":
- `CreateNFTInfo` is called
- Line 22-24 reads `__nft_create_chain_id` = "999999"
- Line 26 assertion fails: `Assert(999999 == Context.ChainId)` 
- Transaction reverts with "NFT create ChainId must be collection's NFT create chainId"

**Expected Result:** NFT creation should succeed or collection creation should fail validation

**Actual Result:** Collection exists but NFT creation is permanently blocked

**Success Condition:** Symbol "RARE" cannot be used for NFTs on any chain, permanently blocking legitimate use

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L48-79)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L695-722)
```csharp
    public override Empty ExtendSeedExpirationTime(ExtendSeedExpirationTimeInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo == null)
        {
            throw new AssertionException("Seed NFT does not exist.");
        }

        Assert(tokenInfo.Owner == Context.Sender, "Sender is not Seed NFT owner.");
        var oldExpireTimeLong = 0L;
        if (tokenInfo.ExternalInfo.Value.TryGetValue(TokenContractConstants.SeedExpireTimeExternalInfoKey,
                out var oldExpireTime))
        {
            long.TryParse(oldExpireTime, out oldExpireTimeLong);
        }

        tokenInfo.ExternalInfo.Value[TokenContractConstants.SeedExpireTimeExternalInfoKey] =
            input.ExpirationTime.ToString();
        State.TokenInfos[input.Symbol] = tokenInfo;
        Context.Fire(new SeedExpirationTimeUpdated
        {
            ChainId = tokenInfo.IssueChainId,
            Symbol = input.Symbol,
            OldExpirationTime = oldExpireTimeLong,
            NewExpirationTime = input.ExpirationTime
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L26-26)
```csharp
    public const string NftCreateChainIdExternalInfoKey = "__nft_create_chain_id";
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L22-27)
```csharp
        if (nftCollectionInfo.ExternalInfo != null && nftCollectionInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.NftCreateChainIdExternalInfoKey,
                out var nftCreateChainId) && long.TryParse(nftCreateChainId, out var nftCreateChainIdLong))
        {
            Assert(nftCreateChainIdLong == Context.ChainId,
                "NFT create ChainId must be collection's NFT create chainId");
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
