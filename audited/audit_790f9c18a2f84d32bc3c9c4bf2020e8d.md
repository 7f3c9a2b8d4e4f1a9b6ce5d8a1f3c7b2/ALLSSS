# Audit Report

## Title
NFT Collection ExternalInfo Poisoning Enables Permanent Symbol Squatting and DoS

## Summary
An attacker can create NFT collections with malicious `__nft_create_chain_id` values in the ExternalInfo field, permanently blocking NFT item creation for those collections. Since collection symbols are unique and ExternalInfo cannot be updated post-creation, this enables irrevocable symbol squatting attacks on valuable NFT collection names.

## Finding Description

The vulnerability exists in the NFT collection creation flow where ExternalInfo is accepted without validation, then later enforced during NFT item creation.

**Unvalidated Collection Creation:**

During NFT collection creation via the `TokenContract.Create` method, the input ExternalInfo is directly assigned to the token without validation of its keys or values. [1](#0-0) 

The validation method `AssertValidCreateInput` does not check ExternalInfo contents at all. [2](#0-1) 

The constant `NftCreateChainIdExternalInfoKey` is defined as `"__nft_create_chain_id"` and used to restrict NFT creation. [3](#0-2) 

Critically, this key is NOT included in the reserved external info key list that would prevent users from setting it. [4](#0-3) 

**Enforced Chain ID Check:**

When creating NFT items, the system retrieves and enforces the `__nft_create_chain_id` value from the collection's ExternalInfo. If an attacker set this to a non-existent chain ID (e.g., 999999), the assertion permanently fails. [5](#0-4) 

**No Recovery Mechanism:**

The only method that can update ExternalInfo post-creation is `ExtendSeedExpirationTime`, which is restricted to updating only the `__seed_exp_time` key for Seed NFTs. [6](#0-5) 

**Symbol Uniqueness:**

Collection symbols must be unique and cannot be recreated once they exist. [7](#0-6) 

## Impact Explanation

**Direct Operational Impact:**
- Permanent DoS of NFT item creation for poisoned collections
- Valuable collection symbols (obtainable via SEED NFTs) can be permanently blocked
- Legitimate projects lose access to their intended collection names
- No recovery mechanism exists—the poisoning is irreversible

**Ecosystem Harm:**
- Symbol squatting enables extortion scenarios
- Griefing attacks can target specific competitors or projects
- Erodes trust in the NFT ecosystem as desirable symbols become permanently unavailable
- Creates artificial scarcity through malicious blocking rather than legitimate use

**Severity: HIGH** - This vulnerability enables permanent, unrecoverable DoS attacks on critical NFT protocol functionality with widespread ecosystem impact.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must acquire a SEED NFT for the target symbol (publicly available mechanism)
- Requires only basic knowledge of the ExternalInfo structure
- No special privileges or insider access needed

**Attack Simplicity:**
- Single transaction: Call `TokenContract.Create` with symbol ending in "-0" and crafted ExternalInfo
- No timing requirements, race conditions, or complex state manipulation
- Deterministic and repeatable

**Economic Feasibility:**
- Cost: One SEED NFT per collection symbol (limited but achievable)
- Benefit: Permanent control/blocking of valuable collection names
- Strategic value: Block competitors from desirable brand-related symbols

**Detection Difficulty:**
- Attack appears as legitimate collection creation
- Malicious ExternalInfo values are not detectable until NFT item creation is attempted
- No inherent red flags in the transaction

**Likelihood: HIGH** - The attack is straightforward, economically rational for valuable symbols, and has no significant technical barriers.

## Recommendation

**Immediate Fix:**
Add validation to prevent users from setting `__nft_create_chain_id` in ExternalInfo during collection creation. Include this key in the reserved external info key list:

```csharp
public override StringList GetReservedExternalInfoKeyList(Empty input)
{
    return new StringList
    {
        Value =
        {
            TokenContractConstants.LockCallbackExternalInfoKey,
            TokenContractConstants.LogEventExternalInfoKey,
            TokenContractConstants.TransferCallbackExternalInfoKey,
            TokenContractConstants.UnlockCallbackExternalInfoKey,
            TokenContractConstants.NftCreateChainIdExternalInfoKey  // Add this
        }
    };
}
```

And validate in `AssertValidCreateInput`:
```csharp
private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
{
    // ... existing validations ...
    
    // Validate ExternalInfo keys
    if (input.ExternalInfo != null)
    {
        var reservedKeys = GetReservedExternalInfoKeyList(new Empty()).Value;
        foreach (var key in input.ExternalInfo.Value.Keys)
        {
            Assert(!reservedKeys.Contains(key), $"ExternalInfo key {key} is reserved.");
        }
    }
}
```

**Additional Mitigations:**
1. Add a governance-controlled method to update collection ExternalInfo for recovery
2. Implement monitoring to detect collections with suspicious `__nft_create_chain_id` values
3. Consider restricting who can set this field to trusted addresses only

## Proof of Concept

```csharp
[Fact]
public async Task ExternalInfoPoisoning_PermanentlyBlocksNFTCreation()
{
    // Step 1: Attacker obtains SEED NFT for desired symbol "GOLD"
    var attacker = Accounts[1].Address;
    await CreateSeedNftForSymbol(attacker, "GOLD");
    
    // Step 2: Attacker creates collection with malicious chain ID
    var createCollectionInput = new CreateInput
    {
        Symbol = "GOLD-0",
        TokenName = "Gold Collection",
        TotalSupply = 10000,
        Decimals = 0,
        Issuer = attacker,
        Owner = attacker,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF"),
        ExternalInfo = new ExternalInfo
        {
            Value =
            {
                // Malicious: Set to non-existent chain ID
                ["__nft_create_chain_id"] = "999999"
            }
        }
    };
    
    // Collection creation succeeds
    var createResult = await TokenContractStub.Create.SendAsync(createCollectionInput);
    createResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Anyone trying to create NFT items in this collection will fail
    var createNftInput = new CreateInput
    {
        Symbol = "GOLD-1",
        TokenName = "Gold NFT #1",
        TotalSupply = 1,
        Decimals = 0,
        Issuer = attacker,
        Owner = attacker,
        IsBurnable = true
    };
    
    // NFT creation permanently fails with chain ID mismatch
    var nftResult = await TokenContractStub.Create.SendWithExceptionAsync(createNftInput);
    nftResult.TransactionResult.Error.ShouldContain("NFT create ChainId must be collection's NFT create chainId");
    
    // Step 4: Verify no recovery mechanism exists
    // The symbol "GOLD-0" is now permanently poisoned and unusable
    var collectionInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "GOLD-0" });
    collectionInfo.ExternalInfo.Value["__nft_create_chain_id"].ShouldBe("999999");
    
    // Cannot recreate collection with same symbol
    var recreateResult = await TokenContractStub.Create.SendWithExceptionAsync(createCollectionInput);
    recreateResult.TransactionResult.Error.ShouldContain("Token already exists");
}
```

**Notes:**
- This vulnerability affects all NFT collections created via `TokenContract.Create` directly
- The `__nft_create_chain_id` key is checked during NFT item creation but not validated during collection creation
- Collections created via `NFTContract.Create` are also vulnerable as that method does not include `__nft_create_chain_id` in its reserved keys validation list
- The attack permanently bricks the collection symbol with no recovery path

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-79)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L26-26)
```csharp
    public const string NftCreateChainIdExternalInfoKey = "__nft_create_chain_id";
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L238-250)
```csharp
    public override StringList GetReservedExternalInfoKeyList(Empty input)
    {
        return new StringList
        {
            Value =
            {
                TokenContractConstants.LockCallbackExternalInfoKey,
                TokenContractConstants.LogEventExternalInfoKey,
                TokenContractConstants.TransferCallbackExternalInfoKey,
                TokenContractConstants.UnlockCallbackExternalInfoKey
            }
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L22-28)
```csharp
        if (nftCollectionInfo.ExternalInfo != null && nftCollectionInfo.ExternalInfo.Value.TryGetValue(
                TokenContractConstants.NftCreateChainIdExternalInfoKey,
                out var nftCreateChainId) && long.TryParse(nftCreateChainId, out var nftCreateChainIdLong))
        {
            Assert(nftCreateChainIdLong == Context.ChainId,
                "NFT create ChainId must be collection's NFT create chainId");
        }
```
