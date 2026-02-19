### Title
Hash Collision Vulnerability in NFT Contract Allows Cross-Protocol Data Corruption and Asset Theft

### Summary
The NFT contract's `CalculateTokenHash` function uses naive string concatenation of symbol and tokenId, creating hash collision opportunities. Attackers can create malicious NFT protocols with crafted symbols that produce identical hashes to legitimate NFTs, causing data corruption across `NftInfoMap`, `BalanceMap`, `AllowanceMap`, and `AssembledNftsMap`, leading to asset theft and metadata loss.

### Finding Description

The root cause lies in the `CalculateTokenHash` implementation: [1](#0-0) 

This function concatenates symbol (string) and tokenId (long) using string interpolation, creating ambiguous hash inputs. For example:
- Symbol "XX12345678" + TokenId 91 → "XX1234567891"  
- Symbol "XX123456789" + TokenId 1 → "XX1234567891"

Both produce identical hashes despite representing different NFTs from different protocols.

The NFT contract expects symbols to follow the format `{shortName}{randomNumber}` with minimum 11 characters (2-letter prefix + 9-digit number): [2](#0-1) [3](#0-2) 

However, the `CrossChainCreate` method accepts any symbol that exists in the TokenContract without validating format or length: [4](#0-3) 

The TokenContract allows creating regular tokens with symbols up to 10 characters: [5](#0-4) [6](#0-5) 

The symbol validation uses regex `^[a-zA-Z0-9]+(-[0-9]+)?$`, which permits alphanumeric strings like "XX12345678" (10 characters). Critically, `CrossChainCreate` has NO permission checks - it's publicly callable.

When minting NFTs, the contract checks if tokenId exists within that protocol but doesn't prevent global hash collisions: [7](#0-6) 

The collision affects all state maps using the same hash key: [8](#0-7) 

### Impact Explanation

**Critical Asset Loss and Data Corruption:**

When a hash collision occurs, the second NFT mint operation overwrites the first NFT's data in `State.NftInfoMap[tokenHash]`: [9](#0-8) 

This causes:
1. **NFT Metadata Loss**: Original NFT's URI, alias, quantity, and metadata are overwritten
2. **Balance Corruption**: `State.BalanceMap[tokenHash][owner]` mixes balances from different NFTs, allowing theft
3. **Allowance Manipulation**: `State.AllowanceMap[tokenHash][owner][spender]` becomes exploitable for unauthorized transfers
4. **Assembled Component Theft**: `State.AssembledNftsMap[tokenHash]` and `State.AssembledFtsMap[tokenHash]` can be stolen via disassembly

Affected operations include Transfer, TransferFrom, Burn, Approve, Recast, and Disassemble - all using the same vulnerable hash: [10](#0-9) [11](#0-10) 

**Quantified Impact**: Complete loss of NFT assets, metadata, and assembled components for all colliding NFTs. This affects legitimate users who have no relationship with the attacker's malicious protocol.

### Likelihood Explanation

**High Exploitability:**

1. **Public Entry Point**: `CrossChainCreate` is publicly callable with no authorization checks: [12](#0-11) 

2. **Attacker Capabilities**: Attacker needs to create a token in MultiToken contract, requiring either:
   - SEED NFT ownership (obtainable through market purchase)
   - Being on the create whitelist (less likely but possible for legitimate projects) [13](#0-12) 

3. **Attack Complexity**: Low - attacker simply:
   - Creates token with crafted symbol (e.g., "XX12345678")
   - Sets required external info fields (no restrictions)
   - Calls `CrossChainCreate` with the symbol
   - Mints NFTs with calculated tokenIds to produce target hashes

4. **Deterministic Execution**: Hash calculation is deterministic, allowing precise targeting of victim NFTs

5. **Economic Rationality**: Cost is minimal (SEED NFT + gas fees), profit is potentially high (stolen NFT assets and assembled components)

6. **Detection Difficulty**: Hash collisions appear as normal NFT operations; no obvious on-chain indicators

### Recommendation

**Immediate Fix**: Modify `CalculateTokenHash` to use structured hashing that prevents ambiguity:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(symbol),
        HashHelper.ComputeFrom(tokenId)
    );
}
```

This ensures different (symbol, tokenId) pairs always produce different hashes, as the inputs are hashed separately before concatenation.

**Additional Protections**:

1. Add symbol format validation in `CrossChainCreate`:
   - Minimum length check (>= 11 characters for mainnet-created protocols)
   - Validate first 2 characters match registered NFT type prefixes
   
2. Add permission check to `CrossChainCreate` - restrict to authorized cross-chain relayers or contract administrators

3. Implement global uniqueness check in `PerformMint`:
   - Before minting, assert that `State.NftInfoMap[tokenHash] == null` OR it belongs to the same protocol
   
4. Add regression tests covering:
   - Hash collision scenarios with different symbol lengths
   - CrossChainCreate authorization
   - Symbol format validation edge cases

### Proof of Concept

**Initial State:**
- Legitimate Protocol A exists: Symbol="XX123456789" (11 chars), created via normal `Create()` method
- NFT minted: TokenId=1, Owner=VictimAddress, Balance=1, Metadata="Valuable NFT"
- Hash: HashHelper.ComputeFrom("XX1234567891")

**Attack Sequence:**

1. **Attacker creates malicious token:**
   - Call `MultiToken.Create()` with Symbol="XX12345678" (10 chars)
   - Set ExternalInfo: `{"aelf_nft_base_uri": "https://attacker.com", "aelf_nft_token_id_reuse": "false"}`
   - Cost: 1 SEED NFT + gas

2. **Attacker registers malicious protocol:**
   - Call `NFT.CrossChainCreate({Symbol: "XX12345678"})`
   - No permission check, succeeds immediately
   - Protocol B now registered

3. **Attacker triggers collision:**
   - Call `NFT.Mint({Symbol: "XX12345678", TokenId: 91, Owner: AttackerAddress})`
   - Computes hash: HashHelper.ComputeFrom("XX1234567891")
   - **IDENTICAL to victim's hash!**

**Expected Result:**
- Separate NFTs with different hashes

**Actual Result:**
- `State.NftInfoMap[hash]` now contains attacker's NFT data (victim's metadata lost)
- `State.BalanceMap[hash][VictimAddress] = 1`, `State.BalanceMap[hash][AttackerAddress] = 1`
- Attacker can call `TransferFrom` using victim's balance
- Victim's original NFT effectively destroyed, data corrupted

**Success Condition:** 
Attacker successfully overwrites victim NFT data and can manipulate shared balance/allowance state, demonstrating critical data corruption and asset theft capability.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L23-24)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L84-85)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L393-396)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
        var nftInfo = State.NftInfoMap[tokenHash];
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L439-439)
```csharp
        State.NftInfoMap[tokenHash] = nftInfo;
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-37)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }

        return $"{shortName}{randomNumber}";
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-93)
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

        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L7-7)
```csharp
    public const int SymbolMaxLength = 10;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L18-21)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+(-[0-9]+)?$");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L17-32)
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
