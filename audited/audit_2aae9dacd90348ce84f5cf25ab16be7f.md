### Title
Hash Collision Vulnerability in CalculateTokenHash Due to Ambiguous String Concatenation

### Summary
The `CalculateTokenHash` function concatenates symbol and tokenId without a delimiter before hashing, creating deterministic hash collisions when different NFT protocols have symbols that form ambiguous boundaries with tokenIds (e.g., "AR123" + tokenId 456 produces the same hash as "AR1234" + tokenId 56, both hashing "AR123456"). This allows attackers to corrupt NFT metadata, manipulate NFT state, and potentially compromise assembled assets by minting colliding NFTs across different protocols.

### Finding Description

The root cause is in the `CalculateTokenHash` implementation which performs naive string concatenation: [1](#0-0) 

This hash is used as the primary key for critical state mappings: [2](#0-1) 

NFT symbols are generated in the format `{2-char-prefix}{randomNumber}` where the randomNumber can be of varying length: [3](#0-2) 

The randomNumber uniqueness check only ensures the same number isn't reused, but doesn't prevent collisions from different symbol-tokenId combinations: [4](#0-3) 

Minters can specify custom tokenIds when minting: [5](#0-4) 

The tokenId uniqueness check only validates within the same protocol (symbol), not across protocols: [6](#0-5) 

When a collision occurs, the NFT metadata gets overwritten: [7](#0-6) 

### Impact Explanation

**Concrete Impact:**
1. **NFT Metadata Corruption**: When an attacker creates a colliding NFT, `State.NftInfoMap[tokenHash]` gets completely overwritten, causing victim's NFT to report incorrect symbol, tokenId, quantity, and metadata through view functions.

2. **Assembled Assets Compromise**: If the victim's NFT was assembled with valuable NFTs or fungible tokens locked inside, the collision corrupts `State.AssembledNftsMap[tokenHash]` and `State.AssembledFtsMap[tokenHash]`, potentially allowing the attacker to disassemble and steal these assets or causing them to become permanently inaccessible.

3. **State Manipulation via Burn**: When the attacker burns their colliding NFT, it decrements the shared `nftInfo.Quantity` and can set `nftInfo.IsBurned = true`, corrupting the victim's NFT state: [8](#0-7) 

4. **Protocol Integration Breakage**: External marketplaces, wallets, and dApps querying NFT info via `GetNFTInfo` will receive incorrect data for the victim's NFT, breaking functionality and potentially causing financial losses in trading scenarios.

**Affected Parties**: All NFT holders whose tokens have symbols that can form collisions (e.g., any NFT with symbol "AR123" is vulnerable to collision from "AR1234", "AR12345", etc.)

**Severity Justification**: HIGH - Deterministic exploitation path with concrete state corruption, metadata loss, and potential asset theft/loss scenarios.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to create NFT protocols (publicly accessible, requires transaction fees)
- Ability to mint NFTs (requires being added as minter by protocol creator or creating own protocol)
- Ability to query existing NFTs to identify collision targets (public view functions)

**Attack Complexity:**
1. Attacker identifies target NFT with symbol and tokenId (e.g., "AR123", tokenId 456)
2. Attacker creates NFT protocols repeatedly until obtaining a collision-enabling symbol (e.g., "AR1234" or "AR12345")
3. Attacker mints NFT with crafted tokenId (56 for "AR1234" or 6 for "AR12345") to match the concatenation "AR123456"
4. Collision achieved, victim's NFT state corrupted

**Feasibility Conditions:**
- Symbol generation uses pseudorandom numbers based on block height and sender, but attacker can make multiple attempts across different blocks
- No rate limiting on protocol creation beyond transaction fees
- Expected attempts: Depends on random number range (currently 10-99, then 100-999 as supply grows), making it economically feasible for high-value NFT targets

**Economic Rationality:** Protocol creation costs are far lower than the value of high-value NFTs or their assembled assets, making this attack profitable for targeted exploitation.

### Recommendation

**Immediate Fix:**
Modify the `CalculateTokenHash` function to include an unambiguous delimiter:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}-{tokenId}");
}
```

Or use a structured approach:
```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(symbol),
        HashHelper.ComputeFrom(tokenId)
    );
}
```

**Additional Safeguards:**
1. Add validation in `PerformMint` to check for existing NFTInfo with different (symbol, tokenId) pairs before writing
2. Implement comprehensive collision detection tests
3. Consider migrating existing NFTs if any collisions exist in production

**Test Cases:**
```csharp
// Test case 1: Verify no collision between different symbol/tokenId pairs
Assert(CalculateTokenHash("AR123", 456) != CalculateTokenHash("AR1234", 56));
Assert(CalculateTokenHash("AR123", 456) != CalculateTokenHash("AR12345", 6));

// Test case 2: Verify same symbol/tokenId produces consistent hash
Assert(CalculateTokenHash("AR123", 456) == CalculateTokenHash("AR123", 456));

// Test case 3: Integration test preventing collision-based metadata overwrite
```

### Proof of Concept

**Initial State:**
1. Victim creates NFT Protocol A (assume symbol "AR123" is generated)
2. Victim mints NFT: symbol="AR123", tokenId=456
   - tokenHash = Hash("AR123456")
   - State.NftInfoMap[tokenHash] = {Symbol: "AR123", TokenId: 456, Quantity: 1, ...}
   - State.BalanceMap[tokenHash][victim] = 1

**Attack Sequence:**
1. Attacker queries victim's NFT via `GetNFTInfo`: retrieves symbol="AR123", tokenId=456
2. Attacker creates multiple NFT protocols until obtaining symbol "AR1234" (or "AR12345", etc.)
3. Attacker mints NFT: symbol="AR1234", tokenId=56
   - tokenHash = Hash("AR123456") - **COLLISION!**
   - State.NftInfoMap[tokenHash] = {Symbol: "AR1234", TokenId: 56, ...} - **OVERWRITES victim's metadata**
   - State.BalanceMap[tokenHash][attacker] = 1

**Expected Result:** Each NFT should have a unique tokenHash with independent state.

**Actual Result:** 
- Calling `GetNFTInfo` for victim's NFT (symbol="AR123", tokenId=456) returns attacker's metadata (symbol="AR1234", tokenId=56)
- Victim's original NFT metadata is permanently lost
- If victim had assembled assets, they are now associated with attacker's NFT configuration
- Attacker can burn their NFT to corrupt the shared nftInfo.Quantity and IsBurned flag

**Success Condition:** `State.NftInfoMap[Hash("AR123456")]` contains attacker's NFT data instead of victim's, demonstrating complete metadata overwrite.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L96-101)
```csharp
        nftInfo.Quantity = nftInfo.Quantity.Sub(input.Amount);

        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;
        if (nftInfo.Quantity == 0 && !nftProtocolInfo.IsTokenIdReuse) nftInfo.IsBurned = true;

        State.NftInfoMap[tokenHash] = nftInfo;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L392-396)
```csharp
        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
        var nftInfo = State.NftInfoMap[tokenHash];
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L439-441)
```csharp
        State.NftInfoMap[tokenHash] = nftInfo;
        var owner = input.Owner ?? Context.Sender;
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L65-85)
```csharp
    private long GenerateSymbolNumber()
    {
        var length = GetCurrentNumberLength();
        var from = 1L;
        for (var i = 1; i < length; i++) from = from.Mul(10);

        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
        long randomNumber;
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);

        return randomNumber;
    }
```
