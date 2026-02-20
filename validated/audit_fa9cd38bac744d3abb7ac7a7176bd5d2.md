# Audit Report

## Title
Hash Collision in AssembledNftsMap Due to Unseparated String Concatenation in Token Hash Calculation

## Summary
The `CalculateTokenHash` function concatenates NFT symbol and tokenId without a separator, allowing different (symbol, tokenId) pairs to produce identical hash values. This causes hash collisions in `AssembledNftsMap`, where assembled NFT data from one NFT can overwrite another's, leading to permanent loss of assembled assets when users disassemble their NFTs.

## Finding Description

The root cause is the `CalculateTokenHash` function which directly concatenates symbol and tokenId strings before hashing, without any separator character. [1](#0-0) 

NFT protocol symbols follow a specific format: a 2-character type prefix followed by a numeric identifier. [2](#0-1) 

The minimum number length is defined as 9 digits. [3](#0-2) 

The number length dynamically increases as more protocols are created. [4](#0-3) 

**Concrete Collision Example:**
- NFT1: symbol="AR123456789" (2-char prefix + 9 digits), tokenId=10 → concatenates to "AR12345678910"
- NFT2: symbol="AR1234567891" (2-char prefix + 10 digits), tokenId=0 → concatenates to "AR12345678910"

Both produce identical strings and thus identical hash values, causing a collision.

The `AssembledNftsMap` state variable uses these calculated token hashes as keys. [5](#0-4) 

During the assembly operation, assembled NFT data is written to this map using the token hash. [6](#0-5) 

During disassembly, the data is retrieved and removed from the map. [7](#0-6) 

**Attack Sequence:**
1. User A assembles NFT1 (symbol="AR123456789", tokenId=10), storing valuable assembled components at hash H
2. User B assembles NFT2 (symbol="AR1234567891", tokenId=0) with the same hash H, **overwriting** User A's map entry
3. User A disassembles NFT1 and retrieves User B's assembled data instead of their own
4. User A permanently **loses** their original assembled NFT components

Minters have the ability to specify custom tokenIds when minting. [8](#0-7) 

The uniqueness validation only checks within the same symbol, not across different symbols. [9](#0-8) 

There is no mechanism to prevent cross-symbol hash collisions in the storage layer.

## Impact Explanation

**Direct Asset Loss:** Users who assemble NFTs with valuable components (rare NFTs or fungible tokens) will permanently lose these assets if a hash collision overwrites their `AssembledNftsMap` entry. When they attempt to disassemble their NFT, they will receive the wrong assets (belonging to the colliding NFT) or nothing at all if the colliding entry has not yet been assembled.

**Affected Parties:** All users who utilize the NFT assembly functionality are at risk. As the protocol scales with more NFT protocols being created and more NFTs being minted, the collision probability increases. With protocols created early having 9-digit numbers and later protocols having 10+ digit numbers, the conditions for collision are structurally built into the system.

**Severity Justification:** HIGH severity due to:
- Permanent, unrecoverable loss of user assets
- No on-chain mechanism to detect or prevent collisions before they occur
- Impact scales with protocol adoption (more protocols = higher collision risk)
- Affects core NFT assembly functionality designed for combining valuable assets
- No recovery mechanism once assets are locked in the contract

## Likelihood Explanation

**Natural Collision Probability:** Given that NFT symbols have variable-length numeric suffixes (starting at 9 digits and increasing), and tokenIds are user-controllable 64-bit integers, mathematical collisions are possible. While early in the protocol lifecycle natural collisions are unlikely, the probability increases as:
1. More protocols are created with different number lengths (9, 10, 11+ digits)
2. More NFTs are minted with various tokenIds
3. More assembled NFTs are created

**Attacker Capabilities:** An attacker can:
1. Monitor on-chain transactions to identify high-value assembled NFTs
2. Calculate which (symbol, tokenId) pairs would collide with target NFTs
3. Create new NFT protocols (subject to protocol creation fees) to obtain symbols with the desired numeric pattern
4. Mint NFTs with specific tokenIds to trigger collisions
5. Assemble low-value NFTs to overwrite victim data

**Attack Feasibility:** While creating a targeted attack requires finding or creating a protocol symbol that enables collision (which may require multiple protocol creations due to random symbol generation), opportunistic attacks are much more feasible. An attacker can monitor for natural collisions or target multiple assembled NFTs simultaneously to increase success probability.

**Likelihood Assessment:** MEDIUM - Natural collisions become increasingly likely as the system scales and protocols with different number lengths coexist. The lack of any collision detection or prevention mechanism, combined with user-controllable tokenIds, makes exploitation feasible. While highly targeted attacks may be economically impractical, opportunistic exploitation of natural collisions or broad-targeting attacks are realistic threats.

## Recommendation

Add a delimiter or use structured hashing to prevent concatenation ambiguity:

**Option 1 - Add Delimiter:**
Modify the hash calculation to include a separator between symbol and tokenId, such as:
```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}#{tokenId}");
}
```

**Option 2 - Structured Hash:**
Hash the components separately and combine:
```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    var symbolHash = HashHelper.ComputeFrom(symbol);
    var tokenIdHash = HashHelper.ComputeFrom(tokenId);
    return HashHelper.ConcatAndCompute(symbolHash, tokenIdHash);
}
```

**Additional Safeguards:**
- Add collision detection in `AssembledNftsMap` writes to check if an entry already exists and revert if found
- Consider adding an assertion in the `Assemble` method to ensure the map slot is empty before writing
- Implement a migration path for any existing deployed contracts to rehash all stored NFT data

## Proof of Concept

```csharp
[Fact]
public void TestHashCollision_DifferentSymbolsAndTokenIds_ProduceSameHash()
{
    // Simulate the CalculateTokenHash logic
    var symbol1 = "AR123456789";  // 9-digit protocol number
    long tokenId1 = 10;
    var concatenated1 = $"{symbol1}{tokenId1}"; // "AR12345678910"
    
    var symbol2 = "AR1234567891"; // 10-digit protocol number  
    long tokenId2 = 0;
    var concatenated2 = $"{symbol2}{tokenId2}"; // "AR12345678910"
    
    // Verify collision
    concatenated1.ShouldBe(concatenated2);
    
    // Both would produce the same hash
    var hash1 = HashHelper.ComputeFrom(concatenated1);
    var hash2 = HashHelper.ComputeFrom(concatenated2);
    hash1.ShouldBe(hash2);
    
    // This proves that AssembledNftsMap[hash1] and AssembledNftsMap[hash2] 
    // point to the same storage location, enabling the overwrite attack
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-176)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L202-209)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var assembledNfts = State.AssembledNftsMap[tokenHash].Clone();
        if (assembledNfts != null)
        {
            var nfts = assembledNfts;
            foreach (var pair in nfts.Value) DoTransfer(Hash.LoadFromHex(pair.Key), Context.Self, receiver, pair.Value);

            State.AssembledNftsMap.Remove(tokenHash);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L392-392)
```csharp
        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L395-396)
```csharp
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-36)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L87-116)
```csharp
    private int GetCurrentNumberLength()
    {
        if (State.CurrentSymbolNumberLength.Value == 0) State.CurrentSymbolNumberLength.Value = NumberMinLength;

        var flag = State.NftProtocolNumberFlag.Value;

        if (flag == 0)
        {
            // Initial protocol number flag.
            var protocolNumber = 1;
            for (var i = 1; i < State.CurrentSymbolNumberLength.Value; i++) protocolNumber = protocolNumber.Mul(10);

            State.NftProtocolNumberFlag.Value = protocolNumber;
            flag = protocolNumber;
        }

        var upperNumberFlag = flag.Mul(2);
        if (upperNumberFlag.ToString().Length > State.CurrentSymbolNumberLength.Value)
        {
            var newSymbolNumberLength = State.CurrentSymbolNumberLength.Value.Add(1);
            State.CurrentSymbolNumberLength.Value = newSymbolNumberLength;
            var protocolNumber = 1;
            for (var i = 1; i < newSymbolNumberLength; i++) protocolNumber = protocolNumber.Mul(10);

            State.NftProtocolNumberFlag.Value = protocolNumber;
            return newSymbolNumberLength;
        }

        return State.CurrentSymbolNumberLength.Value;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L32-32)
```csharp
    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
```
