### Title
Hash Collision Vulnerability in NFT Token Hash Calculation Due to Unseparated String Concatenation

### Summary
The `CalculateTokenHash()` function concatenates NFT protocol symbols with token IDs without a separator, enabling hash collisions between different NFTs. An attacker with minter permissions in two protocols can craft token IDs to produce identical hashes, causing critical state confusion including balance manipulation, metadata overwriting, and asset loss.

### Finding Description

The vulnerability exists in the token hash calculation implementation: [1](#0-0) 

The function directly concatenates the symbol string with the tokenId integer without any delimiter. NFT protocol symbols are generated with varying lengths: [2](#0-1) 

Symbols consist of a 2-letter prefix followed by a numeric suffix starting at 9 digits minimum: [3](#0-2) 

The numeric portion length increases over time as more protocols are created: [4](#0-3) 

This means symbols like "AB100000000" (11 characters) and "AB1000000001" (12 characters) can both exist.

Users can specify custom token IDs when minting: [5](#0-4) 

**Collision Example:**
- Protocol "AB100000000" + TokenId 123 → Hash("AB100000000123")
- Protocol "AB1000000001" + TokenId 23 → Hash("AB100000000123")

Both produce identical hashes despite representing different NFTs.

The tokenHash is used as the key for all critical state mappings: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) 

### Impact Explanation

**Critical State Collision:** When two different NFTs share the same tokenHash, they become indistinguishable in all contract state:

1. **Balance Manipulation**: Minting/transferring one NFT affects the balance of the other, enabling double-spending or balance theft
2. **Metadata Overwriting**: The NFTInfo stored in State.NftInfoMap gets overwritten, losing original NFT properties
3. **Approval Confusion**: Allowances set for one NFT apply to the other
4. **Assembly Data Corruption**: AssembledNfts/Fts mappings get mixed up
5. **Ownership Fraud**: Actual ownership becomes ambiguous between colliding NFTs

**Affected Parties:** 
- NFT holders who lose assets or control
- Protocol operators whose NFTs become compromised
- Marketplace users trading confused assets

**Severity Justification:** This is HIGH severity because it directly enables asset theft, balance manipulation, and breaks the fundamental uniqueness invariant required for NFT systems.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Minter permission in two different NFT protocols (achievable by creating protocols or being added as minter)
2. Ability to calculate collision-producing tokenIds (trivial arithmetic)
3. Wait for or trigger symbol number length increase (happens naturally as protocols are created)

**Attack Complexity:** LOW
- Simple mathematical calculation to find colliding tokenIds
- No race conditions or timing requirements
- No need for special privileges beyond standard minter role

**Feasibility Conditions:**
- Multiple symbol lengths must exist in the system (guaranteed after sufficient protocol creation)
- Attacker has minter access to at least two protocols (common for protocol creators)
- Token ID reuse disabled or attacker mints first (default behavior per protocol settings)

**Detection Difficulty:** HIGH
- Collision appears as normal NFT operations
- No transaction failures or errors
- Only detectable through careful state analysis
- Users may not notice until balance inconsistencies emerge

**Economic Rationality:** Highly profitable - attacker can steal valuable NFTs by manipulating balances through collision, with minimal cost (just gas fees for minting).

### Recommendation

**Immediate Fix:** Add an unambiguous separator in the hash calculation:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}#{tokenId}");
}
```

Or use structured hashing:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    var symbolHash = HashHelper.ComputeFrom(symbol);
    var tokenIdHash = HashHelper.ComputeFrom(tokenId);
    return HashHelper.ConcatAndCompute(symbolHash, tokenIdHash);
}
```

**Additional Safeguards:**
1. Add assertion to verify symbol format matches expected pattern (2-letter prefix + numeric suffix)
2. Enforce minimum symbol length validation in CrossChainCreate
3. Add invariant check: tokenHash uniqueness across all protocols
4. Implement migration path for existing NFTs to recalculate hashes with new method

**Test Cases:**
1. Create two protocols with symbols of different lengths (e.g., 11 and 12 characters)
2. Mint NFTs with calculated colliding tokenIds
3. Verify hashes are different after fix
4. Test edge cases: tokenId = 0, very large tokenIds, maximum symbol lengths

### Proof of Concept

**Initial State:**
1. System has created enough NFT protocols that symbol number length has increased from 9 to 10 digits
2. Protocol A exists with symbol "AB100000000" (2-letter prefix + 9-digit number)
3. Protocol B exists with symbol "AB1000000001" (2-letter prefix + 10-digit number)
4. Attacker has minter permission in both protocols

**Exploitation Steps:**

**Step 1:** Calculate collision
- Target string: "AB100000000123"
- Protocol A: "AB100000000" + TokenId 123
- Protocol B: "AB1000000001" + TokenId 23

**Step 2:** Mint in Protocol A
```
Call: NFTContract.Mint({
  symbol: "AB100000000",
  token_id: 123,
  owner: VictimAddress,
  quantity: 1
})
```
Result: NFT created with balance 1 for VictimAddress at tokenHash = Hash("AB100000000123")

**Step 3:** Mint in Protocol B
```
Call: NFTContract.Mint({
  symbol: "AB1000000001", 
  token_id: 23,
  owner: AttackerAddress,
  quantity: 10
})
```
Result: Same tokenHash overwritten, balance now 10 for AttackerAddress

**Expected Result:** Two distinct NFTs with separate balances and metadata

**Actual Result:** 
- Colliding tokenHash causes state confusion
- Later mint overwrites NFTInfo from first mint
- Balance tracking becomes ambiguous between the two NFTs
- Attacker can manipulate balances by transferring either NFT
- Protocol invariant "each NFT has unique identifier" is violated

**Success Condition:** GetNFTInfoByTokenHash(Hash("AB100000000123")) returns data from Protocol B's mint (symbol "AB1000000001", tokenId 23) instead of maintaining separate states for both NFTs.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L22-24)
```csharp
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L52-54)
```csharp
        Assert(State.BalanceMap[tokenHash][from] >= amount, "Insufficient balance.");
        State.BalanceMap[tokenHash][from] = State.BalanceMap[tokenHash][from].Sub(amount);
        State.BalanceMap[tokenHash][to] = State.BalanceMap[tokenHash][to].Add(amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L84-101)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(nftProtocolInfo.IsBurnable,
            $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
        State.BalanceMap[tokenHash][Context.Sender] = State.BalanceMap[tokenHash][Context.Sender].Sub(input.Amount);
        nftProtocolInfo.Supply = nftProtocolInfo.Supply.Sub(input.Amount);
        nftInfo.Quantity = nftInfo.Quantity.Sub(input.Amount);

        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;
        if (nftInfo.Quantity == 0 && !nftProtocolInfo.IsTokenIdReuse) nftInfo.IsBurned = true;

        State.NftInfoMap[tokenHash] = nftInfo;
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L392-393)
```csharp
        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L439-441)
```csharp
        State.NftInfoMap[tokenHash] = nftInfo;
        var owner = input.Owner ?? Context.Sender;
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);
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
