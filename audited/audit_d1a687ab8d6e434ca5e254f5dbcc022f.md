### Title
NFT Token Hash Collision via Ambiguous String Concatenation Enables Cross-Protocol Denial of Service and State Corruption

### Summary
The `CalculateTokenHash` function uses simple string concatenation without a delimiter to generate token identifiers from symbol and tokenId, enabling hash collisions across different NFT protocols. Since NFT symbols use variable-length random numbers (starting at 9 digits and growing to 10+), an attacker can exploit the ambiguity where `symbol1 + tokenId1 == symbol2 + tokenId2` to either block legitimate mints or corrupt NFT state across protocols.

### Finding Description

The root cause is in the `CalculateTokenHash` implementation which concatenates symbol and tokenId without any delimiter: [1](#0-0) 

NFT protocol symbols are generated with variable-length random numbers. The initial minimum length is 9 digits, which increases as more protocols are created: [2](#0-1) [3](#0-2) [4](#0-3) 

The symbol generation creates formats like `"AR123456789"` (9 digits), which later grows to `"AR1234567890"` (10 digits), `"AR12345678901"` (11 digits), etc. as the system scales.

Users can specify arbitrary tokenId values with no range validation: [5](#0-4) 

**Collision Example:**
- Protocol A: Symbol `"AR123456789"` (9-digit number) + tokenId `999` → Hash(`"AR123456789999"`)
- Protocol B: Symbol `"AR1234567899"` (10-digit number) + tokenId `99` → Hash(`"AR123456789999"`)

Both produce identical hashes despite representing completely different NFTs from different protocols.

The collision detection at mint time checks if the hash already exists but does NOT distinguish between protocols: [6](#0-5) 

This check prevents the second protocol from minting when `IsTokenIdReuse` is false, causing denial of service. If `IsTokenIdReuse` is true, the check is bypassed, leading to state corruption where both protocols share the same storage slots.

All critical NFT operations depend on this tokenHash:
- NFT metadata storage: [7](#0-6) 
- Balance tracking: [8](#0-7) 
- Allowance management: [9](#0-8) 
- Transfer operations: [10](#0-9) 
- Burn operations: [11](#0-10) 
- Query operations: [12](#0-11) 

### Impact Explanation

**Denial of Service Impact:**
When protocol "AR123456789" mints tokenId=999 first, any subsequent protocol whose symbol creates a collision (e.g., "AR1234567899" with tokenId=99) will be permanently blocked from using that tokenId. The error message "Token id 99 already exists" is misleading since tokenId 99 doesn't exist for the second protocol—only the hash collision exists. This affects legitimate protocol operators who cannot mint specific tokenIds.

**State Corruption Impact:**
If `IsTokenIdReuse=true` for the colliding protocol, the assertion is bypassed and both protocols write to the same state storage locations:
- `State.NftInfoMap[tokenHash]` stores conflated metadata from both NFTs
- `State.BalanceMap[tokenHash]` mixes balances across protocols  
- `State.AllowanceMap[tokenHash]` conflates approval permissions

This causes:
- Wrong NFT metadata returned by `GetNFTInfo`
- Incorrect balance queries via `GetBalance`
- Misrouted transfer operations affecting the wrong NFT
- Incorrect burn operations destroying the wrong assets
- Mixed allowance permissions creating unauthorized transfer capabilities

**Affected Parties:**
- NFT protocol creators who are blocked from minting legitimate tokenIds
- NFT holders whose balances are corrupted or misattributed
- Users performing transfers/burns that affect unintended NFTs
- The entire NFT ecosystem's integrity and trust

**Severity Justification:**
This is CRITICAL because:
1. Breaks the fundamental invariant that each (symbol, tokenId) pair must be unique
2. Enables systematic DoS against new protocols as the system scales
3. Corrupts core state storage affecting all NFT operations
4. No authentication required—any user with mint permissions can trigger it
5. Impacts increase as more protocols are created and symbol length grows

### Likelihood Explanation

**Attacker Capabilities:**
- Requires mint permission on at least one NFT protocol (obtainable by creating a protocol or being added as a minter)
- Ability to calculate hash collisions (simple arithmetic)
- Ability to frontrun or strategically mint specific tokenIds
- No special privileges or governance control needed

**Attack Complexity:**
The attack is straightforward:
1. Monitor protocol creation events to identify symbol values
2. Calculate collision pairs: For symbol `S` of length `N`, find symbol `S'` of length `N+1` where `S + tokenId1 == S' + tokenId2`
3. Mint the colliding tokenId first in the protocol with the shorter symbol
4. Wait for the longer symbol protocol to be created
5. Legitimate users cannot mint the colliding tokenId in the second protocol

**Feasibility Conditions:**
- Fully achievable: Symbol generation is deterministic and observable on-chain
- No special timing windows required beyond standard transaction ordering
- Attack becomes more practical as system scales and more 10+ digit symbols exist
- Collision probability increases with ecosystem growth

**Detection Constraints:**
- Collisions appear as legitimate mint transactions
- Error messages don't indicate cross-protocol collision
- No on-chain monitoring currently detects this pattern
- Victims may not realize their blockage is due to collision

**Economic Rationality:**
- Attack cost: Only gas fees for mint transactions
- Potential gain: Blocking competitors' protocols, griefing specific tokenId ranges, creating protocol-level DoS
- Cost-benefit strongly favors the attacker

### Recommendation

**Immediate Fix:**
Modify `CalculateTokenHash` to include an unambiguous delimiter that cannot appear in symbols:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}#{tokenId}");
}
```

The `#` character (or any character not allowed in symbols) ensures no collision is possible since symbols follow the pattern `^[A-Z]{2}[0-9]+$` and cannot contain `#`.

**Alternative Fix:**
Use structured hashing instead of string concatenation:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(symbol),
        HashHelper.ComputeFrom(tokenId)
    );
}
```

**Validation Check:**
Add protocol-specific verification in `PerformMint`:

```csharp
if (nftInfo != null && nftInfo.Symbol != input.Symbol)
{
    throw new AssertionException(
        $"Token hash collision detected: hash belongs to {nftInfo.Symbol}, not {input.Symbol}"
    );
}
```

**Regression Tests:**
Add test cases verifying:
1. Symbols "AR123456789" + tokenId=999 and "AR1234567899" + tokenId=99 produce different hashes
2. All historical collision patterns are prevented
3. Hash uniqueness across protocol boundaries
4. Migration path for existing collisions if any exist

### Proof of Concept

**Initial State:**
- System is operational with symbol number length = 9 digits
- Protocol "AR123456789" created and operational
- User A is authorized minter for "AR123456789"

**Step 1: First Mint (Attacker)**
- User A calls `Mint`:
  - Symbol: `"AR123456789"`
  - TokenId: `999`
  - TokenHash = Hash(`"AR123456789999"`)
- NFTInfo stored at `State.NftInfoMap[Hash("AR123456789999")]`
- Result: SUCCESS

**Step 2: System Growth**
- Symbol number length increases to 10 digits (via `GetCurrentNumberLength` reaching threshold)
- Protocol "AR1234567899" is created (10-digit random number)
- User B is authorized minter for "AR1234567899"

**Step 3: Collision Exploitation (Victim)**
- User B calls `Mint`:
  - Symbol: `"AR1234567899"`
  - TokenId: `99`
  - Expected TokenHash: Unique identifier for this NFT
  - Actual TokenHash: Hash(`"AR123456789999"`) ← COLLISION!
- Code executes:
  ```
  var tokenHash = CalculateTokenHash("AR1234567899", 99) → Hash("AR123456789999")
  var nftInfo = State.NftInfoMap[tokenHash] → Returns User A's NFT from Step 1!
  Assert(nftInfo == null, "Token id 99 already exists") → FAILS!
  ```
- Result: **TRANSACTION REVERTS** with misleading error "Token id 99 already exists. Please assign a different token id."

**Expected Outcome:** User B should successfully mint tokenId=99 for their protocol "AR1234567899"

**Actual Outcome:** User B is permanently blocked from using tokenId=99 due to hash collision with unrelated protocol "AR123456789" tokenId=999

**Success Condition:** Transaction reverts with assertion failure, proving the collision prevents legitimate minting operations across different protocols.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L23-24)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L64-66)
```csharp
            var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
            Assert(allowance >= input.Amount, "Not approved.");
            State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L84-84)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L441-441)
```csharp
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_View.cs (L16-16)
```csharp
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
```
