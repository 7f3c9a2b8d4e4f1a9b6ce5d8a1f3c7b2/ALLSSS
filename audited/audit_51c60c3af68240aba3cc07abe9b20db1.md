### Title
Token Hash Collision Vulnerability Allows NFT Metadata Corruption and Balance Pool Sharing

### Summary
The `CalculateTokenHash()` function concatenates symbol and tokenId strings without a delimiter, enabling hash collisions between different (Symbol, TokenId) combinations. When NFT protocols have `IsTokenIdReuse=true`, attackers can mint NFTs with colliding hashes, causing multiple distinct NFTs to share the same storage keys. This corrupts NFT metadata, creates shared balance pools, and breaks NFT uniqueness guarantees.

### Finding Description

**Root Cause:**

The hash calculation function uses simple string concatenation without delimiter: [1](#0-0) 

This creates collision potential. For example:
- (Symbol="VW100000000", TokenId=123) produces "VW100000000123"
- (Symbol="VW1000000001", TokenId=23) produces "VW100000000123" (COLLISION)

Both are valid since NFT protocol symbols follow the format of 2-character prefix plus N-digit random numbers (N starts at 9, increases over time): [2](#0-1) 

**Insufficient Protection:**

The minting function attempts to prevent duplicate tokenHashes, but this check is bypassed when `IsTokenIdReuse=true`: [3](#0-2) 

When the check passes or is bypassed, the code modifies or overwrites the shared NFTInfo: [4](#0-3) 

**Exploitation Path:**

The Transfer function calculates tokenHash from user input without validating that the (symbol, tokenId) pair corresponds to an existing NFT: [5](#0-4) 

The underlying DoTransfer only checks balance sufficiency, not NFT existence or (symbol, tokenId) validity: [6](#0-5) 

### Impact Explanation

**Critical Protocol Damage:**

1. **NFT Metadata Corruption**: When colliding NFTs are minted, they share `State.NftInfoMap[tokenHash]`, causing metadata from different NFTs to be mixed. The victim's NFT metadata gets overwritten with attacker-controlled values.

2. **Balance Pool Sharing**: Multiple distinct NFTs access the same `State.BalanceMap[tokenHash]` storage. While addresses maintain separate balances, the semantic meaning is corrupted - transferring one NFT's (symbol, tokenId) affects the balance pool of a completely different NFT.

3. **Broken NFT Uniqueness**: The fundamental guarantee that each NFT has unique identity and storage is violated. Two different (Symbol, TokenId) pairs represent the same on-chain entity.

4. **Audit Trail Confusion**: Transfer events emit the input (symbol, tokenId) regardless of which underlying NFT was affected, creating fraudulent or misleading transaction history.

5. **Allowance/Approval Corruption**: Approvals granted for one NFT automatically apply to its collision counterpart since they share `State.AllowanceMap[tokenHash]`.

**Affected Parties:**
- NFT owners whose tokens have colliding hashes
- NFT marketplaces relying on (symbol, tokenId) uniqueness
- Auditors and indexers tracking NFT ownership
- Applications depending on NFT metadata integrity

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to create NFT protocols with `IsTokenIdReuse=true` (anyone can call Create on mainchain)
- Computational resources to identify hash collision candidates
- Timing: wait for system to scale such that longer symbol numbers are generated

**Feasibility Conditions:**

1. **Natural Collision Emergence**: As the system scales and generates symbols with increasing lengths (9, 10, 11+ digits), the collision space grows: [7](#0-6) 

2. **IsTokenIdReuse Feature**: Some protocols legitimately enable this flag, removing the collision protection: [8](#0-7) 

3. **No Input Validation**: Transfer and other functions accept any (symbol, tokenId) without verifying they match stored NFT: [9](#0-8) 

**Probability Assessment:**
- **Medium-High**: Collisions become increasingly likely as more protocols are created
- **Deterministic**: Once a collision exists, exploitation is guaranteed
- **Undetectable**: The collision is embedded in the hash function design
- **Economic**: Low cost to create protocols and search for collisions offline

### Recommendation

**Immediate Fix:**

Modify `CalculateTokenHash` to use a structured hash that prevents collisions:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    // Use protobuf message to ensure proper serialization
    var input = new CalculateTokenHashInput
    {
        Symbol = symbol,
        TokenId = tokenId
    };
    return HashHelper.ComputeFrom(input);
}
```

This uses the protobuf serialization which properly separates fields, preventing string concatenation collisions.

**Additional Validations:**

1. Add validation in Transfer/TransferFrom/Approve functions:
```csharp
var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
var nftInfo = State.NftInfoMap[tokenHash];
Assert(nftInfo != null && nftInfo.Symbol == input.Symbol && nftInfo.TokenId == input.TokenId,
    "Invalid NFT reference");
```

2. Remove or redesign `IsTokenIdReuse` feature to maintain collision protection

3. Add collision detection in PerformMint regardless of `IsTokenIdReuse` flag

**Test Cases:**

1. Test that symbols "AB123" + tokenId "456" and "AB1234" + tokenId "56" produce different hashes
2. Test that Transfer fails when (symbol, tokenId) don't match stored NFTInfo
3. Test that minting fails on hash collision even with IsTokenIdReuse=true

### Proof of Concept

**Initial State:**
1. System has generated NFT protocol with Symbol="VW100000000" (9-digit number era)
2. Victim mints NFT: (Symbol="VW100000000", TokenId=123)
   - TokenHash = Hash("VW100000000123")
   - State.NftInfoMap[TokenHash] = {Symbol: "VW100000000", TokenId: 123, ...}
   - State.BalanceMap[TokenHash][Victim] = 1

**Attack Sequence:**
1. System scales, now generates 10-digit symbols
2. Attacker creates NFT protocol with `IsTokenIdReuse=true`, receives Symbol="VW1000000001"
3. Attacker mints NFT: (Symbol="VW1000000001", TokenId=23)
   - TokenHash = Hash("VW100000000123") (COLLISION!)
   - Since IsTokenIdReuse=true, line 395-396 check is bypassed
   - State.NftInfoMap[TokenHash] gets modified with attacker's data
   - State.BalanceMap[TokenHash][Attacker] = 1

**Expected vs Actual Result:**

**Expected:** Two distinct NFTs with separate storage and metadata

**Actual:** 
- Both NFTs share State.NftInfoMap[TokenHash] (metadata corrupted)
- Both NFTs share State.BalanceMap[TokenHash] key (separate address balances but same pool)
- Transfer using either (VW100000000, 123) or (VW1000000001, 23) affects same balance pool
- Events emit different (symbol, tokenId) but manipulate identical storage
- NFT uniqueness guarantee is violated

**Success Condition:** Demonstrate that transferring NFT (VW1000000001, 23) affects the balance pool also accessible by (VW100000000, 123), proving the collision enables cross-NFT manipulation.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L21-35)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L57-80)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var operatorList = State.OperatorMap[input.Symbol][input.From];
        var isOperator = operatorList?.Value.Contains(Context.Sender) ?? false;
        if (!isOperator)
        {
            var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
            Assert(allowance >= input.Amount, "Not approved.");
            State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
        }

        DoTransfer(tokenHash, input.From, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = input.From,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L395-396)
```csharp
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L433-439)
```csharp
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
        }

        State.NftInfoMap[tokenHash] = nftInfo;
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

**File:** protobuf/nft_contract.proto (L126-127)
```text
    // Is token id can be reused.
    bool is_token_id_reuse = 9;
```
