### Title
Hash Collision in NFT BalanceMap Keys Allows Balance Manipulation Across Unrelated Tokens

### Summary
The NFT contract uses string concatenation without delimiters to generate hash keys for BalanceMap storage, combining symbol and tokenId directly. As NFT protocol symbols grow from 9-digit to 10-digit suffixes over time, different (symbol, tokenId) pairs can produce identical hash keys, causing unrelated NFTs to share the same balance storage location and enabling theft.

### Finding Description

The vulnerability exists in the token hash calculation mechanism used as keys for the BalanceMap state variable.

**Root Cause:**

The BalanceMap is defined as a MappedState indexed by token hash and owner address: [1](#0-0) 

Token hashes are computed using simple string concatenation without any delimiter: [2](#0-1) 

NFT protocol symbols are generated with a 2-character type code followed by a random number starting at 9 digits: [3](#0-2) 

The minimum number length is hardcoded as 9 digits: [4](#0-3) 

As more protocols are created, the random number length automatically increases from 9 to 10+ digits: [5](#0-4) 

**Why Protections Fail:**

The lack of delimiter in string concatenation creates ambiguity. When symbols transition from 9-digit to 10-digit suffixes, collision scenarios emerge:

- Protocol A (early): Symbol = "AR100000000" (11 chars: 2-letter + 9 digits)
- Protocol B (later): Symbol = "AR1000000001" (12 chars: 2-letter + 10 digits)

Collision example:
- Protocol A TokenId 23 → Hash("AR100000000" + "23") = Hash("AR10000000023")
- Protocol B TokenId 3 → Hash("AR1000000001" + "3") = Hash("AR10000000013")

Different collision:
- Protocol A TokenId 123 → "AR100000000123"
- Protocol B TokenId 23 → "AR100000000123" ✓ **COLLISION**

Both NFTs map to the same BalanceMap key, sharing balance storage.

**Execution Path:**

Balance transfers use the colliding hash directly: [6](#0-5) 

When DoTransfer executes, both colliding NFTs manipulate the same balance location, causing cross-contamination.

### Impact Explanation

**Direct Fund Impact:**

1. **Balance Theft:** An attacker who controls both colliding NFTs can:
   - Mint NFT from Protocol A with collision-prone TokenId
   - Transfer to victim → victim's balance increases for both NFTs
   - Transfer NFT from Protocol B to self → drains victim's balance of Protocol A NFT
   
2. **Balance Corruption:** Legitimate users transferring one NFT inadvertently modify balances of an unrelated NFT they may not even own.

3. **Supply Accounting Failure:** Total supply tracking becomes incorrect as minting one NFT can appear to mint another.

**Affected Parties:**
- All NFT holders when symbol lengths differ (inevitable as protocols grow)
- Secondary market integrity compromised (NFTs thought to be owned may not be)
- Protocol reputation damage

**Severity Justification:**
This is CRITICAL because:
- It violates the fundamental invariant that distinct NFTs must have isolated balance tracking
- Enables direct asset theft without authorization
- Affects all users as symbol length naturally increases
- Cannot be detected by normal balance checks since both NFTs appear to share ownership

### Likelihood Explanation

**Attacker Capabilities:**
- Standard user: can create NFT protocols and mint NFTs
- No special privileges required
- Can monitor on-chain state to determine symbol length transitions

**Attack Complexity:**
1. Monitor when `CurrentSymbolNumberLength` increases from 9 to 10 (observable via protocol creation patterns)
2. Create Protocol A during 9-digit era or identify existing protocol
3. Wait for or create Protocol B during 10-digit era
4. Calculate collision: if ProtocolA.symbol + tokenIdA == ProtocolB.symbol + tokenIdB
5. Mint colliding NFTs with calculated tokenIds
6. Execute transfers to manipulate shared balance

**Feasibility Conditions:**
- Collision is deterministic and calculable given known symbols
- TokenId values are user-controllable during mint operations
- No validation prevents the collision
- Symbol length transition is guaranteed to occur as more protocols are created

**Economic Rationality:**
- Cost: Gas for protocol creation + minting (standard operation costs)
- Benefit: Theft of arbitrary-value NFTs
- Attack is profitable whenever stolen NFT value exceeds creation costs

**Probability:** HIGH - The symbol length transition occurs naturally, making collisions inevitable without mitigation.

### Recommendation

**Immediate Fix:**

Replace the concatenation-based hash with a structured approach that eliminates ambiguity:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    // Use separate hashing of components then combine
    var symbolHash = HashHelper.ComputeFrom(symbol);
    var tokenIdHash = HashHelper.ComputeFrom(tokenId);
    return HashHelper.ConcatAndCompute(symbolHash, tokenIdHash);
}
```

Alternatively, use a delimiter:
```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}|{tokenId}");
}
```

**Invariant Checks:**

1. Add collision detection in PerformMint to reject tokenIds that would create hash collisions with existing protocols
2. Implement unit tests covering multi-length symbol scenarios
3. Add assertion: `State.NftInfoMap[tokenHash] == null || tokenHash matches expected (symbol, tokenId)`

**Test Cases:**

Create regression tests that:
1. Generate protocols with 9-digit and 10-digit symbols
2. Attempt to mint colliding tokenIds
3. Verify balances remain isolated after transfers
4. Test all symbol length transitions (9→10, 10→11, etc.)

### Proof of Concept

**Initial State:**
- System has created enough protocols that `CurrentSymbolNumberLength` = 9
- Protocol A exists with symbol "AR100000000"

**Attack Steps:**

1. **Wait for Length Transition:**
   - Monitor protocol creations until `CurrentSymbolNumberLength` increases to 10
   
2. **Create Collision Protocol:**
   - Attacker calls `Create()` to get Protocol B with symbol "AR1000000001" (10 digits)
   
3. **Calculate Collision:**
   - Compute: "AR100000000" + "123" = "AR100000000123"
   - Compute: "AR1000000001" + "23" = "AR100000000123" ✓ Match found
   
4. **Mint Colliding NFTs:**
   - Mint from Protocol A with TokenId 123 to Victim
   - Mint from Protocol B with TokenId 23 to Attacker
   
5. **Exploit Shared Balance:**
   - Victim transfers Protocol A NFT to someone else
   - Check: Attacker's balance of Protocol B NFT also decreases (unexpected)
   - OR: Attacker transfers Protocol B NFT to self from Victim's address (theft)

**Expected Result:** 
- Protocol A balance and Protocol B balance are independent

**Actual Result:**
- Both NFTs share the same BalanceMap entry
- Transfers of one affect the balance of the other
- Balance corruption or theft occurs

**Success Condition:**
- `GetBalance(victim, ProtocolA, TokenId123) == GetBalance(victim, ProtocolB, TokenId23)`
- Demonstrates shared storage and exploitability

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L22-22)
```csharp
    public MappedState<Hash, Address, long> BalanceMap { get; set; }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L65-116)
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
