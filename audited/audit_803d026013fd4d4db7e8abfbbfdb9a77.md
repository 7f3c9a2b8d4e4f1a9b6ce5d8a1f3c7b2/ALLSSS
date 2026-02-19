### Title
Infinite Loop DoS in NFT Protocol Symbol Generation Due to Non-Updating Random Hash

### Summary
The `GenerateSymbolNumber()` function contains a critical flaw where the `randomHash` is computed once outside the do-while loop, causing `Context.ConvertHashToInt64()` to return the same value on every iteration. When a collision occurs with an already-created symbol number, the loop becomes infinite until the AElf execution observer stops it at 15,000 branches, causing guaranteed transaction failure and DoS of NFT protocol creation.

### Finding Description

The vulnerability exists in the `GenerateSymbolNumber()` method where a do-while loop attempts to find an unused random number for NFT symbol generation. [1](#0-0) 

**Root Cause**: The `randomHash` is computed once outside the loop (lines 71-77), then inside the do-while loop (lines 79-82), `Context.ConvertHashToInt64(randomHash, from, from.Mul(10))` is called repeatedly with the same hash and range parameters. Since `ConvertHashToInt64()` is a deterministic function that uses modulo arithmetic to map a hash to a range: [2](#0-1) 

The function will always return the **exact same `randomNumber`** on every iteration. If `State.IsCreatedMap[randomNumber]` is `true`, the loop condition remains `true` forever, creating an infinite loop.

**Why Protections Fail**: While AElf's execution observer will eventually stop the loop after 15,000 branch counts: [3](#0-2) 

This still results in transaction failure. The loop has no mechanism to:
1. Generate a new random value by re-hashing
2. Limit iterations with a maximum retry count
3. Gracefully handle collisions

**Execution Path**: The function is called from `GetSymbol()` during NFT protocol creation: [4](#0-3) 

Which is invoked from the public `Create()` method: [5](#0-4) 

### Impact Explanation

**Operational DoS Impact**:
- When a collision occurs, the transaction **fails after 15,000 loop iterations**
- User loses transaction fees with no NFT protocol created
- NFT protocol creation functionality becomes unusable for affected sender/block-height combinations
- No recovery mechanism - the same sender at the same block height will always generate the same failing randomHash

**Collision Probability Analysis**:
- Initial number space: 100,000,000 to 999,999,999 (900 million numbers) [6](#0-5) 

- After ~30,000 NFT protocols created: collision probability becomes non-negligible (birthday paradox: √900M ≈ 30,000)
- After ~300,000 protocols: collisions become increasingly likely
- Each collision results in guaranteed transaction failure

**Affected Parties**:
- Users attempting to create NFT protocols
- Platform reputation when creation transactions mysteriously fail
- Economic loss through wasted transaction fees

### Likelihood Explanation

**Reachable Entry Point**: The `Create()` method is publicly accessible to any user creating NFT protocols.

**Feasible Preconditions**: 
- Natural occurrence as the NFT ecosystem grows - no attacker needed
- Collision probability increases quadratically with number of created protocols
- Random number depends on `Context.Sender` and block height randomness, which provides limited entropy

**Malicious Exploitation**:
1. Attacker monitors blockchain to predict random numbers for specific sender/block combinations
2. Attacker creates NFT protocols to deliberately occupy those numbers
3. Victim transactions fail when attempting to create protocols
4. Attack cost: gas fees for NFT creation × number of targeted numbers

**Execution Practicality**: 
- Bug triggers automatically when collision occurs - no special transaction crafting needed
- AElf execution model will terminate the loop at 15,000 branches, guaranteeing failure
- Reproducible: same sender + same block height = same deterministic failure

**Probability Assessment**: 
- **Short-term (< 10,000 protocols)**: Low probability, rare natural collisions
- **Medium-term (10,000-100,000 protocols)**: Medium probability, occasional failures
- **Long-term (> 100,000 protocols)**: High probability, frequent DoS events
- **With malicious actor**: Attacker can deliberately trigger for griefing

### Recommendation

**Primary Fix - Regenerate Random Hash on Collision**:
```
Modify the loop to update randomHash on each iteration:

private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(
        new Int64Value { Value = Context.CurrentHeight.Sub(1) }.ToBytesValue());
    var randomHash = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender),
        HashHelper.ComputeFrom(randomBytes));
    
    long randomNumber;
    int attempts = 0;
    const int MAX_ATTEMPTS = 100;
    
    do
    {
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        if (!State.IsCreatedMap[randomNumber])
            break;
        
        // Rehash to get a new random number
        randomHash = HashHelper.ComputeFrom(randomHash);
        attempts++;
        
        Assert(attempts < MAX_ATTEMPTS, "Failed to generate unique symbol number after maximum attempts");
    } while (true);

    return randomNumber;
}
```

**Alternative Fix - Remove Collision Check**:
If collision checking is not strictly necessary (symbols can be allowed to have numeric conflicts as long as the full symbol string is unique), remove the loop entirely and accept the generated number.

**Invariant Checks**:
- Add iteration counter with maximum threshold
- Log collision events for monitoring
- Add assertion that randomHash changes between iterations

**Test Cases**:
1. Pre-populate IsCreatedMap with specific number, verify transaction doesn't hang
2. Create 1000+ protocols and monitor for failed transactions
3. Test collision scenario with mocked randomHash returning same value

### Proof of Concept

**Initial State**:
- NFT contract deployed and initialized
- Assume ~50,000 NFT protocols already created, filling IsCreatedMap

**Attack Sequence**:
1. Attacker calculates that for sender address `0xABC...` at block height `H`, the generated randomHash will produce `randomNumber = 123456789`
2. Attacker (or natural occurrence) has already created an NFT protocol that resulted in that number being set in `State.IsCreatedMap[123456789] = true`
3. Legitimate user with address `0xABC...` calls `Create()` at block height `H`

**Expected Result**: 
- New NFT protocol created with a unique symbol number
- Transaction succeeds

**Actual Result**:
- `GenerateSymbolNumber()` enters infinite loop at line 79-82
- Loop iterates exactly 15,000 times (branch count limit)
- Transaction execution paused by execution observer
- Transaction fails with execution limit exceeded
- User loses transaction fees
- No NFT protocol created
- User cannot retry with same sender at same block height

**Success Condition for Exploit**: Transaction failure confirmed when `State.IsCreatedMap[randomNumber]` returns true for the deterministically generated number.

### Citations

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

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L169-178)
```csharp
    public long ConvertHashToInt64(Hash hash, long start = 0, long end = long.MaxValue)
    {
        if (start < 0 || start > end) throw new ArgumentException("Incorrect arguments.");

        var range = end.Sub(start);
        var bigInteger = new BigInteger(hash.Value.ToByteArray());
        // This is safe because range is long type.
        var index = Math.Abs((long)(bigInteger % range));
        return index.Add(start);
    }
```

**File:** docs-sphinx/architecture/smart-contract/restrictions/others.rst (L15-15)
```text
- AElf's contract patcher will patch method branch count observer for your contract. This is used to prevent infinitely loop case. The number of code control transfer in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-20)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```
