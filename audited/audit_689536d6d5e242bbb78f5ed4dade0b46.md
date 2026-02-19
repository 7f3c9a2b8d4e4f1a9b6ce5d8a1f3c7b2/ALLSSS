### Title
Deterministic Hash Causes Infinite Loop DOS in NFT Protocol Creation

### Summary
The `GenerateSymbolNumber()` function contains a critical flaw where it generates a random hash once but attempts to use it in a collision-avoidance loop. Since the hash is never regenerated within the loop, the same number is produced on every iteration, causing an infinite loop when that number already exists in `State.IsCreatedMap`. This results in a DOS of the NFT protocol creation functionality.

### Finding Description

The vulnerability exists in the `GenerateSymbolNumber()` function where a `randomHash` is computed once before entering the do-while loop: [1](#0-0) 

This fixed hash is then used inside the collision-avoidance loop: [2](#0-1) 

The critical flaw is that `Context.ConvertHashToInt64()` is a deterministic function. Given the same `randomHash`, `from`, and `from.Mul(10)` parameters, it will **always return the exact same value**. The implementation confirms this deterministic behavior: [3](#0-2) 

Since the hash never changes within the loop, `randomNumber` will be identical on every iteration. If `State.IsCreatedMap[randomNumber]` returns `true`, the while condition is satisfied and the loop continues indefinitely with no mechanism to escape, consuming gas until the transaction runs out and fails.

This function is invoked through the public `Create()` method: [4](#0-3) 

### Impact Explanation

**Direct Operational Impact:**
- Complete DOS of the `Create()` function for affected sender addresses at specific block heights
- Users attempting to create NFT protocols will experience transaction failures after gas exhaustion
- The NFT protocol creation mechanism becomes unreliable and eventually unusable as more protocols are created

**Scope of Affected Users:**
- Any user whose address and transaction block height combination produces a hash that maps to an already-used symbol number
- As `State.IsCreatedMap` accumulates more entries over time, the probability of collision increases
- With enough protocols created, certain address ranges will be completely unable to create new protocols at any block height

**Protocol Damage:**
- Core functionality of the NFT contract becomes degraded
- Loss of user trust and potential migration to alternative solutions
- Wasted gas fees for users encountering the infinite loop

This is a **Critical** severity issue because it directly impacts the primary functionality of the NFT contract with increasing likelihood over time.

### Likelihood Explanation

**Attacker Capabilities Required:** None - this can occur naturally without any malicious intent.

**Attack Complexity:** Trivial
- User simply calls the public `Create()` method
- No special permissions or setup required
- Occurs automatically when the generated number collides with an existing entry

**Feasibility Conditions:**
- The probability of collision increases monotonically as more NFT protocols are created
- With 9-digit symbol numbers (starting from NumberMinLength = 9), there are initially 9×10^8 possible values [5](#0-4) 
- However, the hash-to-number mapping is deterministic for each (sender, blockHeight) pair
- As the contract is used over time, specific sender addresses will inevitably encounter collisions at certain block heights

**Probability Assessment:**
- Initially low when few protocols exist
- Increases geometrically as `State.IsCreatedMap` fills up
- Eventually reaches 100% for certain address/block height combinations
- The deterministic nature means once an address hits a collision at one block height, it will consistently fail at that same block height if retried

**Detection:** Transaction will fail with gas exhaustion, making it obvious to users but not providing a clear indication of the root cause.

### Recommendation

**Immediate Fix:** Modify the loop to regenerate or vary the hash on each iteration. Three potential approaches:

**Option 1 - Add iteration counter to hash:**
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
    
    long randomNumber;
    int attempt = 0;
    do
    {
        var randomHash = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(Context.Sender),
            HashHelper.ComputeFrom(randomBytes),
            HashHelper.ComputeFrom(attempt)); // Add iteration counter
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        attempt++;
    } while (State.IsCreatedMap[randomNumber] && attempt < 100); // Add max attempts
    
    Assert(attempt < 100, "Failed to generate unique symbol number after 100 attempts.");
    return randomNumber;
}
```

**Option 2 - Add maximum retry limit with length increment:**
Add a retry limit (e.g., 100 attempts) and if exhausted, automatically increment the symbol number length and retry with the new range.

**Invariant Checks to Add:**
- Maximum iteration count to prevent infinite loops
- Assertion that a unique number was successfully generated before returning
- Consider adding metrics/events to track collision rates

**Test Cases:**
1. Fill `State.IsCreatedMap` with consecutive numbers in a range and verify the function can still generate unique numbers
2. Test behavior when approaching capacity in a given length range
3. Verify the function properly transitions to longer symbol numbers when needed
4. Load test with high collision probability to ensure bounded execution time

### Proof of Concept

**Initial State:**
- NFT contract deployed and initialized
- Multiple NFT protocols already created, with their symbol numbers stored in `State.IsCreatedMap`

**Exploit Sequence:**
1. Attacker (or innocent user) observes on-chain state and identifies their address
2. At block height H, the user calls `Create()` with any valid NFT type (e.g., "Art")
3. The function computes: `randomHash = Hash(Hash(userAddress) + Hash(randomBytes from H-1))`
4. This deterministic hash maps to a number N via `ConvertHashToInt64()`
5. If `State.IsCreatedMap[N]` is already true (number N was used by a previous protocol), the loop condition is satisfied
6. Loop iteration 2: Same `randomHash` → same number N → same `IsCreatedMap[N] == true`
7. Loop iteration 3: Same `randomHash` → same number N → same `IsCreatedMap[N] == true`
8. ... continues indefinitely until gas exhaustion

**Expected Result:** Function should generate a unique symbol number and create the NFT protocol successfully.

**Actual Result:** Transaction fails with gas exhaustion. The `Create()` function becomes unusable for this user at this block height, and potentially at all future block heights depending on the randomBytes evolution.

**Success Condition for Exploit:** Transaction failure with gas exhaustion, observable by anyone attempting to call `Create()` when their hash happens to collide with an existing entry.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L75-77)
```csharp
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L79-82)
```csharp
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L173-177)
```csharp
        var range = end.Sub(start);
        var bigInteger = new BigInteger(hash.Value.ToByteArray());
        // This is safe because range is long type.
        var index = Math.Abs((long)(bigInteger % range));
        return index.Add(start);
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
