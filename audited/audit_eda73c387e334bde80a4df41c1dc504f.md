### Title
Predictable NFT Symbol Generation Due to Hash.Empty Fallback in Random Number Provider

### Summary
The `GenerateSymbolNumber()` function in the NFT contract relies on random bytes from the consensus contract's `GetRandomBytes` method. When the requested block height's random hash is not set, `GetRandomHash` returns `Hash.Empty` as a fallback. This leads to predictable symbol generation because `HashHelper.ComputeFrom()` produces a deterministic hash when given the same `BytesValue` containing `Hash.Empty`, allowing attackers to predict and manipulate NFT protocol symbol assignments.

### Finding Description

**Code Location:** [1](#0-0) 

**Root Cause:**
The NFT contract's `GenerateSymbolNumber()` function requests random bytes for the previous block height from the consensus contract. The consensus contract's `GetRandomHash` method uses a fallback pattern that returns `Hash.Empty` when the random hash for a requested height is not found in state: [2](#0-1) 

When `Hash.Empty` is returned, it gets serialized into a `BytesValue` via the `ToBytesValue()` extension method: [3](#0-2) [4](#0-3) 

`Hash.Empty` is a constant value consisting of 32 zero bytes: [5](#0-4) 

**Why Protections Fail:**
When `HashHelper.ComputeFrom()` is called with the `randomBytes` (a `BytesValue` containing the serialized `Hash.Empty`), it uses the `IMessage` overload which serializes the protobuf message and hashes it: [6](#0-5) 

Since both `Hash.Empty` and its `BytesValue` wrapper are deterministic protobuf messages, the serialized bytes are always identical, resulting in `HashHelper.ComputeFrom(randomBytes)` producing the same hash every time.

The final random hash computation only varies by `Context.Sender`: [7](#0-6) 

An attacker who controls their sender address can predict the exact `randomHash` and consequently the `randomNumber` generated, allowing them to predict which NFT protocol symbol will be created.

**Execution Path:**
1. User calls `NFTContract.Create()` which invokes `GetSymbol()`
2. `GetSymbol()` calls `GenerateSymbolNumber()`
3. `GenerateSymbolNumber()` requests random bytes for `CurrentHeight - 1`
4. If `State.RandomHashes[CurrentHeight - 1]` is null, `Hash.Empty` is returned
5. The predictable hash leads to predictable symbol generation [8](#0-7) 

### Impact Explanation

**Concrete Harm:**
- **NFT Protocol Symbol Manipulation**: Attackers can predict which symbols will be generated for NFT protocols, enabling symbol squatting attacks where valuable or desirable protocol identifiers can be pre-computed and claimed
- **Front-Running Attacks**: Since symbols are predictable, attackers can front-run legitimate NFT protocol creation transactions by computing the symbol that would be generated and creating their own malicious protocol with that symbol first
- **Uniqueness Violation**: The core security assumption that NFT protocol symbols are randomly and uniquely generated is violated, compromising the integrity of the NFT namespace

**Who Is Affected:**
- NFT protocol creators who expect unpredictable, fairly distributed symbols
- The NFT ecosystem as a whole, as symbol namespace integrity is compromised
- Users who rely on symbol uniqueness for identifying authentic NFT protocols

**Severity Justification:**
This is a **High severity** vulnerability because it violates a fundamental security invariant (Token Supply & Fees - "NFT uniqueness and ownership checks") and enables namespace manipulation attacks that can affect the entire NFT ecosystem on the chain.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker needs only a normal account to call `Create()`
- Must be able to predict when `State.RandomHashes` will be unpopulated
- Controls their own sender address (standard capability)

**Attack Complexity:**
- Low complexity: simply call `Create()` at the right time with knowledge of sender address
- Can pre-compute expected symbols offline using publicly known values

**Feasibility Conditions:**
This vulnerability can be exploited when `State.RandomHashes[height]` is not set, which occurs in:

1. **Early Block Heights**: The assertion `Assert(input.Value > 1, "Invalid block height.")` prevents querying blocks 0-1, but blocks 2-3 during initial chain deployment may have irregular random hash states [9](#0-8) 

2. **Consensus Irregularities**: If a block is produced without proper AEDPoS consensus transactions (UpdateValue, NextRound, NextTerm, TinyBlock), the random hash may not be set [10](#0-9) 

3. **Side Chains and Development Environments**: Chains that don't follow strict mainchain consensus rules or test environments without full consensus implementation

4. **Chain State Migrations**: After contract upgrades or chain restarts where historical state isn't fully preserved

**Probability Reasoning:**
While properly functioning mainchains should always populate random hashes, the explicit `?? Hash.Empty` fallback indicates developers anticipated scenarios where this wouldn't be the case. The vulnerability is realistic in edge cases and non-mainchain deployments.

### Recommendation

**Code-Level Mitigation:**

1. **Add Validation in NFT Contract**: Before using `randomBytes`, verify it doesn't contain `Hash.Empty`:

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
    
    // NEW: Validate randomBytes is not empty/predictable
    var randomHash = new Hash();
    randomHash.MergeFrom(randomBytes.Value);
    Assert(randomHash != Hash.Empty, "Random hash not available, cannot generate secure symbol.");
    
    var finalHash =
        HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
            HashHelper.ComputeFrom(randomBytes));
    // ... rest of function
}
```

2. **Remove Hash.Empty Fallback in Consensus Contract**: Make `GetRandomHash` fail explicitly rather than return a predictable value:

```csharp
public override Hash GetRandomHash(Int64Value input)
{
    Assert(input.Value > 1, "Invalid block height.");
    Assert(Context.CurrentHeight >= input.Value, "Block height not reached.");
    var randomHash = State.RandomHashes[input.Value];
    Assert(randomHash != null, $"Random hash not available for height {input.Value}.");
    return randomHash;
}
```

3. **Invariant Checks**: Add a startup check in NFT contract initialization to ensure the random number provider is properly seeded before allowing NFT creation

**Test Cases:**
- Test NFT creation attempt when random hash is not available (should revert)
- Test that Hash.Empty cannot be used for symbol generation
- Test symbol generation produces different results for different blocks
- Test that symbols cannot be predicted given knowledge of sender address only

### Proof of Concept

**Required Initial State:**
- Chain at block height >= 3 (to pass assertion checks)
- `State.RandomHashes[CurrentHeight - 1]` is null (simulated by consensus failure or test environment)
- Attacker has a funded account

**Transaction Steps:**

1. **Attacker Pre-computes Symbol**:
   - Attacker knows their sender address `A`
   - Knows that `GetRandomBytes` will return `Hash.Empty` wrapped in `BytesValue`
   - Computes: `hash1 = SHA256(A)`
   - Computes: `hash2 = SHA256(serialize(BytesValue(Hash.Empty)))`  // Always the same
   - Computes: `randomHash = SHA256(hash1 + hash2)`
   - Computes: `randomNumber = ConvertHashToInt64(randomHash, from, from*10)`
   - Predicts symbol: `{NFTType}{randomNumber}`

2. **Attacker Calls Create**:
   - Transaction from address `A`
   - Calls `NFTContract.Create(CreateInput)` with desired NFT type
   - Transaction succeeds

3. **Expected vs Actual Result**:
   - **Expected (Secure)**: Symbol should be unpredictable, different for each creator
   - **Actual (Vulnerable)**: Symbol matches attacker's pre-computed prediction exactly

**Success Condition:**
The symbol returned by `Create()` matches the attacker's pre-computed symbol, proving that symbol generation is predictable and not cryptographically secure when random hashes are unavailable.

### Notes

The vulnerability fundamentally stems from the design decision to use `Hash.Empty` as a fallback rather than failing explicitly when randomness is unavailable. While this may provide better user experience in some scenarios, it creates a security vulnerability by making supposedly random values predictable. The NFT contract should validate that proper randomness is available before proceeding with symbol generation, as the security model depends on unpredictable symbol assignment.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-77)
```csharp
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L117-122)
```csharp
    public override Hash GetRandomHash(Int64Value input)
    {
        Assert(input.Value > 1, "Invalid block height.");
        Assert(Context.CurrentHeight >= input.Value, "Block height not reached.");
        return State.RandomHashes[input.Value] ?? Hash.Empty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L124-129)
```csharp
    public override BytesValue GetRandomBytes(BytesValue input)
    {
        var height = new Int64Value();
        height.MergeFrom(input.Value);
        return GetRandomHash(height).ToBytesValue();
    }
```

**File:** src/AElf.Types/Extensions/IMessageExtensions.cs (L9-12)
```csharp
        public static BytesValue ToBytesValue(this IMessage message)
        {
            return new BytesValue { Value = message.ToByteString() };
        }
```

**File:** src/AElf.Types/Types/Hash.cs (L13-14)
```csharp
        public static readonly Hash Empty = LoadFromByteArray(Enumerable.Range(0, AElfConstants.HashByteArrayLength)
            .Select(x => byte.MinValue).ToArray());
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L55-58)
```csharp
        public static Hash ComputeFrom(IMessage message)
        {
            return ComputeFrom(message.ToByteArray());
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
```
