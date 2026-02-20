# Audit Report

## Title
Predictable NFT Symbol Generation Enables Selective Participation Attack

## Summary
The NFT contract's symbol generation mechanism uses publicly readable randomness from the previous block combined with attacker-controlled sender addresses, allowing attackers to predict their symbol before submitting transactions and selectively participate only when obtaining desirable vanity symbols.

## Finding Description

The vulnerability exists in the random number generation for NFT protocol symbol creation. When users call the `Create` method to create NFT protocols, the system generates symbols by combining a type prefix with a random number. [1](#0-0) 

The randomness generation occurs in `GenerateSymbolNumber()`, which retrieves random bytes from the consensus contract using the **previous block height**: [2](#0-1) 

This calls the ACS6 `GetRandomBytes` method, which is explicitly marked as a **view method** in the protocol definition: [3](#0-2) 

The implementation returns publicly readable state: [4](#0-3) 

These random hashes are stored during block production: [5](#0-4) 

The critical flaw is that while the function combines the sender's address with the random bytes, **attackers control their own address**: [6](#0-5) 

**Attack Flow:**
1. After block H-1 is finalized, `State.RandomHashes[H-1]` becomes publicly readable via `GetRandomBytes`
2. Attacker computes: `Hash(Hash(AttackerAddress) + RandomHash[H-1])`
3. Attacker converts to symbol number using the same `ConvertHashToInt64` logic
4. If symbol is desirable (e.g., "AR888888", "AR123456"), submit `Create` transaction
5. If not desirable, skip and wait for next block

The `do-while` loop only prevents duplicate symbols, not predictability: [7](#0-6) 

## Impact Explanation

**Fairness Violation**: The NFT protocol assumes fair, unpredictable symbol allocation. This vulnerability breaks that fundamental security guarantee, allowing sophisticated actors to gain systematic advantages over regular users.

**Economic Value Extraction**: NFT symbols with desirable patterns (repeating digits, sequential numbers, palindromes) have significant market value similar to vanity cryptocurrency addresses or premium domain names. Attackers can monopolize premium symbols over time, create artificial scarcity, and extract value from legitimate creators who must accept less desirable symbols.

**Ecosystem Trust Impact**: The attack is undetectable to normal users who assume randomness, undermining trust in the NFT protocol's fairness when premium symbols consistently go to the same sophisticated actors.

**Severity: Medium-High** - While this doesn't directly steal funds or break consensus, it represents a significant protocol integrity violation with real economic consequences enabling systematic value extraction.

## Likelihood Explanation

**Attack Complexity: LOW**
- Only requires standard blockchain node query capabilities (view method calls)
- Standard hash computation available in any programming environment
- Basic transaction submission

**Attacker Requirements:**
- No special privileges needed
- No need to compromise any systems
- Fully automatable with simple scripts
- Economic cost is minimal (only pay fees for desirable symbols)

**Practical Execution:**
1. Monitor blockchain for new blocks
2. For each block H-1, query `GetRandomBytes(H-1)` via view method
3. Compute predicted symbol for own address
4. Submit transaction only if symbol meets desirability criteria
5. Repeat for every block

**Detection Difficulty:** The attack is indistinguishable from normal usage patterns since attackers submit legitimate `Create` transactions. Multiple addresses can be used to avoid pattern detection.

**Likelihood: HIGH** - The attack is practical, profitable, automatable, and undetectable.

## Recommendation

Implement commit-reveal scheme or use future block hashes for randomness:

**Option 1: Commit-Reveal Scheme**
- Users first commit to a secret value in transaction 1
- After commitment is finalized, create NFT in transaction 2 using hash of (secret + block hash)
- This prevents prediction since the secret is unknown when querying block hash

**Option 2: Future Block Hash**
- Use `Context.CurrentHeight + N` where N > 0 for randomness source
- Symbol is assigned only after N blocks pass
- Prevents prediction since future block hash is unknown at submission time

**Option 3: Additional Entropy from Transaction Hash**
- Combine `Context.TransactionId` (unpredictable before inclusion) with other entropy sources
- Makes prediction impossible before transaction is included in a block

## Proof of Concept

```csharp
// Attacker script (off-chain):
// 1. Query GetRandomBytes for previous block
var previousBlockHeight = await GetCurrentBlockHeight() - 1;
var randomBytes = await ConsensusContract.GetRandomBytes(previousBlockHeight);

// 2. Predict symbol for attacker's address
var attackerAddress = "attacker_address_here";
var predictedHash = Hash.Concat(
    Hash.ComputeFrom(attackerAddress),
    Hash.ComputeFrom(randomBytes)
);
var predictedSymbol = ConvertHashToInt64(predictedHash, from, to);

// 3. Selectively submit only if desirable
if (IsDesirableSymbol(predictedSymbol)) { // e.g., contains "888" or "123456"
    await NFTContract.Create(nftTypeInput);
    // Will receive the predicted premium symbol
}
// Otherwise, wait for next block and repeat
```

The vulnerability is confirmed by the code path showing that `GetRandomBytes` returns publicly readable state from previous blocks, combined with attacker-controlled sender addresses, enabling deterministic pre-computation of resulting symbols.

### Citations

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-74)
```csharp
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L76-77)
```csharp
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

**File:** protobuf/acs6.proto (L19-21)
```text
    rpc GetRandomBytes (google.protobuf.BytesValue) returns (google.protobuf.BytesValue) {
        option (aelf.is_view) = true;
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
