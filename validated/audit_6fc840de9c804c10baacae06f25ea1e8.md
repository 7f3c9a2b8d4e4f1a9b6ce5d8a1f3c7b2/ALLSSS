# Audit Report

## Title
Predictable NFT Symbol Generation Enables Selective Participation Attack

## Summary
The NFT contract's symbol generation mechanism uses the previous block's random hash as its randomness source. Since this random hash is publicly readable before transactions execute, attackers can predict their assigned symbol number in advance and selectively submit NFT creation transactions only when they would receive desirable vanity symbols, enabling systematic monopolization of premium symbol numbers.

## Finding Description

The NFT contract generates protocol symbols by combining a type prefix with a random number. The `GenerateSymbolNumber()` function obtains this random number by querying the consensus contract for the random hash of the previous block. [1](#0-0) 

When a transaction executes in block H, it requests randomness from block H-1. The consensus contract stores random hashes during block production using EC-VRF verification. [2](#0-1) 

Once block H-1 is finalized, its random hash becomes publicly accessible through the `GetRandomHash` view method. [3](#0-2) 

The `GetRandomBytes` method is explicitly marked as a view method in the ACS6 protocol definition. [4](#0-3) 

**Attack Execution Flow:**

1. After block N is finalized, attacker queries `GetRandomHash(N)` to retrieve the stored random hash
2. Attacker computes predicted symbol for their address by combining `Hash(AttackerAddress)` with the retrieved random hash. [5](#0-4) 
3. Converts to symbol number. [6](#0-5) 
4. If the predicted symbol is desirable (e.g., contains repeating digits like 111111 or 888888), attacker submits `Create` transaction in block N+1
5. If not desirable, attacker waits for next block and repeats

**Why Existing Protections Fail:**

The inclusion of `Context.Sender` in the hash computation does not prevent prediction because the attacker is computing the outcome for their own address - they know all inputs to the calculation. The do-while collision check only prevents duplicate symbols, not predictability. [7](#0-6) 

## Impact Explanation

**High Severity** - This vulnerability breaks the fundamental fairness guarantee of the NFT protocol symbol allocation mechanism.

**Concrete Harms:**
- **Value Extraction**: Premium NFT symbols (patterns like AR111111, AR888888, AR123456) have intrinsic market value similar to vanity addresses or premium domain names. Attackers can systematically monopolize these valuable symbols.
- **Market Manipulation**: Attackers can accumulate portfolios of premium symbols and either withhold them or sell at inflated prices, extracting value from the ecosystem.
- **Fairness Violation**: Legitimate NFT creators cannot compete on equal terms for desirable symbols, undermining trust in the protocol.
- **Systemic Impact**: The attack can be executed repeatedly over time, allowing sustained value extraction with minimal cost (only transaction fees for desirable symbols).

## Likelihood Explanation

**High Likelihood** - The attack is practical, profitable, and requires only standard blockchain capabilities.

**Attacker Requirements:**
- Read blockchain state through standard node queries (no special access)
- Compute hash functions (standard cryptographic operations)
- Submit transactions (basic blockchain participation)

**Feasibility:**
- No special privileges required
- Works for any NFT type
- Easily automated with monitoring scripts
- Undetectable - transactions appear legitimate
- Economic cost is minimal - attacker only pays fees when obtaining desirable symbols

The attack can be executed by any rational actor monitoring the blockchain, making exploitation highly probable.

## Recommendation

Use commit-reveal schemes or incorporate future block data that cannot be predicted at transaction submission time. Specifically:

1. **Option 1 - Commit-Reveal**: Require users to commit to creating an NFT in block N (with a hash commitment), then reveal and execute in block N+k where k > 1, using the random hash from block N+k-1. This prevents prediction because the random hash is not known at commitment time.

2. **Option 2 - Future Block Data**: Use `Context.CurrentHeight` (the block being created) instead of `Context.CurrentHeight.Sub(1)`. However, this requires careful consideration as the current block's random hash is generated during consensus and may not be available during transaction execution.

3. **Option 3 - Transaction Hash Mixing**: Mix in `Context.TransactionId` which cannot be known before the transaction is included in a block, though this requires ensuring transaction IDs are not predictable.

The recommended approach is the commit-reveal scheme as it provides strong unpredictability guarantees without requiring changes to the consensus layer.

## Proof of Concept

```csharp
// Attacker's off-chain script
public async Task<bool> ShouldSubmitNFTCreation()
{
    // Step 1: Get current block height
    var currentHeight = await GetCurrentBlockHeight();
    
    // Step 2: Query previous block's random hash (view method - no transaction)
    var randomHash = await ConsensusContract.GetRandomHash(currentHeight - 1);
    
    // Step 3: Predict symbol for attacker's address
    var attackerAddress = GetAttackerAddress();
    var senderHash = HashHelper.ComputeFrom(attackerAddress);
    var combinedHash = HashHelper.ConcatAndCompute(senderHash, HashHelper.ComputeFrom(randomHash));
    
    // Step 4: Convert to symbol number using same logic as contract
    var symbolNumber = ConvertHashToInt64(combinedHash, from, to);
    
    // Step 5: Check if desirable (e.g., repeating digits)
    if (IsDesirableSymbol(symbolNumber)) 
    {
        // Submit NFT creation transaction - will be included in next block
        await SubmitNFTCreationTransaction();
        return true;
    }
    
    // Wait for next block and retry
    return false;
}

private bool IsDesirableSymbol(long symbolNumber)
{
    var str = symbolNumber.ToString();
    // Check for patterns like 111111, 888888, 123456, etc.
    return HasRepeatingDigits(str) || IsSequential(str) || IsPalindrome(str);
}
```

This proof of concept demonstrates that an attacker can predict their symbol number before submitting a transaction, enabling selective participation.

**Notes:**

- The vulnerability is confirmed across multiple contract files spanning the NFT contract and consensus contract implementation
- The attack vector is architectural - it stems from using finalized, publicly readable randomness for future transaction outcomes
- The randomness itself (EC-VRF) is cryptographically sound; the issue is the timing of when it becomes accessible versus when it's used
- This is not a theoretical vulnerability - it has concrete economic impact as premium symbols have market value in NFT ecosystems

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-74)
```csharp
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L117-122)
```csharp
    public override Hash GetRandomHash(Int64Value input)
    {
        Assert(input.Value > 1, "Invalid block height.");
        Assert(Context.CurrentHeight >= input.Value, "Block height not reached.");
        return State.RandomHashes[input.Value] ?? Hash.Empty;
    }
```

**File:** protobuf/acs6.proto (L19-21)
```text
    rpc GetRandomBytes (google.protobuf.BytesValue) returns (google.protobuf.BytesValue) {
        option (aelf.is_view) = true;
    }
```
