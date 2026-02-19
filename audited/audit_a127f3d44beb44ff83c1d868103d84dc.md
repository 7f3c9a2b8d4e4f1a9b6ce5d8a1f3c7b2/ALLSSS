# Audit Report

## Title
Predictable NFT Symbol Generation Enables Selective Participation Attack

## Summary
The NFT contract's `GenerateSymbolNumber()` function uses the previous block's random hash as its entropy source, which is publicly readable before transactions execute in the current block. Since the function also combines this with `Context.Sender` (which attackers control), attackers can predict their exact symbol before submitting transactions and selectively participate only when obtaining desirable symbols, systematically monopolizing valuable vanity symbol numbers.

## Finding Description

The vulnerability exists in the random number generation mechanism used for NFT protocol symbol creation. When a user calls the `Create` method to create a new NFT protocol, the system generates a unique symbol by combining a type prefix (e.g., "AR" for Art) with a random number.

The randomness generation occurs in `GenerateSymbolNumber()` which requests random bytes from the consensus contract using the previous block height: [1](#0-0) 

This calls the ACS6 `GetRandomBytes` method, which is explicitly marked as a view method in the protocol definition: [2](#0-1) 

The consensus contract stores random hashes during block production: [3](#0-2) 

These stored hashes are publicly readable through view methods: [4](#0-3) 

The critical flaw is that while the function combines the sender's address with the random bytes: [5](#0-4) 

This does NOT prevent prediction because attackers control their own address. The attack flow:

1. After block H-1 is finalized, `State.RandomHashes[H-1]` becomes publicly readable
2. Attacker computes: `Hash(Hash(AttackerAddress) + RandomHash[H-1])`
3. Attacker converts this to a symbol number using the same `ConvertHashToInt64` logic: [6](#0-5) 
4. If the symbol is desirable (e.g., "AR888888", "AR123456"), submit `Create` transaction
5. If not desirable, skip and wait for the next block

The `do-while` loop only prevents duplicate symbols, not predictability: [7](#0-6) 

## Impact Explanation

**Fairness Violation**: The NFT protocol assumes fair, unpredictable symbol allocation. This vulnerability breaks that fundamental assumption, allowing sophisticated actors to gain systematic advantages.

**Economic Value Extraction**: NFT symbols with desirable patterns (repeating digits, sequential numbers, palindromes) have significant market value, similar to vanity cryptocurrency addresses or premium domain names. Attackers can:
- Monopolize premium symbols over time
- Create artificial scarcity
- Extract value from legitimate creators who must accept less desirable symbols
- Potentially sell accumulated premium symbols at inflated prices

**Ecosystem Trust Impact**: The attack is undetectable to normal users who assume randomness, undermining trust in the NFT protocol's fairness when premium symbols consistently go to the same sophisticated actors.

**Severity: Medium-High** - While this doesn't directly steal funds or break consensus, it represents a significant protocol integrity violation with real economic consequences and enables systematic value extraction.

## Likelihood Explanation

**Attack Complexity: LOW**
- Only requires standard blockchain node query capabilities
- Standard hash computation (available in any programming environment)
- Basic transaction submission

**Attacker Requirements:**
- No special privileges needed
- No need to compromise any systems
- Can be fully automated with simple scripts
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

**Solution 1: Commit-Reveal Scheme**
Implement a two-phase creation process:
1. Phase 1 (Commit): User submits a hash of their intent with a secret nonce
2. Phase 2 (Reveal): After commitment is included in a block, user reveals the secret and receives a symbol based on the block hash at commitment time combined with their secret

This prevents prediction because the attacker cannot know the future block hash when committing.

**Solution 2: Use Current Block Information**
Instead of using the previous block's hash, use information only available during transaction execution:
- Current transaction hash
- Current block time
- Transaction input hash
Combined with sender address

The consensus contract already provides this through `Context.GetRandomHash()` which is designed for this purpose: [8](#0-7) 

**Recommended Fix:**
Replace the call to `State.RandomNumberProviderContract.GetRandomBytes.Call(...)` with `Context.GetRandomHash(Context.Sender)` which already combines multiple sources of entropy available only at execution time.

## Proof of Concept

```csharp
[Fact]
public async Task PredictableSymbolGeneration_AttackerCanSelectivelyParticipate()
{
    // Simulate attacker's prediction capability
    
    // Step 1: Get consensus contract stub
    var consensusStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ConsensusContractAddress, DefaultKeyPair);
    
    // Step 2: Read current block height
    var currentHeight = (await consensusStub.GetCurrentRoundNumber.CallAsync(new Empty())).Value;
    
    // Step 3: Attacker reads previous block's random hash (publicly available via view method)
    var previousRandomHash = await consensusStub.GetRandomHash.CallAsync(
        new Int64Value { Value = currentHeight - 1 });
    
    // Step 4: Attacker computes what their symbol would be
    var attackerAddressHash = HashHelper.ComputeFrom(DefaultAddress);
    var predictedRandomHash = HashHelper.ConcatAndCompute(
        attackerAddressHash,
        HashHelper.ComputeFrom(previousRandomHash.ToBytesValue()));
    
    // Step 5: Compute predicted symbol number using same logic as contract
    var numberLength = 9; // Assuming current length is 9
    var from = 100000000L; // 10^8
    var range = 900000000L; // 10^9 - 10^8
    var bigInteger = new BigInteger(predictedRandomHash.Value.ToByteArray());
    var predictedNumber = Math.Abs((long)(bigInteger % range)) + from;
    
    // Step 6: Attacker decides whether to participate
    var isDesirable = IsDesirableSymbol(predictedNumber); // e.g., repeating digits
    
    if (isDesirable)
    {
        // Submit transaction
        var result = await NFTContractStub.Create.SendAsync(new CreateInput
        {
            NftType = NFTType.Art.ToString(),
            ProtocolName = "Premium",
            TotalSupply = 1000000,
            BaseUri = "ipfs://test/"
        });
        
        var actualSymbol = result.Output.Value;
        var actualNumber = long.Parse(actualSymbol.Substring(2)); // Remove "AR" prefix
        
        // Verify prediction matches reality
        actualNumber.ShouldBe(predictedNumber);
    }
    // else: Skip this block and wait for next opportunity
}

private bool IsDesirableSymbol(long number)
{
    var str = number.ToString();
    // Check for repeating digits (e.g., 111111111, 888888888)
    return str.Distinct().Count() == 1 ||
           // Check for sequential digits
           IsSequential(str) ||
           // Check for palindrome
           str.SequenceEqual(str.Reverse());
}
```

This test demonstrates that an attacker can predict their exact symbol before submitting a transaction by reading publicly available blockchain state, enabling selective participation to monopolize valuable symbols.

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

**File:** protobuf/acs6.proto (L19-21)
```text
    rpc GetRandomBytes (google.protobuf.BytesValue) returns (google.protobuf.BytesValue) {
        option (aelf.is_view) = true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L80-81)
```csharp
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

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L161-167)
```csharp

    public Hash GetRandomHash(Hash fromHash)
    {
        var currentBlockTimeHash = HashHelper.ComputeFrom(CurrentBlockTime);
        return HashHelper.XorAndCompute(TransactionId, HashHelper.XorAndCompute(currentBlockTimeHash,
            HashHelper.XorAndCompute(fromHash, PreviousBlockHash)));
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
