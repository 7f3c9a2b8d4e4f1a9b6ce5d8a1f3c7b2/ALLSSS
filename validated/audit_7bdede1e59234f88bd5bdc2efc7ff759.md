# Audit Report

## Title
Deterministic Random Hash Generation Causes DoS in NFT Protocol Creation for Multiple Transactions per Block

## Summary
The `GenerateSymbolNumber()` function in the NFT contract computes a random hash only once before entering a collision-detection loop. When multiple transactions from the same sender are included in the same block, all transactions after the first one generate identical random numbers in every loop iteration, causing an infinite loop that fails after hitting the 15,000 branch execution threshold.

## Finding Description

The vulnerability exists in the NFT protocol symbol creation logic. The `GenerateSymbolNumber()` function retrieves random bytes from the consensus contract for the previous block height and combines them with the sender's address to compute a `randomHash`. [1](#0-0) 

This `randomHash` is computed **once** before the do-while loop and is never updated inside the loop. The loop repeatedly calls `ConvertHashToInt64()` with the same hash to generate a random number, then checks if that number has been marked as used. [2](#0-1) 

The consensus contract's `GetRandomBytes` implementation retrieves deterministic random hash values stored per block height. [3](#0-2) 

The `ConvertHashToInt64` function is deterministic, using modulo arithmetic to map a hash to an integer range. [4](#0-3) 

When multiple transactions from the same sender are included in the same block, all transactions have identical `Context.Sender` values and identical `Context.CurrentHeight` values, resulting in identical `randomBytes` from the consensus contract, identical `randomHash` values, and identical `randomNumber` values in each loop iteration.

The first transaction succeeds and marks the generated number as used. [5](#0-4) 

Subsequent transactions repeatedly compute the same `randomNumber`, find it marked as used, and loop indefinitely. The execution continues until the branch threshold is exceeded. [6](#0-5) 

When the threshold is reached, the system throws a `RuntimeBranchThresholdExceededException`. [7](#0-6) 

This vulnerability is triggered through the public `Create` method which is accessible to any user. [8](#0-7) 

## Impact Explanation

**Severity: HIGH**

1. **Denial of Service**: Users attempting to create multiple NFT protocols in rapid succession will have all transactions after the first one fail when they are batched into the same block by block producers.

2. **Financial Loss**: Users lose transaction fees for failed transactions that consume maximum execution resources (15,000 branch iterations) before failing.

3. **Resource Exhaustion**: Each failed transaction wastes computational resources executing 15,000 loop iterations before termination.

4. **No Workaround**: Users cannot bypass this issue except by manually spacing out transactions across multiple blocks, which may not be immediately apparent and degrades user experience.

5. **Core Functionality Impaired**: NFT protocol creation is a fundamental feature, and its availability is compromised for common usage patterns where users or automated systems submit multiple creation requests.

6. **Protocol Invariant Violation**: The NFT uniqueness guarantee mechanism fails to function correctly, as the collision detection loop cannot find alternative numbers when collisions occur within the same block due to the static hash value.

## Likelihood Explanation

**Likelihood: HIGH**

1. **No Privileges Required**: Any user can call the public `Create` method without special permissions or authorization checks.

2. **Common Scenario**: Users naturally submit multiple transactions in quick succession through wallets, dApps, or automated systems. Block producers routinely batch multiple transactions from the same user into single blocks for efficiency.

3. **Deterministic Trigger**: The issue occurs 100% of the time when the conditions are met (same sender, same block, symbol number collision).

4. **Easy to Reproduce**: Both malicious actors and legitimate users can trigger this vulnerability through normal usage patterns.

5. **No Pre-existing Constraints**: There are no rate limits, delays, nonces, or other mechanisms preventing multiple transactions from the same sender in a single block.

## Recommendation

Modify the `GenerateSymbolNumber()` function to update the `randomHash` inside the loop iteration to ensure different random numbers are generated on each attempt:

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
    
    var randomHash = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender),
        HashHelper.ComputeFrom(randomBytes));
    
    long randomNumber;
    do
    {
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        // Update randomHash for next iteration to avoid infinite loop
        randomHash = HashHelper.ComputeFrom(randomHash);
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

Alternatively, add a nonce or iteration counter to vary the hash:

```csharp
var nonce = 0;
do
{
    var iterationHash = HashHelper.ConcatAndCompute(randomHash, HashHelper.ComputeFrom(nonce));
    randomNumber = Context.ConvertHashToInt64(iterationHash, from, from.Mul(10));
    nonce++;
} while (State.IsCreatedMap[randomNumber] && nonce < 1000);
```

## Proof of Concept

A test demonstrating this vulnerability would involve:
1. Creating an NFT protocol in block N (succeeds)
2. Attempting to create a second NFT protocol from the same sender in block N (fails after 15,000 iterations)

The test would verify that the second transaction fails with `RuntimeBranchThresholdExceededException` due to the infinite loop caused by the static `randomHash` value.

## Notes

This vulnerability fundamentally breaks the collision detection mechanism in NFT protocol creation. The design assumes that the do-while loop can find an unused symbol number, but when the hash remains constant across iterations, the loop generates the same number repeatedly. The 15,000 branch threshold acts as a safety mechanism to prevent true infinite loops, but it results in wasted resources and failed transactions rather than preventing the vulnerability.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L27-27)
```csharp
        State.IsCreatedMap[randomNumber] = true;
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L79-82)
```csharp
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L124-128)
```csharp
    public override BytesValue GetRandomBytes(BytesValue input)
    {
        var height = new Int64Value();
        height.MergeFrom(input.Value);
        return GetRandomHash(height).ToBytesValue();
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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L31-33)
```csharp
        if (_branchThreshold != -1 && _branchCount == _branchThreshold)
            throw new RuntimeBranchThresholdExceededException(
                $"Contract branch threshold {_branchThreshold} exceeded.");
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
