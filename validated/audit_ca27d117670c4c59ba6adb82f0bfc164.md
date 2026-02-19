# Audit Report

## Title
Null Signature Handling Causes Consensus DoS in CalculateSignature()

## Summary
The AEDPoS consensus contract contains a critical null reference vulnerability where `CalculateSignature()` aggregates miner signatures without null checks. When miners miss their time slots in any round (especially the first round of a term), their signatures remain uninitialized (null), causing `NextRound()` to crash with a `NullReferenceException` and halting consensus completely.

## Finding Description

The vulnerability exists in a multi-layer call chain starting from consensus round transitions:

**Entry Point:** The public `NextRound()` method is called to transition between consensus rounds. [1](#0-0) 

**Supply Logic:** `SupplyCurrentRoundInformation()` attempts to fill missing information for miners who didn't mine. For miners without `OutValue` (indicating they didn't mine), it retrieves the previous round and calculates their signature: [2](#0-1) 

**Signature Aggregation:** The `CalculateSignature()` method aggregates all miner signatures from the round using XOR operations: [3](#0-2) 

**Vulnerable Helper:** The `HashHelper.XorAndCompute()` method directly accesses `h2.Value[i]` without checking if `h2` is null: [4](#0-3) 

**Root Cause:** When new rounds are generated, the `Signature` field is never initialized. In `GenerateNextRoundInformation()`: [5](#0-4) 

Similarly, in `GenerateFirstRoundOfNewTerm()`: [6](#0-5) 

The `Signature` field is only set when a miner successfully produces a block via `ProcessUpdateValue()`: [7](#0-6) 

The protobuf definition shows `Signature` is an optional field that defaults to null: [8](#0-7) 

**Attack Scenario:**
1. A new term begins, first round is generated with all `Signature` fields = null
2. Some miners produce blocks → their signatures are set via `ProcessUpdateValue()`
3. At least one miner misses their time slot → their signature remains null
4. A validator calls `NextRound()` to transition to round 2
5. `SupplyCurrentRoundInformation()` retrieves round 1 data
6. For any miner who didn't mine in round 2, it calls `previousRound.CalculateSignature()`
7. This aggregates ALL miners from round 1, including those with null signatures
8. `HashHelper.XorAndCompute()` crashes with `NullReferenceException` when accessing `null.Value[i]`
9. Transaction fails, consensus cannot progress

## Impact Explanation

**Severity: High**

This vulnerability causes complete consensus denial-of-service:

- **Consensus Halt**: Once triggered, `NextRound()` cannot execute successfully, preventing any new rounds from being created
- **Block Production Stoppage**: No new blocks can be produced until manual intervention
- **Network-Wide Impact**: All validators, users, and applications are affected
- **Data Integrity**: While no data is corrupted, the chain becomes completely unresponsive
- **Recovery Difficulty**: Requires either chain restart or emergency contract upgrade

The impact is complete availability loss of the consensus mechanism, which is a critical system component. Unlike fund theft or privilege escalation, this is a complete denial-of-service that affects every participant in the network.

## Likelihood Explanation

**Likelihood: Medium-High**

**Reachability:** Direct - `NextRound()` is a public method that is part of the standard consensus flow and called regularly by validators.

**Preconditions:** 
- A new round exists where at least one miner has a null signature
- Most vulnerable: first round of any term (generated via `GenerateFirstRoundOfNewTerm()`)
- Also affects: any round generated via `GenerateNextRoundInformation()`

**Trigger Practicality:**
- Missed time slots are a normal occurrence in consensus systems due to:
  - Network latency or partitions
  - Node crashes or restarts
  - Hardware failures
  - Intentional griefing (miner simply doesn't produce block)
- No special privileges required
- First round of each term is vulnerable (recurring vulnerability)

**Economic Feasibility:**
- Zero cost to attacker - simply don't mine when scheduled
- Can be triggered passively through normal network issues
- Can be triggered actively by malicious miner

The combination of easy trigger conditions, recurring vulnerability windows, and normal network behavior makes this highly likely to occur in production.

## Recommendation

Add null checks before accessing the `Signature` field in signature aggregation logic:

**Option 1: Guard in XorAndCompute**
```csharp
public static Hash XorAndCompute(Hash h1, Hash h2)
{
    if (h1 == null || h2 == null)
        return h1 ?? h2 ?? Hash.Empty;
        
    var newBytes = new byte[AElfConstants.HashByteArrayLength];
    for (var i = 0; i < newBytes.Length; i++) 
        newBytes[i] = (byte)(h1.Value[i] ^ h2.Value[i]);
    return ComputeFrom(newBytes);
}
```

**Option 2: Guard in CalculateSignature**
```csharp
public Hash CalculateSignature(Hash inValue)
{
    var signature = RealTimeMinersInformation.Values
        .Where(m => m.Signature != null)
        .Aggregate(Hash.Empty, (current, minerInRound) => 
            HashHelper.XorAndCompute(current, minerInRound.Signature));
    return HashHelper.XorAndCompute(inValue, signature);
}
```

**Option 3: Initialize signatures in round generation**
```csharp
// In GenerateNextRoundInformation and GenerateFirstRoundOfNewTerm
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minerInRound.Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots,
    Signature = Hash.Empty  // Initialize to prevent null
};
```

**Recommended Solution:** Implement both Option 1 (defensive coding in XorAndCompute) and Option 3 (proper initialization) to ensure defense-in-depth.

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_CrashesWhenPreviousRoundHasNullSignature()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(3);
    var firstRound = GenerateFirstRoundOfNewTerm(miners, miningInterval: 4000, 
        Context.CurrentBlockTime);
    await InitialAElfConsensusContract(firstRound);
    
    // Round 1: Only first miner produces block (others have null signatures)
    var firstMiner = miners[0];
    await UpdateValue(new UpdateValueInput 
    {
        OutValue = Hash.Generate(),
        Signature = ComputeSignature(Hash.Generate()),  // Only first miner has signature
        // Other fields...
    }, firstMiner);
    
    // Miners 2 and 3 miss their slots - signatures remain null
    
    // Attempt to transition to Round 2
    var nextRoundInput = GenerateNextRoundInput(firstRound);
    
    // This should crash with NullReferenceException in SupplyCurrentRoundInformation
    // when it calls previousRound.CalculateSignature() with miners that have null signatures
    var exception = await Assert.ThrowsAsync<NullReferenceException>(
        async () => await NextRound(nextRoundInput)
    );
    
    // Verify: Consensus is stuck, cannot progress to next round
    var currentRound = await GetCurrentRoundInformation();
    Assert.Equal(1, currentRound.RoundNumber);  // Still on round 1
}
```

## Notes

This vulnerability demonstrates a critical failure in defensive programming where the contract assumes all miners will always have signatures set. The protobuf schema allows null values for the `Signature` field, but the aggregation logic has no null handling. This is particularly dangerous because:

1. **First-round vulnerability**: Every new term starts with all signatures null
2. **Cascading failure**: One missed slot can prevent all future round transitions
3. **Normal conditions**: Missed slots are expected behavior in distributed consensus
4. **No recovery path**: Once triggered, the chain is stuck without manual intervention

The fix requires either ensuring signatures are always initialized (defensive initialization) or handling null values in aggregation (defensive computation), preferably both.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-199)
```csharp
    private void SupplyCurrentRoundInformation()
    {
        var currentRound = GetCurrentRoundInformation(new Empty());
        Context.LogDebug(() => $"Before supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
        var notMinedMiners = currentRound.RealTimeMinersInformation.Values.Where(m => m.OutValue == null).ToList();
        if (!notMinedMiners.Any()) return;
        TryToGetPreviousRoundInformation(out var previousRound);
        foreach (var miner in notMinedMiners)
        {
            Context.LogDebug(() => $"Miner pubkey {miner.Pubkey}");

            Hash previousInValue = null;
            Hash signature = null;

            // Normal situation: previous round information exists and contains this miner.
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L66-72)
```csharp
        public static Hash XorAndCompute(Hash h1, Hash h2)
        {
            var newBytes = new byte[AElfConstants.HashByteArrayLength];
            for (var i = 0; i < newBytes.Length; i++) newBytes[i] = (byte)(h1.Value[i] ^ h2.Value[i]);

            return ComputeFrom(newBytes);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L25-36)
```csharp
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-244)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
```

**File:** protobuf/aedpos_contract.proto (L275-276)
```text
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
```
