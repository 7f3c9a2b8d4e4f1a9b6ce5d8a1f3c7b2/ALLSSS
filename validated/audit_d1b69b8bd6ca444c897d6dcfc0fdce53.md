# Audit Report

## Title
Null Signature Handling Causes Consensus DoS in CalculateSignature()

## Summary
The AEDPoS consensus contract contains a critical null reference vulnerability where `CalculateSignature()` aggregates miner signatures without null checks. When miners miss their time slots in any round starting from round 2, their signatures remain uninitialized (null), causing `NextRound()` to crash with a `NullReferenceException` and halting consensus completely.

## Finding Description

The vulnerability exists in a multi-layer call chain starting from consensus round transitions:

**Entry Point:** The public `NextRound()` method is called to transition between consensus rounds. [1](#0-0) 

**Supply Logic:** `SupplyCurrentRoundInformation()` attempts to fill missing information for miners who didn't mine. For miners without `OutValue` (indicating they didn't mine), it retrieves the previous round and calculates their signature. [2](#0-1) 

The critical call occurs where the signature is calculated from the previous round: [3](#0-2) 

**Signature Aggregation:** The `CalculateSignature()` method aggregates all miner signatures from the round using XOR operations, iterating over ALL miners without filtering for null signatures. [4](#0-3) 

**Vulnerable Helper:** The `HashHelper.XorAndCompute()` method directly accesses `h2.Value[i]` without checking if `h2` is null. [5](#0-4) 

**Root Cause:** When new rounds are generated, the `Signature` field is never initialized. In `GenerateNextRoundInformation()`, only specific fields are set for each miner, excluding `Signature`: [6](#0-5) [7](#0-6) 

Similarly, in `GenerateFirstRoundOfNewTerm()`, the `Signature` field is not initialized: [8](#0-7) 

The `Signature` field is only set when a miner successfully produces a block via `ProcessUpdateValue()`: [9](#0-8) 

The protobuf definition confirms `Signature` is an optional field that defaults to null: [10](#0-9) 

**Attack Scenario:**
1. Round 1 is active with miners A, B, C
2. Miner A produces a block → signature is set via `ProcessUpdateValue()`
3. Miner B misses their time slot → signature remains null
4. Round 2 is generated via `GenerateNextRoundInformation()` with all signatures null initially
5. Miner C produces a block in round 2, Miner D misses
6. A validator calls `NextRound()` to transition to round 3
7. `SupplyCurrentRoundInformation()` processes Miner D (who didn't mine in round 2)
8. It calls `previousRound.CalculateSignature()` where previousRound = round 1
9. `CalculateSignature()` iterates over all miners in round 1, including Miner B with null signature
10. `HashHelper.XorAndCompute()` crashes with `NullReferenceException` when accessing `null.Value[i]`
11. Transaction fails, consensus cannot progress beyond round 2

## Impact Explanation

**Severity: High**

This vulnerability causes complete consensus denial-of-service with network-wide impact:

- **Consensus Halt**: Once triggered, `NextRound()` cannot execute successfully, preventing new rounds from being created
- **Block Production Stoppage**: No new blocks can be produced as the round transition mechanism is broken
- **Network-Wide Impact**: All validators, users, and applications are affected
- **Irrecoverable State**: The chain remains stuck until manual intervention (emergency contract upgrade or chain restart)
- **Recurring Vulnerability**: Affects every round transition starting from round 2

The impact is a complete availability loss of the consensus mechanism, which is the most critical system component in a blockchain. While no funds are stolen or data corrupted, the entire network becomes non-functional.

## Likelihood Explanation

**Likelihood: High**

**Reachability:** Direct - `NextRound()` is a public RPC method that is part of the standard consensus flow and called regularly by validators during normal operation.

**Preconditions:** 
- Current round ≥ 2 (the first round is protected by early return in `TryToGetPreviousRoundInformation`) [11](#0-10) 
- At least one miner in any previous round has a null signature (did not mine)

**Trigger Practicality:**
- Missed time slots are a normal occurrence in consensus systems due to:
  - Network latency or temporary partitions
  - Node crashes or restarts
  - Hardware failures
  - Intentional non-participation by malicious miner
- No special privileges required beyond being a scheduled miner
- Zero cost to trigger - simply don't mine when scheduled
- Can occur passively through normal network issues

**Economic Feasibility:**
- No attack cost - omission is free
- Can be triggered by any miner in the validator set
- Persistent vulnerability across all rounds

The combination of trivial trigger conditions, normal network behavior causing missed slots, and recurring vulnerability windows makes this highly likely to occur in production environments.

## Recommendation

Add null checks before aggregating signatures in `CalculateSignature()`. Filter out miners with null signatures:

```csharp
public Hash CalculateSignature(Hash inValue)
{
    return HashHelper.XorAndCompute(inValue,
        RealTimeMinersInformation.Values
            .Where(minerInRound => minerInRound.Signature != null) // Add null check
            .Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
}
```

Alternatively, initialize signatures to a default non-null value (e.g., `Hash.Empty`) in `GenerateNextRoundInformation()` and `GenerateFirstRoundOfNewTerm()` to ensure they are never null.

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_WithNullSignature_CausesConsensusDoS()
{
    // Setup: Initialize consensus with 3 miners
    var miners = GenerateMinerList(3);
    await InitializeConsensus(miners);
    
    // Round 1: Only first miner produces block
    // Other miners' signatures remain null
    await MineBlock(miners[0]); 
    
    // Round 2: Generate next round (all signatures start as null)
    var round2Input = BuildNextRoundInput();
    await NextRound(round2Input);
    
    // Round 2: Only first miner produces block again
    await MineBlock(miners[0]);
    
    // Round 3: Attempt to transition - this should crash
    // SupplyCurrentRoundInformation will try to calculate signature from Round 1
    // Round 1 has miners with null signatures
    // This will throw NullReferenceException in HashHelper.XorAndCompute
    var round3Input = BuildNextRoundInput();
    
    // Assert: NextRound crashes with NullReferenceException
    await Assert.ThrowsAsync<NullReferenceException>(async () => 
        await NextRound(round3Input)
    );
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-221)
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
                }
            }

            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
            }

            // Fill this two fields at last.
            miner.InValue = previousInValue;
            miner.Signature = signature;

            currentRound.RealTimeMinersInformation[miner.Pubkey] = miner;
        }

        TryToUpdateRoundInformation(currentRound);
        Context.LogDebug(() => $"After supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-56)
```csharp
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L23-38)
```csharp
        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** protobuf/aedpos_contract.proto (L266-276)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L56-64)
```csharp
    private bool TryToGetPreviousRoundInformation(out Round previousRound)
    {
        previousRound = new Round();
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        if (roundNumber < 2) return false;
        var targetRoundNumber = roundNumber.Sub(1);
        previousRound = State.Rounds[targetRoundNumber];
        return !previousRound.IsEmpty;
    }
```
