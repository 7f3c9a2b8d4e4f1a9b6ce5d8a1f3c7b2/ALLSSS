# Audit Report

## Title
Non-Deterministic Extra Block Producer Selection in Consensus Fallback Path

## Summary
The `GenerateNextRoundInformation` method contains a non-deterministic fallback that uses `.First()` without ordering on a protobuf `MapField` collection. If this fallback executes, different validator nodes will select different miners as the extra block producer, creating divergent consensus state and causing an immediate network fork.

## Finding Description

The vulnerability exists in the consensus contract's round generation logic. The `RealTimeMinersInformation` field is defined as a protobuf `map<string, MinerInRound>` [1](#0-0) , which generates as `Google.Protobuf.Collections.MapField<TKey, TValue>` in C#. This collection type does NOT guarantee deterministic iteration order.

**The Vulnerable Code:**

When calculating the extra block producer for the next round, the code attempts to find a miner with a specific order. If no match is found (`expectedExtraBlockProducer == null`), it falls back to selecting the first miner from an unordered collection [2](#0-1) .

This `.First()` call without `OrderBy` operates on an unordered `MapField`, meaning different nodes may iterate the collection in different orders and select different miners.

**Why Existing Protections Fail:**

The codebase demonstrates awareness of determinism requirements. The same file correctly uses `.OrderBy()` before iteration in other locations [3](#0-2)  and [4](#0-3) .

Additionally, `BlockExecutingService` uses `SortedSet` to ensure deterministic state hashing [5](#0-4) . However, this sorting occurs AFTER contract execution completes. If the contract execution itself is non-deterministic (different nodes create different state changes), sorting afterward cannot fix the divergence.

**Execution Context:**

This method is invoked from consensus-critical paths during next round generation [6](#0-5)  and [7](#0-6) .

## Impact Explanation

**Severity: CRITICAL**

If the fallback executes:
1. Node A iterates `MapField` in order [Miner1, Miner2, Miner3] → selects Miner1
2. Node B iterates `MapField` in order [Miner3, Miner1, Miner2] → selects Miner3
3. Different nodes create different `Round` objects with different `IsExtraBlockProducer` flags
4. Different `Round` objects cause different state changes during block execution
5. Different state changes produce different `MerkleTreeRootOfWorldState` values
6. Different merkle roots result in different block hashes
7. **Consensus fork occurs** - the network splits as nodes reject each other's blocks

**Affected Parties:**
- All validator nodes in the network
- Block finality is lost
- Transaction settlement becomes unreliable
- Network availability degraded until manual intervention

This breaks the fundamental consensus invariant that all honest nodes must agree on the canonical blockchain state.

## Likelihood Explanation

**Normal Operation:** The fallback executes when `expectedExtraBlockProducer == null`, meaning no miner has the order calculated by `CalculateNextExtraBlockProducerOrder()` [8](#0-7) . 

The order calculation returns a value in [1, blockProducerCount], and the order assignment logic [9](#0-8)  is designed to assign all orders from 1 to minersCount, so theoretically the null case shouldn't occur.

**Risk Factors:**

1. **Complex Conflict Resolution:** The order assignment involves conflict resolution logic [10](#0-9)  that could fail to assign valid orders under edge cases

2. **Miner Replacement:** During miner replacement operations [11](#0-10) , the miner map is modified, potentially creating temporary inconsistencies

3. **Latent Bug:** Even if rarely triggered, the presence of non-deterministic code in consensus-critical paths represents a ticking time bomb. Any future bug, race condition, or code modification that causes the fallback to execute would result in immediate network fork.

**Detection:** Once triggered, the consensus fork is automatic and immediately detectable through divergent block hashes across nodes.

## Recommendation

Replace the non-deterministic `.First()` call with a deterministic selection:

```csharp
if (expectedExtraBlockProducer == null)
{
    // Use deterministic ordering to select fallback extra block producer
    var fallbackProducer = nextRound.RealTimeMinersInformation.Values
        .OrderBy(m => m.Pubkey)  // Deterministic ordering by public key
        .First();
    fallbackProducer.IsExtraBlockProducer = true;
}
```

Alternatively, add validation to ensure this fallback never executes:

```csharp
if (expectedExtraBlockProducer == null)
{
    // This should never happen - indicates a bug in order assignment
    throw new AssertionException(
        $"No miner found with order {extraBlockProducerOrder} in next round");
}
```

The second approach is preferable as it makes the invariant explicit and prevents silent failures.

## Proof of Concept

A proof of concept would require:

1. Setting up multiple AElf validator nodes
2. Creating a scenario where the order assignment logic leaves a gap (e.g., through miner replacement during round transition)
3. Triggering next round generation
4. Observing that nodes produce different block hashes due to selecting different extra block producers

While demonstrating this in production may be difficult, the vulnerability is evident from code inspection:
- The protobuf map is unordered (confirmed in protobuf definition)
- `.First()` without `OrderBy` is non-deterministic (confirmed in vulnerable code)
- The codebase uses `OrderBy` elsewhere, showing awareness of this requirement (confirmed in same file)
- Post-execution sorting cannot fix non-deterministic execution (confirmed in BlockExecutingService)

**Notes**

This is a **latent vulnerability** - a determinism bug that may not trigger frequently but has catastrophic consequences when it does. The code pattern violates determinism principles that the rest of the AElf consensus implementation correctly follows. The presence of this fallback path, even if rarely reached, represents an unacceptable risk to network stability.

The vulnerability demonstrates incomplete defensive programming in consensus-critical code, where ALL code paths must be deterministic, not just the common paths.

### Citations

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-56)
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

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L62-63)
```csharp
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockExecutingService.cs (L168-168)
```csharp
        foreach (var k in new SortedSet<string>(keys))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L176-176)
```csharp
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-342)
```csharp
            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L345-346)
```csharp
        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-40)
```csharp
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }
```
