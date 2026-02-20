# Audit Report

## Title
Duplicate FinalOrderOfNextRound Due to Failed Conflict Resolution in ApplyNormalConsensusData

## Summary
The conflict resolution logic in `ApplyNormalConsensusData` fails to reassign conflicted miners when all mining orders are occupied, allowing duplicate `FinalOrderOfNextRound` values to persist. This causes time slot collisions in subsequent rounds, disrupting consensus scheduling integrity.

## Finding Description
The vulnerability exists in the order conflict resolution mechanism within the consensus round processing logic.

**Root Cause:**

When a miner produces a block, `ApplyNormalConsensusData` calculates a `supposedOrderOfNextRound` based on the block signature. [1](#0-0) 

If this order conflicts with another miner's existing `FinalOrderOfNextRound`, the system detects conflicts and attempts reassignment. [2](#0-1) 

However, the conflict resolution loop fails when all orders [1, minersCount] are occupied. [3](#0-2)  The loop iterates through candidate orders but never finds an available slot when all miners are active. It exits without reassigning the conflicted miner, leaving their `FinalOrderOfNextRound` unchanged.

Subsequently, the current miner is unconditionally assigned the conflicting order. [4](#0-3) 

**Exploitation Path:**
1. All miners have claimed orders [1, 2, 3, 4, 5] via their `FinalOrderOfNextRound` values
2. Miner M1 (currently has order 1) produces another block within the same round (TinyBlock production is legitimate [5](#0-4) )
3. `ApplyNormalConsensusData` is invoked [6](#0-5) 
4. The signature calculation yields `supposedOrderOfNextRound = 2`, conflicting with Miner M2
5. Conflict detection adds M2 to the conflicts list
6. The reassignment loop checks orders but all are occupied (M1 still holds order 1 at this point), exits without reassignment
7. M2 retains `FinalOrderOfNextRound = 2`
8. M1 is assigned `FinalOrderOfNextRound = 2`
9. **Result: Both M1 and M2 have `FinalOrderOfNextRound = 2`**

**Why Existing Protections Fail:**

The `NextRoundMiningOrderValidationProvider` validates using `.Distinct()` on `MinerInRound` objects. [7](#0-6) 

Since `MinerInRound` is a protobuf message type with multiple fields including `pubkey` [8](#0-7) , the equality comparison checks all fields. Two miners with different pubkeys but identical `FinalOrderOfNextRound` values are considered distinct objects, allowing the duplicate to pass validation.

## Impact Explanation

**Consensus Integrity Violation:**

When `GenerateNextRoundInformation` processes the round, miners with duplicate `FinalOrderOfNextRound` values are both assigned the same `Order` and `ExpectedMiningTime` in the next round. [9](#0-8) 

This causes:

1. **Time Slot Collision**: Two miners produce blocks at identical timestamps, creating fork conditions
2. **Missing Time Slot**: One order becomes unfilled, incorrectly calculated as "available" [10](#0-9) 
3. **Non-Deterministic Behavior**: `BreakContinuousMining` logic using `.First()` becomes unpredictable when orders are missing or duplicated [11](#0-10) 
4. **Round Schedule Disruption**: The deterministic mining schedule is compromised

While no direct fund loss occurs, consensus schedule integrity is a critical protocol invariant. The disruption affects block production reliability and consensus predictability, which are fundamental to blockchain security.

## Likelihood Explanation

**Attacker Capabilities**: Any active miner can trigger this by producing multiple blocks within the same round.

**Preconditions:**
- All miners are active and have claimed orders [1, minersCount] - this is the **normal operational state**
- A miner produces a second block in the same round (TinyBlocks are a legitimate feature)
- The signature calculation produces a different `supposedOrderOfNextRound` value (probabilistic based on hash)

**Feasibility**: High - The condition of "all orders occupied" is the expected state when all miners are active and participating normally. Miners can legitimately produce multiple blocks per round (TinyBlocks). The signature varies based on `previousInValue`, which changes between blocks, making conflicts probabilistically likely (probability = (minersCount - 1) / minersCount per additional block, potentially 80%+ with 5 miners).

The validation is only triggered for `NextRound` behavior [12](#0-11) , meaning duplicates can be created during TinyBlock processing without immediate detection.

## Recommendation

Modify the conflict resolution logic to ensure proper reassignment:

1. **Option 1**: Check for available orders AFTER updating the current miner's order, making the vacated slot available for reassignment.

2. **Option 2**: Add explicit validation that prevents the unconditional assignment at line 44 if conflict resolution failed:
   - Track whether the loop successfully reassigned the conflicted miner
   - Only proceed with assignment if no unresolved conflicts remain

3. **Option 3**: Enhance the validation provider to check for duplicate `FinalOrderOfNextRound` values explicitly rather than relying on `.Distinct()` on the entire object:
   - Group miners by `FinalOrderOfNextRound`
   - Reject if any group has more than one miner

## Proof of Concept

```csharp
[Fact]
public void Test_DuplicateFinalOrderOfNextRound()
{
    // Setup: Round with 5 miners, all have claimed orders [1,2,3,4,5]
    var round = new Round { RoundNumber = 1, TermNumber = 1 };
    for (int i = 1; i <= 5; i++)
    {
        var pubkey = $"miner{i}";
        round.RealTimeMinersInformation[pubkey] = new MinerInRound
        {
            Pubkey = pubkey,
            FinalOrderOfNextRound = i,
            SupposedOrderOfNextRound = i,
            OutValue = Hash.FromString("out" + i)
        };
    }
    
    // M1 produces second block with signature yielding order 2
    var miner1Pubkey = "miner1";
    var signatureYieldingOrder2 = Hash.FromString("signature_mod_to_2");
    
    // Apply consensus data (simulates TinyBlock production)
    var updatedRound = round.ApplyNormalConsensusData(
        miner1Pubkey,
        Hash.FromString("prev"),
        Hash.FromString("new_out"),
        signatureYieldingOrder2
    );
    
    // Verify: Both miner1 and miner2 now have FinalOrderOfNextRound = 2
    Assert.Equal(2, updatedRound.RealTimeMinersInformation["miner1"].FinalOrderOfNextRound);
    Assert.Equal(2, updatedRound.RealTimeMinersInformation["miner2"].FinalOrderOfNextRound);
    
    // Generate next round and verify time slot collision
    updatedRound.GenerateNextRoundInformation(
        Timestamp.FromDateTime(DateTime.UtcNow),
        Timestamp.FromDateTime(DateTime.UtcNow.AddDays(-1)),
        out var nextRound
    );
    
    // Both miners assigned same Order and ExpectedMiningTime
    var m1NextOrder = nextRound.RealTimeMinersInformation["miner1"].Order;
    var m2NextOrder = nextRound.RealTimeMinersInformation["miner2"].Order;
    var m1NextTime = nextRound.RealTimeMinersInformation["miner1"].ExpectedMiningTime;
    var m2NextTime = nextRound.RealTimeMinersInformation["miner2"].ExpectedMiningTime;
    
    Assert.Equal(m1NextOrder, m2NextOrder); // Duplicate order
    Assert.Equal(m1NextTime, m2NextTime); // Same mining time - collision!
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-26)
```csharp
        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L31-40)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** protobuf/aedpos_contract.proto (L266-301)
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
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-79)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-86)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```
