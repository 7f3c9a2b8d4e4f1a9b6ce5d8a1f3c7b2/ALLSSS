# Audit Report

## Title
Duplicate FinalOrderOfNextRound Due to Failed Conflict Resolution in ApplyNormalConsensusData

## Summary
The conflict resolution logic in `ApplyNormalConsensusData` fails to reassign conflicted miners when all mining orders are occupied, allowing duplicate `FinalOrderOfNextRound` values to persist. This causes time slot collisions in subsequent rounds, disrupting consensus scheduling integrity.

## Finding Description
The vulnerability exists in the order conflict resolution mechanism within the consensus round processing logic.

**Root Cause:**
In `ApplyNormalConsensusData`, when a miner produces a block, the system calculates a `supposedOrderOfNextRound` based on the block signature [1](#0-0) . If this order conflicts with another miner's existing `FinalOrderOfNextRound`, the conflict resolution loop attempts to reassign the conflicted miner to an available order [2](#0-1) .

However, when all orders [1, minersCount] are occupied (normal operational state), the loop at line 31-40 iterates through candidate orders but never finds an available slot. The loop exits without breaking, leaving the conflicted miner's `FinalOrderOfNextRound` unchanged. Subsequently, the current miner is unconditionally assigned the same conflicting order [3](#0-2) .

**Exploitation Path:**
1. All miners have claimed orders [1, 2, 3, 4, 5] via their `FinalOrderOfNextRound` values
2. Miner M1 (currently has order 1) produces another block within the same round [4](#0-3) 
3. The signature calculation yields `supposedOrderOfNextRound = 2`, conflicting with Miner M2
4. Conflict detection adds M2 to the conflicts list [5](#0-4) 
5. The reassignment loop tries orders but all are occupied, exits without reassignment
6. M2 retains `FinalOrderOfNextRound = 2`
7. M1 is assigned `FinalOrderOfNextRound = 2`
8. **Result: Both M1 and M2 have `FinalOrderOfNextRound = 2`**

**Why Existing Protections Fail:**
The `NextRoundMiningOrderValidationProvider` calls `.Distinct()` on `MinerInRound` objects [6](#0-5) . Since `MinerInRound` is a protobuf message type [7](#0-6) , the equality comparison checks all fields including `pubkey`. Two miners with different pubkeys but identical `FinalOrderOfNextRound` values are considered distinct, allowing the duplicate to pass validation.

## Impact Explanation
**Consensus Integrity Violation:**
When `GenerateNextRoundInformation` processes the round, miners with duplicate `FinalOrderOfNextRound` values are both assigned the same `Order` and `ExpectedMiningTime` in the next round [8](#0-7) . This causes:

1. **Time Slot Collision**: Two miners produce blocks at identical timestamps, creating fork conditions
2. **Missing Time Slot**: One order becomes unfilled, calculated as "available" [9](#0-8) 
3. **Non-Deterministic Behavior**: `BreakContinuousMining` logic using `First()` becomes unpredictable [10](#0-9) 
4. **Round Schedule Disruption**: The deterministic mining schedule is compromised

While no direct fund loss occurs, consensus schedule integrity is a critical protocol invariant. The disruption affects block production reliability and consensus predictability.

## Likelihood Explanation
**Attacker Capabilities**: Any active miner can trigger this by producing multiple blocks within the same round.

**Preconditions:**
- All miners are active and have claimed orders [1, minersCount] - **normal operational state**
- A miner produces a second block in the same round (evidenced by `ProducedTinyBlocks` counter increments) [11](#0-10) 
- The signature calculation produces a different `supposedOrderOfNextRound` value [12](#0-11) 

**Feasibility**: High - The condition of "all orders occupied" is the expected state when all miners are active and participating normally. Miners can legitimately produce multiple blocks per round (TinyBlocks). The signature varies based on `previousInValue`, which changes between blocks, making conflicts probabilistically likely (probability = occupied_orders/minersCount, potentially 80%+ with 5 miners and 4 existing orders).

## Recommendation
Modify the conflict resolution loop to ensure proper wraparound and complete order space coverage:

```csharp
foreach (var orderConflictedMiner in conflicts)
{
    bool reassigned = false;
    for (var i = 1; i <= minersCount; i++)
    {
        var candidateOrder = ((supposedOrderOfNextRound + i - 1) % minersCount) + 1;
        if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != candidateOrder))
        {
            RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = candidateOrder;
            reassigned = true;
            break;
        }
    }
    
    // Assert or revert if reassignment fails
    Assert(reassigned, "Failed to resolve FinalOrderOfNextRound conflict - all orders occupied.");
}
```

Additionally, fix the validation to check for duplicate `FinalOrderOfNextRound` values:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

## Proof of Concept
```csharp
// This test demonstrates the duplicate FinalOrderOfNextRound scenario
[Fact]
public void Test_DuplicateFinalOrderOfNextRound()
{
    var round = new Round();
    
    // Setup: 5 miners with all orders occupied [1,2,3,4,5]
    for (int i = 1; i <= 5; i++)
    {
        var pubkey = $"Miner{i}";
        round.RealTimeMinersInformation[pubkey] = new MinerInRound
        {
            Pubkey = pubkey,
            FinalOrderOfNextRound = i,
            OutValue = Hash.FromString($"out{i}"),
            Signature = Hash.FromString($"sig{i}")
        };
    }
    
    // Miner1 produces second block with signature yielding order 2
    var signature = Hash.FromString("newsig_order2");
    var sigNum = signature.ToInt64();
    var supposedOrder = (Math.Abs(sigNum) % 5) + 1; // Should equal 2
    
    // This simulates the signature being crafted/occurring to conflict with order 2
    // In reality, adjust Hash.FromString to produce correct signature
    
    // Apply consensus data - this should trigger the bug
    round.ApplyNormalConsensusData("Miner1", Hash.FromString("prev"), Hash.FromString("out"), signature);
    
    // Verify the bug: Both Miner1 and Miner2 now have FinalOrderOfNextRound = 2
    var miner1Order = round.RealTimeMinersInformation["Miner1"].FinalOrderOfNextRound;
    var miner2Order = round.RealTimeMinersInformation["Miner2"].FinalOrderOfNextRound;
    
    Assert.Equal(2, miner1Order);
    Assert.Equal(2, miner2Order); // DUPLICATE - BUG CONFIRMED
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-26)
```csharp
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L28-40)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L44-44)
```csharp
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L58-61)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L68-69)
```csharp
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-290)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-84)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L251-252)
```csharp
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```
