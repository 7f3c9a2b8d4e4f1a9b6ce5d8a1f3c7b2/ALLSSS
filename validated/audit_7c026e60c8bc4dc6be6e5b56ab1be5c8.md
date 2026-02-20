# Audit Report

## Title
Time Slot Collision via Failed Order Conflict Resolution and Flawed Validation

## Summary
The AEDPoS consensus mechanism contains a critical vulnerability where miners can receive duplicate `Order` values due to failed conflict resolution in `ApplyNormalConsensusData` when no available orders exist for reassignment, combined with a flawed validation check in `NextRoundMiningOrderValidationProvider` that calls `.Distinct()` on object references instead of `FinalOrderOfNextRound` values. When duplicate orders propagate to the next round, affected miners receive identical timestamps, causing block production conflicts that can disrupt consensus.

## Finding Description

### Root Cause 1: Failed Conflict Resolution

When a miner produces a block, the `ApplyNormalConsensusData` method calculates their `supposedOrderOfNextRound` based on their signature hash and checks for conflicts with existing miners' `FinalOrderOfNextRound` values. [1](#0-0) 

If conflicts exist, the code attempts to reassign conflicting miners to available orders through an inner loop: [2](#0-1) 

**Critical Flaw**: The inner for loop has no error handling if it completes without finding an available order (no `break` statement executed). When all non-conflicting orders are occupied, the loop exits silently, leaving the conflicting miner's `FinalOrderOfNextRound` at the duplicate value. The current miner then also sets their `FinalOrderOfNextRound` to the same value: [3](#0-2) 

This results in multiple miners having identical `FinalOrderOfNextRound` values.

### Root Cause 2: Flawed Validation

The `NextRoundMiningOrderValidationProvider` is intended to validate that miners have unique `FinalOrderOfNextRound` values. However, it contains a critical bug where it calls `.Distinct()` on `MinerInRound` objects: [4](#0-3) 

Since `MinerInRound` is a protobuf-generated message: [5](#0-4) 

It does not override `Equals()` or `GetHashCode()`, meaning `.Distinct()` uses reference equality. Each `MinerInRound` object is distinct by reference, so this validation passes even when multiple miners have identical `FinalOrderOfNextRound` integer values. The correct implementation would require `.Select(m => m.FinalOrderOfNextRound).Distinct()`.

### Propagation to Next Round

During next round generation, miners who mined in the current round have their `FinalOrderOfNextRound` directly copied to become their `Order` in the next round: [6](#0-5) 

This means duplicate `FinalOrderOfNextRound` values from the current round become duplicate `Order` values in the next round.

### Time Slot Collision

When miners need their mining timestamps calculated, the `ExpectedMiningTime` is computed using their `Order`: [7](#0-6) 

Similarly, when arranging abnormal mining time: [8](#0-7) 

Since `futureRoundStartTime` and `miningInterval` are the same for all miners in a round, miners with identical `Order` values receive identical `ExpectedMiningTime` timestamps, causing them to attempt block production at the exact same time.

### Inadequate Existing Protection

The `CheckRoundTimeSlots()` method validates round time slots but has a limitation: [9](#0-8) 

It orders miners by `Order` and checks intervals. While it catches zero intervals at the first position (`baseMiningInterval <= 0`), the subsequent check `Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval` when `miningInterval=0` evaluates to `baseMiningInterval > baseMiningInterval` which is false, failing to detect duplicate orders at other positions.

## Impact Explanation

**Consensus Integrity Violation**: This vulnerability breaks the fundamental AEDPoS invariant that each miner must have a unique, sequential time slot for block production. When multiple miners receive identical timestamps:

1. **Block Production Conflicts**: Miners attempt to produce blocks simultaneously, leading to competing valid blocks and potential network forks
2. **Chain Reorganizations**: The network experiences increased orphan blocks as conflicting blocks are resolved
3. **Consensus Stalls**: If the network cannot determine block order due to timestamp ambiguity, consensus can stall
4. **Cascading Failures**: Once duplicates exist, they persist through validation and propagate to subsequent rounds, with each round having a higher probability of conflict resolution failures as order space becomes saturated

**Network-Wide Impact**: This affects core consensus operations, not isolated to individual miners. All network participants experience disruption when timestamp collisions occur.

**Severity Justification**: Critical - directly undermines the consensus mechanism's time slot allocation, causing operational disruption and potential network-wide consensus failures.

## Likelihood Explanation

**Triggering Conditions**:
1. All miners produce blocks in a round (expected in healthy network operation)
2. A signature hash collision produces the same `supposedOrderOfNextRound % minersCount` (probability ≈ 1/minersCount per collision pair)
3. All non-conflicting orders are occupied when conflict resolution executes

**Feasibility**: The vulnerability can manifest through:
- **Natural Occurrence**: Hash collisions in high-participation rounds where all miners produce blocks before conflict resolution completes
- **Network Timing**: Out-of-order block processing due to network delays can create scenarios where order space is fully occupied during collision
- **Stealth Factor**: The flawed `.Distinct()` validation guarantees duplicates will not be detected, making this issue persistent once triggered

**Attack Complexity**: Medium. While specific conditions are required, the lack of protective checks and the broken validation mean this can occur through both natural hash collisions and edge cases in production networks with typical miner counts (5-21 miners).

**Probability Assessment**: Medium-High likelihood. The validation bug ensures that once duplicates occur (through either natural collisions or edge cases), they persist and propagate, creating cascading failures.

## Recommendation

**Fix 1: Add Error Handling to Conflict Resolution**

In `Round_ApplyNormalConsensusData.cs`, track whether conflict resolution succeeded and handle failure cases:

```csharp
foreach (var orderConflictedMiner in conflicts)
{
    var resolved = false;
    for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
    {
        var maybeNewOrder = i > minersCount ? i % minersCount : i;
        if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
        {
            RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
            resolved = true;
            break;
        }
    }
    
    if (!resolved)
    {
        // Handle failure: either reject the block or implement fallback logic
        throw new InvalidOperationException($"Unable to resolve order conflict for miner {orderConflictedMiner.Pubkey}");
    }
}
```

**Fix 2: Correct the Validation Logic**

In `NextRoundMiningOrderValidationProvider.cs`, fix the `.Distinct()` call to operate on `FinalOrderOfNextRound` values:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Add this line
    .Distinct()
    .Count();
```

**Fix 3: Strengthen CheckRoundTimeSlots**

In `Round.cs`, explicitly check for zero mining intervals at all positions:

```csharp
for (var i = 1; i < miners.Count - 1; i++)
{
    var miningInterval = (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
    
    if (miningInterval <= 0)
        return new ValidationResult { Message = $"Mining interval must be greater than 0 at position {i}.\n{this}" };
        
    if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
        return new ValidationResult { Message = "Time slots are so different." };
}
```

## Proof of Concept

Due to the complexity of setting up a full consensus test environment with multiple miners, hash collisions, and round state management, a complete PoC would require extensive test infrastructure. However, the vulnerability can be demonstrated through the following test scenario:

1. Initialize a round with 5 miners, all having produced blocks (FinalOrderOfNextRound values 1-5 assigned)
2. Simulate miner A producing a block with a signature hash that maps to order 3 (already occupied by miner B)
3. Before conflict resolution, have miners C, D, E produce blocks filling orders 4, 5, 1, 2
4. When miner A's `ApplyNormalConsensusData` runs, the conflict resolution loop searches for available orders but finds none
5. Both miner A and miner B end up with `FinalOrderOfNextRound = 3`
6. The `NextRoundMiningOrderValidationProvider` validation passes due to the `.Distinct()` bug
7. In the next round generation, both miners receive `Order = 3` and identical `ExpectedMiningTime` values
8. Both miners attempt to produce blocks at the same timestamp, causing a consensus conflict

The key test would verify that after step 5, multiple miners have identical `FinalOrderOfNextRound` values, and this state passes validation but results in timestamp collisions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-26)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** protobuf/aedpos_contract.proto (L280-301)
```text
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L36-36)
```csharp
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-54)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
```
