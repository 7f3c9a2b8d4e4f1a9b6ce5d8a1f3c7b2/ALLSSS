# Audit Report

## Title
Time Slot Collision via Failed Order Conflict Resolution and Flawed Validation

## Summary
The AEDPoS consensus mechanism contains a critical vulnerability where miners can receive duplicate `Order` values due to (1) failed conflict resolution in `ApplyNormalConsensusData` when no available orders exist for reassignment, and (2) a flawed validation check in `NextRoundMiningOrderValidationProvider` that calls `.Distinct()` on object references instead of `FinalOrderOfNextRound` values. When duplicate orders propagate to the next round, affected miners receive identical timestamps, causing block production conflicts that can disrupt consensus.

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
- **State Manipulation**: No protection prevents a miner from updating consensus values multiple times if they can produce multiple blocks

**Stealth Factor**: The flawed `.Distinct()` validation guarantees duplicates will not be detected, making this issue persistent once triggered. Duplicates only manifest as operational issues during block production, not during validation.

**Attack Complexity**: Medium. While specific conditions are required, the lack of protective checks and the broken validation mean this can occur through both natural hash collisions and deliberate manipulation in production networks with typical miner counts (5-21 miners).

**Probability Assessment**: Medium-High likelihood. The validation bug ensures that once duplicates occur (through either natural collisions or edge cases), they persist and propagate, creating cascading failures.

## Recommendation

### Fix 1: Correct the Validation Logic

Change the validation to check `FinalOrderOfNextRound` values instead of object references:

```csharp
// In NextRoundMiningOrderValidationProvider.cs
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // ADD THIS LINE
    .Distinct()
    .Count();
```

### Fix 2: Add Error Handling to Conflict Resolution

Add explicit error handling when no available order is found:

```csharp
// In Round_ApplyNormalConsensusData.cs
foreach (var orderConflictedMiner in conflicts)
{
    bool reassigned = false;
    for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
    {
        var maybeNewOrder = i > minersCount ? i % minersCount : i;
        if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
        {
            RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
            reassigned = true;
            break;
        }
    }
    
    if (!reassigned)
    {
        // Handle failure case - could throw exception or use fallback logic
        throw new InvalidOperationException($"Failed to reassign order for conflicting miner {orderConflictedMiner.Pubkey}");
    }
}
```

### Fix 3: Strengthen Time Slot Validation

Enhance `CheckRoundTimeSlots()` to explicitly detect duplicate orders:

```csharp
// In Round.cs CheckRoundTimeSlots method
var orders = miners.Select(m => m.Order).ToList();
if (orders.Count != orders.Distinct().Count())
{
    return new ValidationResult { Message = "Duplicate mining orders detected." };
}
```

## Proof of Concept

```csharp
[Fact]
public void Test_DuplicateOrdersNotDetectedByValidation()
{
    // Setup: Create a round with 5 miners
    var round = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation =
        {
            ["miner1"] = new MinerInRound { Pubkey = "miner1", FinalOrderOfNextRound = 1, OutValue = Hash.FromString("out1") },
            ["miner2"] = new MinerInRound { Pubkey = "miner2", FinalOrderOfNextRound = 2, OutValue = Hash.FromString("out2") },
            ["miner3"] = new MinerInRound { Pubkey = "miner3", FinalOrderOfNextRound = 3, OutValue = Hash.FromString("out3") },
            ["miner4"] = new MinerInRound { Pubkey = "miner4", FinalOrderOfNextRound = 1, OutValue = Hash.FromString("out4") }, // DUPLICATE ORDER!
            ["miner5"] = new MinerInRound { Pubkey = "miner5", FinalOrderOfNextRound = 5, OutValue = Hash.FromString("out5") }
        }
    };

    // Execute: Run the flawed validation
    var validationContext = new ConsensusValidationContext
    {
        ProvidedRound = round
    };
    
    var validator = new NextRoundMiningOrderValidationProvider();
    var result = validator.ValidateHeaderInformation(validationContext);
    
    // Assert: Validation incorrectly passes despite duplicate orders
    Assert.True(result.Success); // BUG: This passes when it should fail!
    
    // Verify the duplicate exists
    var ordersWithDuplicate = round.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0)
        .Select(m => m.FinalOrderOfNextRound)
        .ToList();
    Assert.Equal(5, ordersWithDuplicate.Count);
    Assert.Equal(4, ordersWithDuplicate.Distinct().Count()); // 4 distinct values from 5 miners
}
```

**Notes:**
- The validation bug is definitive: `.Distinct()` on protobuf-generated objects without equality overrides uses reference equality
- The conflict resolution flaw is confirmed: no error handling when the inner loop fails to find an available order
- Duplicates propagate: `FinalOrderOfNextRound` → `Order` → `ExpectedMiningTime`
- Existing protections are insufficient: `CheckRoundTimeSlots()` doesn't catch all duplicate order scenarios
- Impact is consensus-breaking: identical timestamps violate the core time slot allocation invariant

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-26)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L36-36)
```csharp
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-57)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

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
        }

        return new ValidationResult { Success = true };
```
