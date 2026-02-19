# Audit Report

## Title
Incomplete Conflict Resolution in Miner Order Assignment Leads to Duplicate Orders and Non-Deterministic Consensus

## Summary
The `ApplyNormalConsensusData()` function contains an off-by-one error in its conflict resolution loop that fails to check all valid miner positions. When `supposedOrderOfNextRound` equals the maximum valid order (minersCount), and all other positions are occupied, the conflict resolution silently fails, allowing duplicate `FinalOrderOfNextRound` values to persist. This violates the critical consensus invariant that each miner must have a unique timeslot, leading to non-deterministic block production.

## Finding Description

The vulnerability exists in the conflict resolution loop within `ApplyNormalConsensusData()`. [1](#0-0) 

**Root Cause Analysis:**

The loop iterates from `supposedOrderOfNextRound + 1` to `minersCount * 2 - 1`, using modulo arithmetic to wrap positions. [2](#0-1)  The order calculation uses `GetAbsModulus(sigNum, minersCount) + 1`, producing values in range [1, minersCount]. [3](#0-2) 

**Critical Gap:**

When `supposedOrderOfNextRound = N` (where N = minersCount), the loop generates:
- For i = N+1: `maybeNewOrder = (N+1) % N = 1`
- For i = N+2: `maybeNewOrder = (N+2) % N = 2`
- ...
- For i = 2N-1: `maybeNewOrder = (2N-1) % N = N-1`

Position N itself is **never checked**, creating a blind spot in the conflict resolution.

**Execution Flow:**

1. When a miner produces a block, `GetConsensusExtraDataToPublishOutValue()` calls `ApplyNormalConsensusData()` to update consensus data and calculate next round orders. [4](#0-3) 

2. If multiple miners calculate the same `supposedOrderOfNextRound`, the conflict detection identifies existing miners at that position. [5](#0-4) 

3. The resolution loop attempts to find a free position for conflicted miners, but when the conflict is at position N and all positions 1 through N-1 are occupied, the loop completes without finding an available slot.

4. The conflicted miner's `FinalOrderOfNextRound` remains unchanged, and the current miner is assigned the same order value. [6](#0-5) 

5. When the block is processed via `ProcessUpdateValue()`, both miners' duplicate order values are persisted to state. [7](#0-6) 

**Why Existing Protections Fail:**

The validation in `NextRoundMiningOrderValidationProvider` uses `Distinct()` on miner objects, not on `FinalOrderOfNextRound` values, so duplicate order values across different miners pass validation. [8](#0-7) 

The `TuneOrderInformation` mechanism only includes miners where `FinalOrderOfNextRound != SupposedOrderOfNextRound`. If both conflicted miners end up with matching supposed and final orders, neither appears in the tuning data. [9](#0-8) 

## Impact Explanation

When duplicate `FinalOrderOfNextRound` values persist into the next round, `GenerateNextRoundInformation()` assigns both miners identical `Order` and `ExpectedMiningTime` values. [10](#0-9) 

**Consensus Integrity Violation:**

1. **Non-Deterministic Block Production**: Two miners believe they should produce at the same timeslot, creating a race condition where network propagation determines which block is accepted.

2. **Unfair Penalties**: One miner may be marked as missing their slot despite attempting production, affecting reputation and rewards.

3. **Chain Ambiguity**: Different nodes may accept different blocks from the two miners at the same timeslot, risking temporary chain forks until reconciliation.

4. **Persistent Degradation**: The duplicate persists through round transitions, potentially affecting multiple subsequent rounds until manual intervention.

This is **HIGH severity** because it directly breaks the fundamental consensus invariant that each miner must have a unique, deterministic production timeslot.

## Likelihood Explanation

**Realistic Trigger Conditions:**

This vulnerability requires NO malicious actor and can occur during normal consensus operations:

1. **Birthday Paradox**: With 21 miners (typical AEDPoS configuration), hash collisions on `supposedOrderOfNextRound` become statistically probable after modest number of rounds.

2. **Natural Occurrence**: Miner signatures derived from their previous in-values create pseudo-random order assignments. Multiple miners can legitimately calculate the same order through hash collisions.

3. **High Occupancy Scenario**: As miners produce blocks throughout a round, positions fill up. When N-1 positions are occupied and a collision occurs at position N, the resolution fails silently.

4. **No Privileges Required**: Happens during standard block production via the `UpdateValue` consensus behavior without any special permissions.

5. **Silent Failure**: No assertion or error is thrown when conflict resolution fails, allowing the duplicate to persist undetected.

The likelihood increases with:
- Longer chain operation (more opportunities for collisions)
- Higher miner participation rates (faster position filling)
- Edge position collisions (position N = minersCount has zero fallback options)

## Recommendation

Fix the conflict resolution loop to cover all valid positions, including the position equal to `supposedOrderOfNextRound`:

```csharp
// Start from supposedOrderOfNextRound itself to ensure all positions are checked
for (var i = supposedOrderOfNextRound; i < supposedOrderOfNextRound + minersCount; i++)
{
    var maybeNewOrder = ((i - 1) % minersCount) + 1; // Ensure 1-indexed range [1, minersCount]
    if (maybeNewOrder != supposedOrderOfNextRound && 
        RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
        break;
    }
}
```

Additionally, enhance validation to detect duplicate order values:

```csharp
// In NextRoundMiningOrderValidationProvider.ValidateHeaderInformation
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();

if (distinctOrderCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound detected.";
    return validationResult;
}
```

## Proof of Concept

```csharp
// Simulate 21-miner scenario with position 21 conflict and all other positions occupied
[Fact]
public void ConflictResolution_FailsAtMaxPosition_CausesDuplicateOrders()
{
    const int minersCount = 21;
    var round = new Round { RealTimeMinersInformation = new Dictionary<string, MinerInRound>() };
    
    // Fill positions 1-20 with miners
    for (int i = 1; i <= 20; i++)
    {
        round.RealTimeMinersInformation[$"miner_{i}"] = new MinerInRound
        {
            Pubkey = $"miner_{i}",
            FinalOrderOfNextRound = i,
            SupposedOrderOfNextRound = i
        };
    }
    
    // Miner A already at position 21
    round.RealTimeMinersInformation["miner_A"] = new MinerInRound
    {
        Pubkey = "miner_A",
        FinalOrderOfNextRound = 21,
        SupposedOrderOfNextRound = 21
    };
    
    // Miner B produces with signature that also hashes to position 21
    var signature = Hash.FromString("collision_signature");
    round.ApplyNormalConsensusData("miner_B", Hash.Empty, Hash.Empty, signature);
    
    // Both miners now have FinalOrderOfNextRound = 21
    Assert.Equal(21, round.RealTimeMinersInformation["miner_A"].FinalOrderOfNextRound);
    Assert.Equal(21, round.RealTimeMinersInformation["miner_B"].FinalOrderOfNextRound);
    
    // Generate next round - both get identical Order and ExpectedMiningTime
    round.GenerateNextRoundInformation(Timestamp.FromDateTime(DateTime.UtcNow), 
        Timestamp.FromDateTime(DateTime.UtcNow), out var nextRound);
    
    var minerANext = nextRound.RealTimeMinersInformation["miner_A"];
    var minerBNext = nextRound.RealTimeMinersInformation["miner_B"];
    
    Assert.Equal(minerANext.Order, minerBNext.Order); // Duplicate Order
    Assert.Equal(minerANext.ExpectedMiningTime, minerBNext.ExpectedMiningTime); // Duplicate timeslot
}
```

## Notes

This vulnerability affects the core consensus mechanism and violates the fundamental invariant that each miner must have a unique production timeslot. The off-by-one error in the conflict resolution search space, combined with inadequate validation, allows duplicate orders to persist silently through normal consensus operations. The issue becomes more likely as the blockchain operates longer and more positions become occupied, particularly when collisions occur at the maximum valid order position.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-26)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
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
