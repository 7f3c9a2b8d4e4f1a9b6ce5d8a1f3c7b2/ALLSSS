### Title
Consensus-Breaking Insufficient Conflict Resolution in Mining Order Assignment

### Summary
The conflict resolution algorithm in `ApplyNormalConsensusData` fails when all `minersCount` miners have the same `FinalOrderOfNextRound` value equal to `minersCount`. The loop can only find `minersCount - 1` alternative positions, leaving one miner with a duplicate order that breaks consensus during next round generation. This leads to non-deterministic round transitions across nodes, potentially causing chain forks or halts.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The conflict resolution loop iterates from `supposedOrderOfNextRound + 1` to `minersCount * 2 - 1`. When `supposedOrderOfNextRound = minersCount`, the loop produces values:
- For `i ∈ [minersCount+1, minersCount]`: direct values (0 positions)  
- For `i ∈ [minersCount+1, 2*minersCount-1]`: modulo values `1, 2, ..., minersCount-1` (minersCount-1 positions)

This provides only `minersCount - 1` unique alternative positions. When all `minersCount` existing miners have `FinalOrderOfNextRound = minersCount` and need to be moved, one miner remains unresolved.

**Execution Path:**
1. Multiple miners produce blocks with signatures that hash to the same order [2](#0-1) 
2. The algorithm identifies conflicts [3](#0-2) 
3. It successfully reassigns `minersCount - 1` miners but fails to find a position for the last one [1](#0-0) 
4. The new miner is then assigned the same order [4](#0-3) 

**Why Protections Fail:**

The validation meant to catch duplicate orders is broken: [5](#0-4) 

This calls `.Distinct()` on `MinerInRound` objects instead of on their `FinalOrderOfNextRound` values, making it ineffective at detecting duplicate order values.

### Impact Explanation

**Consensus Integrity Violation:**

When duplicate `FinalOrderOfNextRound` values exist, next round generation breaks: [6](#0-5) 

Two miners receive the same `Order` value in the next round, violating the fundamental invariant that each miner must have a unique mining position. This causes:

1. **Non-Deterministic Round Generation**: The `OrderBy(m => m.FinalOrderOfNextRound)` operation with duplicate keys has undefined tie-breaking behavior across nodes, as it depends on dictionary iteration order which is non-deterministic.

2. **Mining Schedule Corruption**: Multiple miners assigned the same `Order` create time slot conflicts and undefined mining behavior.

3. **Chain Fork Risk**: Different nodes generate different next round configurations, leading to consensus divergence and potential chain splits.

4. **Operational Disruption**: Nodes may reject blocks or fail to progress rounds, causing network halts requiring manual intervention.

**Severity:** HIGH - Core consensus integrity compromise affecting all validators and network operation.

### Likelihood Explanation

**Preconditions:**
- Requires `minersCount` miners to all have `FinalOrderOfNextRound = minersCount`
- This occurs when multiple miners' signature hashes collide to the same value through [2](#0-1) 

**Probability Analysis:**
- Each miner has ~1/minersCount probability of getting `supposedOrderOfNextRound = minersCount`
- For typical AEDPoS with 21 miners: ~4.8% per miner per round
- As the round progresses and more miners produce blocks, cumulative collision probability increases
- Over hundreds of rounds, the probability of this edge case occurring becomes significant
- Once a few miners have the same order, subsequent collisions trigger the vulnerability

**Attacker Capabilities:**
- No special privileges required - occurs through natural hash collisions
- Cannot be directly forced but becomes increasingly likely over time
- No economic cost to trigger naturally

**Feasibility:** MEDIUM - Not likely in every round, but mathematically inevitable over extended operation.

### Recommendation

**Fix the conflict resolution loop bounds:**

Modify [7](#0-6)  to:

```csharp
for (var i = 1; i <= minersCount; i++)
{
    if (i == supposedOrderOfNextRound) continue;
    var maybeNewOrder = i;
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
        break;
    }
}
```

This ensures all `minersCount - 1` alternative positions are always searched.

**Fix the validation check:**

Modify [5](#0-4)  to:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

This correctly validates that `FinalOrderOfNextRound` values are unique.

**Add assertion after conflict resolution:**

After [8](#0-7) , add:

```csharp
Assert(
    RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0)
        .Select(m => m.FinalOrderOfNextRound)
        .Distinct()
        .Count() == RealTimeMinersInformation.Values.Count(m => m.FinalOrderOfNextRound > 0),
    "Failed to resolve all order conflicts."
);
```

**Test cases:**
1. All N miners with FinalOrderOfNextRound = N, new miner wants N
2. N-1 miners with same order, verify all get unique assignments
3. Stress test with various collision scenarios

### Proof of Concept

**Initial State:**
- `minersCount = 3`
- Existing miners: MinerA, MinerB, MinerC
- All have `FinalOrderOfNextRound = 3`

**Transaction Sequence:**

1. MinerD produces a block, signature hashes to value yielding `supposedOrderOfNextRound = 3`
2. `ApplyNormalConsensusData("MinerD", previousInValue, outValue, signature)` is called
3. Conflict detection identifies: `conflicts = [MinerA, MinerB, MinerC]`

**Conflict Resolution Execution:**

Iteration 1 (MinerA):
- Loop: `i ∈ [4, 5]`
- `i=4`: `maybeNewOrder = 4 % 3 = 1` → Available → MinerA reassigned to 1

Iteration 2 (MinerB):
- `i=4`: `maybeNewOrder = 1` → Taken by MinerA
- `i=5`: `maybeNewOrder = 5 % 3 = 2` → Available → MinerB reassigned to 2

Iteration 3 (MinerC):
- `i=4`: `maybeNewOrder = 1` → Taken
- `i=5`: `maybeNewOrder = 2` → Taken  
- Loop exits without finding available position
- MinerC remains at order 3

4. MinerD assigned: `FinalOrderOfNextRound = 3`

**Expected Result:** All miners have unique `FinalOrderOfNextRound` values

**Actual Result:**
- MinerA = 1
- MinerB = 2  
- MinerC = 3 (DUPLICATE)
- MinerD = 3 (DUPLICATE)

**Success Condition:** Two miners with identical `FinalOrderOfNextRound = 3`, breaking consensus invariant and causing non-deterministic next round generation across nodes.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
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
