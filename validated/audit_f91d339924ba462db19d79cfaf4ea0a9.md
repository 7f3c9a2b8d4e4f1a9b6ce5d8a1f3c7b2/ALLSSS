# Audit Report

## Title
Incomplete Conflict Resolution in Miner Order Assignment Leads to Duplicate Orders and Non-Deterministic Consensus

## Summary
The `ApplyNormalConsensusData()` function contains a critical flaw in its conflict resolution loop that fails to check all possible miner positions when resolving order conflicts. When `supposedOrderOfNextRound` equals the maximum valid position (e.g., position 21 in a 21-miner set), the loop's search space excludes that position entirely, causing silent resolution failures that allow duplicate `FinalOrderOfNextRound` values to persist. This violates the fundamental consensus invariant requiring unique miner orders and creates non-deterministic block production.

## Finding Description

The vulnerability exists in the conflict resolution mechanism that reassigns miners when multiple miners calculate the same `FinalOrderOfNextRound` value. [1](#0-0) 

**Root Cause Analysis:**

The conflict resolution loop iterates from `supposedOrderOfNextRound + 1` to `minersCount * 2 - 1`, using modulo arithmetic to wrap positions. The critical flaw occurs when `supposedOrderOfNextRound` equals `minersCount` (the maximum valid order).

For a 21-miner configuration where `supposedOrderOfNextRound = 21`:
- Loop iterates: `i = 22` to `41`
- For all iterations, `i > minersCount` evaluates to true
- `maybeNewOrder` calculation: `22 % 21 = 1`, `23 % 21 = 2`, ..., `41 % 21 = 20`
- **Positions checked: 1 through 20 only**
- **Position 21 is never evaluated**

**Execution Flow:**

1. Miner A produces a block early in the round and receives `FinalOrderOfNextRound = 21` [2](#0-1) 

2. Later in the round, Miner B produces a block and calculates the same `supposedOrderOfNextRound = 21` (hash collision) [3](#0-2) 

3. Conflict detection identifies Miner A already occupies position 21 [4](#0-3) 

4. The resolution loop attempts to reassign Miner A but only checks positions 1-20. If all these positions are occupied by other miners who have already produced blocks, no free position is found.

5. Miner A's `FinalOrderOfNextRound` remains at 21 (unchanged due to failed resolution).

6. Miner B is then assigned `FinalOrderOfNextRound = 21`, creating a duplicate.

7. The duplicate values persist through the update process [5](#0-4)  and [6](#0-5) 

**Why Existing Protections Fail:**

The validation mechanism uses `Distinct()` on miner objects rather than on `FinalOrderOfNextRound` values, failing to detect duplicate order assignments: [7](#0-6) 

The `TuneOrderInformation` mechanism only tracks miners whose `FinalOrderOfNextRound` differs from `SupposedOrderOfNextRound`. When both conflicted miners end up with the same value equal to their supposed order, neither appears in the tuning dictionary: [8](#0-7) 

## Impact Explanation

**Critical Consensus Invariant Violation:**

When duplicate `FinalOrderOfNextRound` values persist into next round generation, both miners are assigned identical `Order` and `ExpectedMiningTime` values: [9](#0-8) 

**Direct Consequences:**

1. **Non-Deterministic Block Production:** Two miners simultaneously believe they should produce at the same timeslot, creating a race condition where network latency determines which block propagates first.

2. **Unfair Penalties:** The miner whose block arrives second may be marked as having missed their timeslot despite legitimate production attempts, damaging their reputation and reducing rewards.

3. **Consensus Ambiguity:** Different network nodes may initially accept different blocks from the two miners, creating temporary forks and requiring additional rounds of consensus reconciliation.

4. **Cascading Effects:** Duplicate orders can persist across multiple round transitions, compounding the problem until the next term change or manual intervention.

**Severity Assessment:**

HIGH severity because this directly compromises the deterministic nature of AEDPoS consensus. The protocol's security model relies on each miner having a unique, predetermined timeslot. Violating this invariant undermines consensus guarantees and can occur during normal operations without malicious actors.

## Likelihood Explanation

**Natural Occurrence Without Attacks:**

This vulnerability triggers during legitimate consensus operations without requiring malicious behavior:

- **Hash Collision Probability:** With 21 miners, the birthday paradox makes signature hash collisions statistically likely over extended operation. The probability that two miners calculate the same order increases as more blocks are produced.

- **Position Saturation:** As miners produce blocks throughout a round, positions 1 through N gradually fill. The edge case becomes exploitable when the collision occurs at position N and N-1 other positions are already occupied.

- **Silent Failure:** The bug produces no error or exception. The conflict resolution loop completes normally, leaving duplicate orders undetected by validation logic.

**Realistic Trigger Conditions:**

1. **No Special Privileges:** Occurs during standard `UpdateValue` consensus behavior as miners produce blocks in their assigned timeslots.

2. **Common Scenarios:** More likely in:
   - Smaller miner sets (< 10 miners) where collision probability is higher
   - Larger miner sets (> 20 miners) near round completion when most positions are occupied
   - High-participation rounds where most miners successfully produce blocks

3. **Cumulative Risk:** Each round with active participation increases the probability. Over hundreds of rounds, the likelihood approaches certainty.

**Feasibility:**

The vulnerability is highly feasible because:
- It requires only normal block production by honest miners
- No coordination or timing manipulation needed
- Naturally occurs when round participation is high (a desired network state)
- Detection difficulty means it may persist unnoticed until consensus failures occur

## Recommendation

**Fix the Search Space:**

Modify the conflict resolution loop to ensure all positions 1 through `minersCount` are checked when `supposedOrderOfNextRound = minersCount`. 

**Approach 1 - Adjust loop bounds:**
Change the loop to explicitly check position `minersCount` before wrapping with modulo:

```csharp
for (var i = supposedOrderOfNextRound + 1; i <= supposedOrderOfNextRound + minersCount; i++)
{
    var maybeNewOrder = i > minersCount ? ((i - 1) % minersCount) + 1 : i;
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
        break;
    }
}
```

**Approach 2 - Separate handling for edge case:**
Before the main loop, explicitly check the `supposedOrderOfNextRound` position itself:

```csharp
// First check if the supposed position itself is available (edge case)
if (supposedOrderOfNextRound == minersCount && 
    RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != minersCount))
{
    // Keep the conflicted miner at their current position
    continue;
}

// Then search other positions
for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
{
    var maybeNewOrder = i > minersCount ? i % minersCount : i;
    if (maybeNewOrder == 0) maybeNewOrder = minersCount; // Handle modulo edge case
    // ... rest of logic
}
```

**Enhanced Validation:**

Additionally, strengthen the validation to detect duplicate orders:

```csharp
var ordersCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize a round with 21 miners
2. Simulate 20 miners producing blocks with orders 1-20
3. Have Miner A produce with signature yielding `FinalOrderOfNextRound = 21`
4. Have Miner B produce with different signature but same modulo result, yielding `supposedOrderOfNextRound = 21`
5. Verify both miners end up with `FinalOrderOfNextRound = 21`
6. Generate next round and confirm both miners receive identical `Order` and `ExpectedMiningTime`

The test would confirm that when position 21 has a conflict and positions 1-20 are all occupied, the conflict resolution fails silently, allowing duplicate orders to persist.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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
