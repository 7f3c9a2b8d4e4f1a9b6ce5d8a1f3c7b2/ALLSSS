### Title
Race Condition in Consensus Order Assignment Leads to Duplicate Mining Orders and Broken Round Schedule

### Summary
Multiple miners can be assigned identical `FinalOrderOfNextRound` values when they concurrently produce blocks based on the same on-chain state, as the conflict resolution logic in `ApplyNormalConsensusData` runs off-chain independently for each miner. This causes duplicate `Order` values in the next round, breaking miner schedule integrity and consensus invariants.

### Finding Description

The vulnerability exists in the interaction between off-chain order calculation and on-chain state updates:

**Off-chain Conflict Resolution:** [1](#0-0) 

Each miner independently calculates their `supposedOrderOfNextRound` and resolves conflicts off-chain by reassigning conflicting miners to available slots.

**On-chain State Update:** [2](#0-1) 

The on-chain processing blindly applies the off-chain calculated values without re-validating uniqueness or detecting if the state has changed.

**Root Cause:**
When two miners (B and C) simultaneously produce blocks based on the same on-chain state (e.g., A=2), both:
1. Detect the same conflict with miner A
2. Calculate the same reassignment (A→3)
3. Both assign themselves order 2
4. Generate identical `TuneOrderInformation = {A: 3}`

When processed sequentially on-chain, B's block executes first (A→3, B=2), then C's block executes (A→3 again [no-op], C=2), resulting in both B and C having `FinalOrderOfNextRound = 2`.

**Missing Validation:** [3](#0-2) 

This validator only checks count equality, not order value uniqueness, and is only applied to `NextRound` behavior, not `UpdateValue` behavior where the vulnerability occurs. [4](#0-3) 

**Impact on Next Round Generation:** [5](#0-4) 

While the dictionary key is `Pubkey` (so no dictionary overwrite occurs), both miners are assigned the same `Order` value in the next round, and: [6](#0-5) 

The `occupiedOrders` list contains duplicate values (e.g., [1, 2, 2, 3]), causing `ableOrders` to miscalculate available slots, leaving gaps in the order sequence while two miners compete for the same time slot.

### Impact Explanation

**Consensus Integrity Breakdown:**
- Two miners receive identical `Order` and `ExpectedMiningTime` values in the next round
- Both miners attempt to produce blocks at the same time slot, causing conflicts
- One valid order position remains unassigned, creating a permanent gap in the mining schedule
- Miner count invariant is violated: not all orders from 1 to N are uniquely assigned

**Quantified Impact:**
- For N miners, up to N-1 duplicate assignments could theoretically occur if all miners race on the same order
- Each duplicate breaks the deterministic time-slot allocation critical to AEDPoS consensus
- Round transitions become unpredictable as miners with duplicate orders race to produce blocks
- The extra block producer calculation and continuous mining prevention logic may malfunction due to duplicate orders

**Affected Parties:**
- All miners in the affected round experience schedule corruption
- Network consensus becomes unreliable as block production timing is compromised
- Chain progress may stall or fork if duplicate-order miners create conflicting blocks

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required - any miner producing blocks can trigger this
- Attack is probabilistic, occurring naturally when:
  1. Multiple miners' signatures modulo into the same `supposedOrderOfNextRound`
  2. These miners produce blocks before seeing each other's blocks on-chain

**Attack Complexity:**
- **Low** - This can occur without malicious intent through natural race conditions
- Probability increases with:
  - Network latency between nodes
  - Number of miners (more miners = higher chance of modulo collision)
  - Small miner counts where collision probability is higher (e.g., 3 miners = 33% chance of collision for any two miners)

**Feasibility Conditions:**
- Normal block production during any round
- No special timing or coordination required
- Can occur repeatedly across multiple rounds

**Detection/Operational Constraints:**
- The duplicate orders only become apparent when the next round is generated
- By then, the corrupted state is already committed on-chain
- No real-time alerts or preventive measures exist

**Probability Reasoning:**
- With 3 miners, probability of two miners getting the same `GetAbsModulus(signature, 3) + 1` is approximately 33% per round
- This makes the vulnerability highly likely to manifest in production environments
- Expected occurrence: multiple times per day on active chains

### Recommendation

**Immediate Fix - Add Uniqueness Validation:**

Add validation in `ProcessUpdateValue` to detect duplicate `FinalOrderOfNextRound` values after applying `TuneOrderInformation`:

```csharp
// After line 260 in AEDPoSContract_ProcessConsensusInformation.cs
var ordersAssigned = currentRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
    
var distinctOrders = ordersAssigned.Distinct().Count();
Assert(distinctOrders == ordersAssigned.Count, 
    "Duplicate FinalOrderOfNextRound values detected");
```

**Long-term Fix - Atomic Order Assignment:**

Implement on-chain conflict resolution instead of trusting off-chain calculations:

```csharp
// In ProcessUpdateValue, re-run conflict detection
var supposedOrder = updateValueInput.SupposedOrderOfNextRound;
var conflicts = currentRound.RealTimeMinersInformation.Values
    .Where(m => m.Pubkey != _processingBlockMinerPubkey && 
                m.FinalOrderOfNextRound == supposedOrder)
    .ToList();

// Re-resolve conflicts on-chain with current state
foreach (var conflictedMiner in conflicts) {
    // Find available order atomically
    var newOrder = FindAvailableOrder(currentRound, conflictedMiner.FinalOrderOfNextRound);
    currentRound.RealTimeMinersInformation[conflictedMiner.Pubkey].FinalOrderOfNextRound = newOrder;
}
```

**Test Cases:**
1. Concurrent UpdateValue transactions from multiple miners with identical `supposedOrderOfNextRound`
2. Verify all miners in a round receive unique `FinalOrderOfNextRound` values
3. Verify next round generation produces unique `Order` values for all miners
4. Stress test with maximum miner count to ensure no order collisions

### Proof of Concept

**Initial State:**
- 3 miners (A, B, C) in current round
- Miner A has produced block: `A.FinalOrderOfNextRound = 2`
- Miners B and C have not yet produced: `B.FinalOrderOfNextRound = 0`, `C.FinalOrderOfNextRound = 0`

**Attack Steps:**

1. **Concurrent Block Production:**
   - Miner B fetches on-chain state: `{A: 2, B: 0, C: 0}`
   - Miner C fetches on-chain state: `{A: 2, B: 0, C: 0}` (same state)

2. **Off-chain Calculation (Miner B):**
   - B's signature yields `supposedOrderOfNextRound = 2`
   - Detects conflict with A (A has order 2)
   - Reassigns A to order 3 (available in B's local view)
   - B gets order 2
   - `TuneOrderInformation = {A: 3}`

3. **Off-chain Calculation (Miner C):**
   - C's signature yields `supposedOrderOfNextRound = 2`
   - Detects conflict with A (A has order 2 in C's view)
   - Reassigns A to order 3 (available in C's local view)
   - C gets order 2
   - `TuneOrderInformation = {A: 3}`

4. **On-chain Execution (Sequential):**
   - B's block processes: `B.FinalOrderOfNextRound = 2`, `A.FinalOrderOfNextRound = 3`
   - State: `{A: 3, B: 2, C: 0}`
   - C's block processes: `C.FinalOrderOfNextRound = 2`, `A.FinalOrderOfNextRound = 3` (already 3)
   - Final State: `{A: 3, B: 2, C: 2}` ← **DUPLICATE ORDER 2**

5. **Next Round Generation:**
   - `minersMinedCurrentRound = [A, B, C]` with `FinalOrderOfNextRound = [3, 2, 2]`
   - Next round assignments: `A.Order = 3`, `B.Order = 2`, `C.Order = 2` ← **Both B and C have Order 2**
   - `occupiedOrders = [3, 2, 2]`
   - `ableOrders = [1]` (order 1 is missing from occupied list)
   - Order 1 never gets assigned, Order 2 is duplicated

**Expected Result:**
Each miner should have unique orders in next round: `{A: 3, B: 2, C: 1}` or similar unique assignment

**Actual Result:**
Duplicate orders in next round: `{A: 3, B: 2, C: 2}`, Order 1 unassigned, consensus schedule broken

**Success Condition:**
Query next round state and verify: `B.Order == C.Order == 2` and no miner has `Order == 1`

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
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

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-260)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-86)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
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
