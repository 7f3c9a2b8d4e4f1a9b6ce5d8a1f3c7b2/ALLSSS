### Title
Duplicate FinalOrderOfNextRound Due to Failed Conflict Resolution in ApplyNormalConsensusData

### Summary
The conflict resolution logic in `ApplyNormalConsensusData` contains a flawed modulo operation that creates an asymmetric order retry pattern. When all mining orders [1, minersCount] are occupied, the reassignment loop fails to find an available slot for conflicted miners, allowing duplicate `FinalOrderOfNextRound` values to persist. This causes time slot collisions in the next round, disrupting consensus integrity.

### Finding Description
The vulnerability exists in the order conflict resolution mechanism [1](#0-0) 

**Root Cause:**
At line 33, the condition `i > minersCount ? i % minersCount : i` produces incorrect wraparound behavior. When `i = minersCount + 1` (e.g., i=6 when minersCount=5), the modulo operation yields `6 % 5 = 1`. This creates an asymmetric retry pattern where orders 1-4 are retried twice but order 5 is only tried once (or never, depending on `supposedOrderOfNextRound`).

**Exploitation Path:**
1. All miners in a round have already claimed orders [1, 2, 3, 4, 5] via `FinalOrderOfNextRound`
2. Miner M1 (currently has order 1) produces another block with a different signature
3. The signature calculation yields `supposedOrderOfNextRound = 2` (conflict with Miner M2)
4. Conflict detection finds M2 in the conflicts list [2](#0-1) 
5. The reassignment loop tries orders: 3, 4, 5, 1, 2, 3, 4 (all occupied)
6. Loop exits without reassigning M2, who retains `FinalOrderOfNextRound = 2`
7. Line 44 assigns M1's `FinalOrderOfNextRound = 2` [3](#0-2) 
8. **Result: Both M1 and M2 have `FinalOrderOfNextRound = 2`**

**Why Existing Protections Fail:**
The `NextRoundMiningOrderValidationProvider` validation does not detect duplicate orders [4](#0-3) . The `.Distinct()` operates on `MinerInRound` objects, not on their `FinalOrderOfNextRound` values, so two different miners with the same order value pass validation as long as the count matches miners who mined.

### Impact Explanation
**Consensus Integrity Violation:**
When `GenerateNextRoundInformation` processes the current round [5](#0-4) , miners with duplicate `FinalOrderOfNextRound` values are both assigned the same `Order` and `ExpectedMiningTime` in the next round. This causes:

1. **Time Slot Collision**: Two miners attempt to produce blocks at the same time slot, creating a fork condition
2. **Missing Time Slot**: The order not claimed (e.g., order 1) becomes an unfilled slot, calculated as an "available order" [6](#0-5) 
3. **BreakContinuousMining Failure**: Logic using `First()` or `FirstOrDefault()` to find specific orders becomes non-deterministic [7](#0-6) 
4. **Round Schedule Disruption**: The deterministic mining schedule is compromised, affecting block production reliability

**Severity Justification**: Medium - While no direct fund loss occurs, consensus integrity is a critical invariant. The attack disrupts the mining schedule predictability required for proper AEDPoS operation.

### Likelihood Explanation
**Attacker Capabilities**: Any active miner can trigger this by producing multiple blocks within the same round with different consensus data.

**Preconditions (Highly Realistic)**:
- All miners are active and have claimed their orders [1, minersCount] - this is the **normal operational state**
- A miner produces a second block in the same round (evidenced by `ProducedTinyBlocks` counter) [8](#0-7) 
- The signature calculation produces a different `supposedOrderOfNextRound` value [9](#0-8) 

**Attack Complexity**: Low - The miner simply needs to produce blocks with varying `triggerInformation.PreviousInValue` parameters, which naturally vary or can be manipulated.

**Economic Rationality**: The cost is minimal (gas for producing blocks), while the impact (consensus disruption) can benefit a malicious miner by creating uncertainty in the next round's block production schedule.

**Feasibility**: High - The condition of "all orders occupied" is the expected state when all miners are active, making this vulnerability triggerable in normal operation, not just edge cases.

### Recommendation
**Fix the modulo logic** at line 33 to ensure proper wraparound that covers all orders [1, minersCount] equally:

```csharp
var maybeNewOrder = ((i - 1) % minersCount) + 1;
```

This ensures orders stay in range [1, minersCount] with proper wraparound arithmetic.

**Add duplicate order validation** in `NextRoundMiningOrderValidationProvider`:
```csharp
var finalOrders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
    
if (finalOrders.Count != finalOrders.Distinct().Count())
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound detected.";
    return validationResult;
}
```

**Add early exit check** if reassignment fails:
```csharp
if (RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound == supposedOrderOfNextRound)
{
    // Reassignment failed, abort or handle error
    Assert(false, "Failed to resolve order conflict - all orders occupied");
}
```

**Test cases**:
- All miners active with orders [1, minersCount] occupied
- Miner produces second block with signature yielding conflicting order
- Verify reassignment succeeds or transaction reverts (no duplicates allowed)

### Proof of Concept
**Initial State:**
- Round with 5 miners (M1, M2, M3, M4, M5)
- All miners have produced blocks: M1=order 1, M2=order 2, M3=order 3, M4=order 4, M5=order 5
- All `FinalOrderOfNextRound` values assigned

**Attack Sequence:**
1. M1 calls consensus contract to produce another block
2. M1 provides `triggerInformation.PreviousInValue` that yields signature calculating to `supposedOrderOfNextRound = 2`
3. `ApplyNormalConsensusData` executes:
   - Detects conflict: M2 has `FinalOrderOfNextRound = 2`
   - Loop attempts reassignment for M2: tries orders 3,4,5,1,2,3,4 (all occupied)
   - Loop exits without reassignment
   - M2 keeps `FinalOrderOfNextRound = 2`
   - M1 assigned `FinalOrderOfNextRound = 2`
4. Next round generation processes both M1 and M2 with order 2
5. Both M1 and M2 receive `Order = 2` and identical `ExpectedMiningTime` in next round

**Expected Result:** Conflict resolution should succeed or transaction should revert

**Actual Result:** Both M1 and M2 have `FinalOrderOfNextRound = 2`, causing time slot collision in next round

**Success Condition:** Query next round's `RealTimeMinersInformation` and verify two miners have the same `Order` value, violating the uniqueness invariant required for deterministic consensus.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-86)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L58-61)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```
