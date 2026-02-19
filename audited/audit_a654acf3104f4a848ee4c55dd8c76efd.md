### Title
Conflict Resolution Failure in ApplyNormalConsensusData Leads to Duplicate Mining Orders

### Summary
When `supposedOrderOfNextRound` equals `minersCount`, the conflict resolution loop fails to check all available orders, only examining orders 1 through `minersCount-1`. If all these orders are occupied, the conflicted miner cannot be reassigned, resulting in two miners being assigned the same `FinalOrderOfNextRound`. This causes both miners to have identical mining time slots in the next round, violating consensus invariants and potentially leading to fork creation or missed blocks.

### Finding Description
The vulnerability exists in the `ApplyNormalConsensusData` function's conflict resolution logic. [1](#0-0) 

When a miner produces a block, their `supposedOrderOfNextRound` is calculated as `GetAbsModulus(sigNum, minersCount) + 1`, yielding values from 1 to `minersCount`. [2](#0-1) 

If this order conflicts with an existing miner's `FinalOrderOfNextRound`, the system attempts to reassign the conflicted miner. [3](#0-2) 

**Root Cause**: When `supposedOrderOfNextRound = minersCount`, the loop iterates from `minersCount + 1` to `minersCount * 2 - 1`. After the modulus operation at line 33, this checks only orders 1, 2, 3, ..., `minersCount-1`, completely skipping order `minersCount`. [4](#0-3) 

The loop checks if any order is unoccupied via `All(m => m.FinalOrderOfNextRound != maybeNewOrder)`. If all checked orders (1 through `minersCount-1`) are occupied, the loop completes without executing the reassignment (line 36-38 never reached), and the conflicted miner retains their original order. [5](#0-4) 

Subsequently, the current miner is assigned the same order at line 44, creating a duplicate. [6](#0-5) 

### Impact Explanation
**Consensus Integrity Violation**: Two miners with identical `FinalOrderOfNextRound` values will be assigned the same `Order` in the next round. [7](#0-6) 

This results in:
1. **Identical ExpectedMiningTime**: Both miners calculate the same mining timestamp, attempting to produce blocks simultaneously
2. **Fork Risk**: Two valid blocks at the same height/timestamp create blockchain forks
3. **Consensus Disruption**: The protocol's time-slot scheduling breaks down, potentially causing rounds to fail validation
4. **Miner Overwriting**: The `RealTimeMinersInformation` dictionary uses pubkey as the key, so both miners are present but with the same Order value, confusing subsequent round logic
5. **Reward Misallocation**: If one miner's slot is effectively skipped or overridden, they lose legitimate mining rewards

**Affected Parties**: All network participants suffer from consensus instability. Miners with duplicate orders may lose rewards or be incorrectly flagged as evil miners.

**Severity Justification**: Medium - requires specific preconditions (all orders occupied + collision) but causes significant consensus integrity violation when triggered.

### Likelihood Explanation
**Entry Point**: The vulnerability is triggered through the standard `UpdateValue` consensus behavior when miners produce blocks. [8](#0-7) 

**Preconditions** (realistic):
1. All `minersCount` orders (1 through `minersCount`) are already occupied by miners who have produced blocks in the current round
2. An additional miner (late block producer or miner recalculating their order) calls `ApplyNormalConsensusData` with a signature that hashes to `supposedOrderOfNextRound = minersCount`
3. The collision probability increases with smaller `minersCount` values (e.g., 5 miners = 20% chance per signature)

**Execution Practicality**: 
- No special permissions required - any miner producing a block triggers this code path
- Signature values are deterministic based on consensus data but vary by miner and round
- With 5-7 miners (common testnet/sidechain configurations), all orders being occupied is a normal end-of-round state

**Detection Constraints**: The bug is silent - no error is thrown, and the duplicate orders only become apparent during next round generation when time-slot conflicts occur.

**Probability**: Medium likelihood - depends on miner count and signature distribution, but becomes increasingly probable as rounds progress and orders fill up.

### Recommendation
**Code-Level Mitigation**:
Modify the loop to ensure all orders except the conflicted order are checked, regardless of the value of `supposedOrderOfNextRound`:

```csharp
for (var i = 1; i <= minersCount; i++)
{
    if (i == supposedOrderOfNextRound) continue; // Skip the conflicted order
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != i))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = i;
        break;
    }
}
```

**Invariant Checks**:
1. After conflict resolution, assert that no two miners have the same `FinalOrderOfNextRound`:
   ```csharp
   Assert(RealTimeMinersInformation.Values
       .GroupBy(m => m.FinalOrderOfNextRound)
       .All(g => g.Count() == 1), 
       "Duplicate FinalOrderOfNextRound detected");
   ```

2. Add validation in `GenerateNextRoundInformation` to detect duplicate orders before they cause consensus issues. [9](#0-8) 

**Test Cases**:
1. Test with `minersCount = 5`, all orders occupied, new miner calculates order 5
2. Test multiple concurrent conflicts with insufficient free orders
3. Verify that conflict resolution succeeds when free orders exist
4. Validate next round generation rejects rounds with duplicate orders

### Proof of Concept

**Initial State**:
- `minersCount = 5`
- Miner A: `FinalOrderOfNextRound = 5`
- Miner B: `FinalOrderOfNextRound = 1`
- Miner C: `FinalOrderOfNextRound = 2`
- Miner D: `FinalOrderOfNextRound = 3`
- Miner E: `FinalOrderOfNextRound = 4`
- All 5 orders are occupied

**Attack Sequence**:
1. Miner X (could be a late block producer or miner updating consensus data) calls `UpdateValue` with consensus trigger information
2. In `GetConsensusExtraDataToPublishOutValue`, signature is calculated yielding `sigNum` such that `GetAbsModulus(sigNum, 5) = 4`
3. `ApplyNormalConsensusData` calculates `supposedOrderOfNextRound = 4 + 1 = 5`
4. Conflict detected: Miner A already has `FinalOrderOfNextRound = 5`
5. Conflict resolution loop executes:
   - `i = 6`: `maybeNewOrder = 6 % 5 = 1` → Occupied by Miner B
   - `i = 7`: `maybeNewOrder = 7 % 5 = 2` → Occupied by Miner C
   - `i = 8`: `maybeNewOrder = 8 % 5 = 3` → Occupied by Miner D
   - `i = 9`: `maybeNewOrder = 9 % 5 = 4` → Occupied by Miner E
   - Loop exits without reassigning Miner A
6. Miner A retains `FinalOrderOfNextRound = 5`
7. Miner X is assigned `FinalOrderOfNextRound = 5`

**Expected Result**: Conflict resolved, Miner A reassigned to available order

**Actual Result**: Both Miner A and Miner X have `FinalOrderOfNextRound = 5`

**Success Condition**: Query `currentRound.RealTimeMinersInformation.Values` and verify two entries have `FinalOrderOfNextRound == 5`, then observe in next round generation that both miners receive `Order = 5` with identical `ExpectedMiningTime` values.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L44-44)
```csharp
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```
