### Title
Duplicate FinalOrderOfNextRound Assignment Causes Consensus Failure Due to Incomplete Conflict Resolution

### Summary
The `ApplyNormalConsensusData` function's conflict resolution loop can fail to find a free position when all mining order slots are occupied, allowing two miners to retain identical `FinalOrderOfNextRound` values. This breaks the critical invariant that each miner must have a unique next-round order, leading to non-deterministic miner ordering across nodes and consensus failure.

### Finding Description

The vulnerability exists in the conflict resolution logic of `ApplyNormalConsensusData`: [1](#0-0) 

**Root Cause:**

When a miner produces a block, `supposedOrderOfNextRound` is calculated from their signature hash (line 21). If this conflicts with another miner's existing `FinalOrderOfNextRound` (lines 25-26), the conflict resolution loop (lines 28-40) attempts to reassign the conflicted miner to a new position.

The loop searches positions from `supposedOrderOfNextRound + 1` to `minersCount * 2 - 1`, wrapping around via modulo arithmetic (line 33). At line 34, it checks if any miner currently occupies each candidate position: [2](#0-1) 

**Critical Flaw:**

This check includes the conflicted miner's own current position. When all positions 1 through `minersCount` are occupied by distinct miners, the loop cannot find any free position because:
- Every candidate position is occupied by some miner
- The conflicted miner's own position is occupied by themselves
- No position passes the "all miners have different FinalOrderOfNextRound" check

When the loop completes without finding a free position, the conflicted miner retains their original `FinalOrderOfNextRound`. Then line 44 unconditionally assigns the same value to the current miner, creating a duplicate.

**Why Existing Protections Fail:**

The validation provider intended to catch this issue has a critical bug: [3](#0-2) 

Line 15-16 calls `.Distinct()` on the `MinerInRound` objects themselves, not on their `FinalOrderOfNextRound` values. This checks for duplicate miner objects (which never exist), not duplicate order values. The validation always passes even when duplicates exist.

### Impact Explanation

**Consensus Integrity Breach:**

When `GenerateNextRoundInformation` creates the next round, it orders miners by `FinalOrderOfNextRound`: [4](#0-3) 

With duplicate `FinalOrderOfNextRound` values, `OrderBy` produces non-deterministic ordering when two miners have the same key. Different nodes may order these miners differently in their local state.

**Concrete Harm:**
- **Blockchain Fork Risk**: Nodes disagree on which miner should produce blocks at specific time slots
- **Block Production Failure**: Miners produce blocks at wrong times, leading to rejections
- **Network Partition**: Nodes following different mining orders cannot reach consensus
- **Complete System Halt**: If enough miners have conflicting orders, the blockchain stops producing valid blocks

**Severity:** Critical - This violates the fundamental consensus invariant that all nodes must agree on miner ordering. The system cannot function with non-deterministic round generation.

### Likelihood Explanation

**Attack Complexity:** None - This occurs naturally without any malicious action.

**Feasible Preconditions:**
1. All `minersCount` positions (1 through `minersCount`) are occupied by distinct miners with set `FinalOrderOfNextRound` values
2. A miner produces a block whose signature hash modulo `minersCount` conflicts with an existing miner's position
3. This happens after the first round when all miners have produced at least one block

**Probability Analysis:**

In a network with `N` miners, each miner's signature hash produces a uniformly distributed value in [1, N]. When all N positions are occupied:
- Each new block has probability ~1/N of conflicting with any specific position
- With N miners producing blocks, conflicts occur frequently (birthday paradox)
- For N=21 miners (typical AElf configuration), this has high probability within a few rounds

**Reachability:**

The entry point is through normal block production: [5](#0-4) 

Every miner calls `ApplyNormalConsensusData` when producing an `UpdateValue` block. This is a standard, frequent operation with no special permissions required.

**Detection Constraints:** The faulty validation provider fails to detect the issue, allowing duplicates to propagate through the network.

### Recommendation

**Immediate Fix - Exclude Conflicted Miner from Check:**

Modify the conflict resolution loop to exclude the miner being reassigned from the position availability check:

```csharp
foreach (var orderConflictedMiner in conflicts)
{
    for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
    {
        var maybeNewOrder = i > minersCount ? i % minersCount : i;
        // Exclude the conflicted miner from the check
        if (RealTimeMinersInformation.Values
            .Where(m => m.Pubkey != orderConflictedMiner.Pubkey)
            .All(m => m.FinalOrderOfNextRound != maybeNewOrder))
        {
            RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
            break;
        }
    }
}

// CRITICAL: Verify no conflicts remain before assignment
var stillHasConflict = RealTimeMinersInformation.Values
    .Any(m => m.Pubkey != pubkey && m.FinalOrderOfNextRound == supposedOrderOfNextRound);
Assert(!stillHasConflict, "Failed to resolve FinalOrderOfNextRound conflict");

RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**Fix Validation Provider:**

Correct the duplicate detection logic:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Select the order value
    .Distinct()
    .Count();
```

**Add Invariant Check:**

After any `FinalOrderOfNextRound` assignment, verify uniqueness:

```csharp
var orderCounts = RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .GroupBy(m => m.FinalOrderOfNextRound)
    .Where(g => g.Count() > 1)
    .ToList();
Assert(orderCounts.Count == 0, "Duplicate FinalOrderOfNextRound detected");
```

**Test Cases:**

1. Simulate full occupancy: All N positions occupied, new miner conflicts with position 1
2. Multiple conflicts: Two miners get same `supposedOrderOfNextRound` simultaneously
3. Wraparound edge case: Conflict at position N, verify correct wraparound handling
4. Validation test: Ensure provider catches duplicate orders

### Proof of Concept

**Initial State:**
- Network with 3 miners (minersCount = 3)
- Round 2 in progress
- Miner A: `FinalOrderOfNextRound = 1`
- Miner B: `FinalOrderOfNextRound = 2`  
- Miner C: `FinalOrderOfNextRound = 3`

**Transaction Sequence:**

1. Miner C produces a block (UpdateValue behavior)
2. Signature hash calculated: `Hash.ToInt64() % 3 = 0`, so `supposedOrderOfNextRound = 1`
3. `ApplyNormalConsensusData` called with `pubkey = "MinerC"`, `supposedOrderOfNextRound = 1`

**Execution Trace:**

- Line 25-26: Conflicts list = `[MinerA]` (has `FinalOrderOfNextRound = 1`)
- Lines 28-40: Attempt to reassign Miner A
  - i=2: `maybeNewOrder = 2`, check fails (Miner B has position 2)
  - i=3: `maybeNewOrder = 3`, check fails (Miner C has position 3)
  - i=4: `maybeNewOrder = 4 % 3 = 1`, check fails (Miner A has position 1)
  - i=5: `maybeNewOrder = 5 % 3 = 2`, check fails (Miner B has position 2)
  - Loop exits without reassigning Miner A
- Line 44: `MinerC.FinalOrderOfNextRound = 1`

**Result:**
- Miner A: `FinalOrderOfNextRound = 1` ✗
- Miner B: `FinalOrderOfNextRound = 2` ✓
- Miner C: `FinalOrderOfNextRound = 1` ✗

**DUPLICATE DETECTED - Consensus invariant violated**

**Expected vs Actual:**
- Expected: Each miner has unique `FinalOrderOfNextRound` in [1,2,3]
- Actual: Miners A and C both have `FinalOrderOfNextRound = 1`

**Success Condition:** 
When `GenerateNextRoundInformation` is called, `minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound)` returns non-deterministic ordering for Miners A and C, causing different nodes to generate different next round configurations.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```
