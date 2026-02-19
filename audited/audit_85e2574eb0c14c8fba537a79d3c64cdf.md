### Title
Conflict Resolution Failure in ApplyNormalConsensusData Causes Duplicate Mining Orders and Consensus Breakdown

### Summary
The conflict resolution loop in `ApplyNormalConsensusData()` fails to guarantee unique `FinalOrderOfNextRound` values when all mining orders are occupied. When the loop exits without finding a free order for a conflicted miner, both the conflicted miner and the current miner are assigned the same order, creating duplicates that break next round generation and cause consensus failure.

### Finding Description

**Exact Location:** [1](#0-0) 

**Root Cause:**
The conflict resolution loop attempts to reassign miners when `FinalOrderOfNextRound` conflicts occur. However, it searches for available orders by checking if any miner currently holds each `maybeNewOrder` value. When all orders 1 through `minersCount` are already occupied by miners (including the current miner's old order), the loop completes without finding a free slot. The conflicted miner retains their original `FinalOrderOfNextRound`, and then the current miner is unconditionally assigned the same conflicting order at line 44.

**Why Protections Fail:**
1. The loop checks orders already held by ALL miners (line 34), including the current miner's old order, which will soon be overwritten
2. No validation ensures the conflicted miner was successfully reassigned before assigning the current miner's order
3. The `TuneOrderInformation` mechanism only propagates changes when `FinalOrderOfNextRound != SupposedOrderOfNextRound` [2](#0-1) , so unresolved conflicts where the miner keeps their original order are never broadcast to other nodes
4. The `NextRoundMiningOrderValidationProvider` only runs for `NextRound` behavior, not `UpdateValue` [3](#0-2) , allowing duplicates to persist through normal block production

**Execution Path:**
1. Miner produces block via `GetConsensusExtraDataToPublishOutValue` [4](#0-3) 
2. `ApplyNormalConsensusData` calculates `supposedOrderOfNextRound` from signature (line 21)
3. Conflict detected if another miner has that order (lines 25-26)
4. Conflict resolution loop searches for free orders but finds none
5. Conflicted miner keeps original order; current miner gets same order
6. When processed, `ProcessUpdateValue` sets both to the same value [5](#0-4) 

### Impact Explanation

**Concrete Harm:**
When `GenerateNextRoundInformation` processes duplicate `FinalOrderOfNextRound` values [6](#0-5) :

1. **Non-deterministic Consensus:** The `OrderBy(m => m.FinalOrderOfNextRound)` at line 26 produces non-deterministic ordering when duplicates exist, causing different nodes to generate different next rounds, permanently forking the chain

2. **Next Round Generation Failure:** The `occupiedOrders` list contains duplicate values (line 40), reducing `ableOrders` count. If there are miners who didn't mine requiring orders from `ableOrders` (line 44), an `IndexOutOfRangeException` occurs, preventing next round generation and halting consensus

3. **Invalid Mining Schedule:** Multiple miners with identical `FinalOrderOfNextRound` receive the same `ExpectedMiningTime` (line 33), causing simultaneous block production attempts and consensus conflicts

**Severity Justification:** HIGH - This breaks the fundamental consensus invariant of unique mining order assignment, causing chain halt or permanent fork. All miners and users are affected as the network becomes non-functional.

### Likelihood Explanation

**Attacker Capabilities:** Any miner can trigger this by producing multiple blocks in the same round (e.g., tiny blocks), which is normal protocol behavior.

**Attack Complexity:** LOW
- Miners naturally produce multiple tiny blocks per time slot [7](#0-6) 
- The `signature` calculation varies by block height when no `PreviousInValue` is provided [8](#0-7) , naturally producing different `supposedOrderOfNextRound` values across blocks
- No special conditions required beyond normal block production

**Feasibility Conditions:**
1. All `minersCount` miners have produced at least one block, occupying all orders 1-N
2. A miner produces an additional block (tiny block or continuation) in the same round
3. Their new `supposedOrderOfNextRound` conflicts with an existing miner's order
4. All other orders are occupied, so conflict resolution fails

**Probability:** MEDIUM-HIGH - In active rounds where all miners participate, the preconditions are frequently met. The signature-based order calculation makes conflicts probabilistic but regular.

### Recommendation

**Code-Level Mitigation:**
1. Before the conflict resolution loop, temporarily clear the current miner's old `FinalOrderOfNextRound` to make it available for reassignment
2. Add a post-loop validation that the conflicted miner was successfully reassigned before assigning the current miner's new order
3. If conflict resolution fails, either:
   - Retain the current miner's old order (don't allow the change)
   - Force a round transition to reset all orders
   - Add fallback logic to swap orders between current and conflicted miner

**Invariant Checks:**
```csharp
// After conflict resolution, before line 44
Assert(
    conflicts.All(c => RealTimeMinersInformation[c.Pubkey].FinalOrderOfNextRound != supposedOrderOfNextRound),
    "Failed to resolve all order conflicts"
);

// After setting all orders
var orderCounts = RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .GroupBy(m => m.FinalOrderOfNextRound)
    .Select(g => g.Count());
Assert(orderCounts.All(count => count == 1), "Duplicate FinalOrderOfNextRound values detected");
```

**Test Cases:**
1. All miners produce blocks occupying orders 1-N
2. First miner produces additional block with conflicting order
3. Verify no duplicate `FinalOrderOfNextRound` values exist
4. Verify next round generates successfully

### Proof of Concept

**Initial State:**
- 5 miners in round: A, B, C, D, E
- All have produced blocks: A(order=1), B(order=2), C(order=3), D(order=4), E(order=5)
- Current round allows tiny blocks

**Exploit Steps:**
1. Miner A produces tiny block at height H+1
2. Due to height-dependent signature calculation, A's new `supposedOrderOfNextRound = 3` (conflicts with C)
3. Conflict resolution loop checks orders: 4(taken by D), 5(taken by E), 1(taken by A), 2(taken by B), 3(taken by C)
4. No free order found, loop exits
5. Miner C retains `FinalOrderOfNextRound = 3`
6. Miner A assigned `FinalOrderOfNextRound = 3`
7. Block processed via `ProcessUpdateValue`, both A and C persist with order 3

**Expected vs Actual:**
- **Expected:** Conflict resolved, all miners have unique orders
- **Actual:** Both A and C have `FinalOrderOfNextRound = 3`

**Success Condition:**
Attempt to generate next round:
- Call `GenerateNextRoundInformation` [9](#0-8) 
- Observe: `occupiedOrders = [1,2,3,3,4]` (duplicate 3)
- Observe: `ableOrders = [5]` (only one available)
- If any miner didn't mine, `ableOrders[i]` access fails with index out of range
- Next round generation halts, consensus breaks

### Notes

The question mentions "Infinite Loop Risk" but the actual vulnerability is not an infinite loop (the loop is bounded by `i < minersCount * 2`). The real issue is what happens when the loop completes without resolution - it creates duplicate mining orders that break consensus.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L31-44)
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

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L58-61)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L96-96)
```csharp
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```
