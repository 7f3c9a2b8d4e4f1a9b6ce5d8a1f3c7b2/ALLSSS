# Audit Report

## Title
Last Irreversible Block (LIB) Progression Can Be Prevented Through Insufficient Miner Overlap Between Consecutive Rounds

## Summary
The AEDPoS consensus contract's LIB calculation mechanism can freeze indefinitely when fewer than 2/3+1 miners who produced blocks in the current round also produced blocks in the previous round. This breaks finality guarantees, cross-chain operations, and eventually degrades blockchain performance to 1 block per mining slot.

## Finding Description

The vulnerability exists in the LIB calculation logic that determines blockchain finality. The calculation process has a critical design flaw in how it handles miners who skip rounds.

**Core Mechanism:**

When a miner produces a block in Round N, their `ImpliedIrreversibleBlockHeight` is set to the current block height: [1](#0-0) 

However, when generating the next round, new `MinerInRound` instances are created without copying this field, leaving it at the default value of 0: [2](#0-1) 

**LIB Calculation Vulnerability:**

During LIB calculation in Round N+1, the system:
1. Gets miners who produced blocks in the current round (N+1)
2. Fetches their `ImpliedIrreversibleBlockHeight` values from the previous round (N)
3. Applies a critical filter that excludes miners with value 0: [3](#0-2) 

4. Checks if remaining miners meet the 2/3+1 consensus threshold: [4](#0-3) 

5. Returns `libHeight = 0` if insufficient: [5](#0-4) 

6. The update check prevents LIB advancement when `libHeight = 0`: [6](#0-5) 

**Trigger Scenario:**

If more than 1/3 of miners who produce blocks in Round N+1 did NOT produce blocks in Round N (due to network issues, Byzantine behavior, or being new replacements), their `ImpliedIrreversibleBlockHeight` in Round N remains 0. After filtering, fewer than 2/3+1 miners remain, causing LIB to freeze.

## Impact Explanation

**HIGH Severity** due to multiple critical system failures:

**1. Cross-Chain Operations Failure**

The `IrreversibleBlockFound` event is the foundation for cross-chain indexing. When LIB freezes, this event stops firing, breaking all cross-chain synchronization and validation mechanisms that depend on finality guarantees.

**2. Finality Guarantees Compromised**

No new blocks become irreversible while LIB is frozen. All transactions remain in an unfinalized state indefinitely, violating the fundamental blockchain guarantee of eventual finality.

**3. Blockchain Performance Degradation**

The system monitors the gap between current round and LIB round to detect anomalies: [7](#0-6) 

As the gap increases beyond the threshold (typically 8 rounds), the blockchain enters Severe status, reducing maximum blocks count to 1: [8](#0-7) 

This cripples throughput from 8 blocks per slot to just 1 block per slot.

**4. Silent Failure Mode**

Block production continues normally, making the LIB freeze difficult to detect until cross-chain operations fail or applications explicitly check finality status.

## Likelihood Explanation

**MEDIUM to HIGH Likelihood**

**Legitimate Trigger Scenarios:**
- Network partitions causing >1/3 of miners to miss Round N while recovering for Round N+1 (common in distributed systems)
- System recovery after outages where miner participation patterns are naturally disrupted
- Term transitions with evil miner replacements where new miners lack previous round participation

**Byzantine Attack Scenario:**
- Requires coordination of >1/3 of miners to alternate participation between rounds
- Economic cost includes mining reward loss during skipped rounds
- Miners can sustain this for up to 3 days (4320 time slots) before being marked as evil: [9](#0-8) [10](#0-9) 

**Recovery Mechanism:**

While a circuit breaker exists to reset the chain when severe status is detected: [11](#0-10) 

This does NOT fix the frozen LIB itself—it only limits damage by preventing unbounded divergence. Recovery requires miner participation patterns to naturally stabilize.

## Recommendation

**Immediate Fix:** Modify the LIB calculation to handle edge cases where insufficient miners have valid `ImpliedIrreversibleBlockHeight` values:

1. **Option A - Fallback Calculation:** If fewer than `MinersCountOfConsent` miners have `ImpliedIrreversibleBlockHeight > 0`, use an alternative calculation based on all available miners rather than returning 0.

2. **Option B - Preserve Field in Round Generation:** Modify `GenerateNextRoundInformation` to copy `ImpliedIrreversibleBlockHeight` from miners in the current round to the next round, ensuring continuity.

3. **Option C - Relaxed Threshold:** During recovery scenarios (detected by extended LIB freeze), temporarily relax the consensus threshold to maintain LIB progression.

**Recommended Implementation (Option A):**

Modify `LastIrreversibleBlockHeightCalculator.Deconstruct()` to add fallback logic when the filtered count is insufficient, using a lower percentile from all available heights rather than returning 0.

## Proof of Concept

```csharp
// Conceptual test demonstrating the vulnerability
// Setup: 7 miners total, MinersCountOfConsent = 5

// Round N:
// - Miners {A, B, C, D} produce blocks (ImpliedIrreversibleBlockHeight set)
// - Miners {E, F, G} do NOT produce blocks (ImpliedIrreversibleBlockHeight = 0)

// Round N+1:
// - Miners {E, F, G, A} produce blocks (E, F, G recovered from network issue)
// - LIB calculation looks for ImpliedIrreversibleBlockHeight from Round N:
//   - E: 0 (filtered out)
//   - F: 0 (filtered out)  
//   - G: 0 (filtered out)
//   - A: [valid height]
// - Only 1 miner remains after filtering < MinersCountOfConsent (5)
// - Returns libHeight = 0
// - LIB update check: currentRound.ConfirmedIrreversibleBlockHeight < 0 is FALSE
// - LIB remains frozen at previous value
// - Cross-chain indexing stops
// - After 8+ rounds, blockchain enters Severe status (max 1 block per slot)
```

The proof demonstrates that when >1/3 of miners (3 out of 7) skip Round N but produce in Round N+1, the LIB calculation returns 0, freezing finality progression and triggering cascading system failures.

## Notes

This vulnerability represents a fundamental flaw in the LIB consensus mechanism's assumption that miner participation patterns remain stable across consecutive rounds. The filtering of zero values, while sensible for data integrity, creates a critical failure mode when combined with the consensus threshold check. The lack of explicit recovery mechanisms means the system relies entirely on natural stabilization, which may not occur promptly in adversarial scenarios or during extended network disruptions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-281)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L119-129)
```csharp
        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockHeightUnacceptableLogEventProcessor.cs (L54-64)
```csharp
        if (distanceToLib.DistanceToIrreversibleBlockHeight > 0)
        {
            Logger.LogDebug($"Distance to lib height: {distanceToLib.DistanceToIrreversibleBlockHeight}");
            Logger.LogDebug("Will rollback to lib height.");
            _taskQueueManager.Enqueue(
                async () =>
                {
                    var chain = await _blockchainService.GetChainAsync();
                    await _blockchainService.ResetChainToLibAsync(chain);
                }, KernelConstants.UpdateChainQueueName);
        }
```
