# Audit Report

## Title
Race Condition in Mining Order Assignment Causes Duplicate Orders and Block Production Conflicts

## Summary
The AEDPoS consensus mechanism contains a race condition where multiple miners can independently calculate and commit the same `FinalOrderOfNextRound` value when generating consensus commands from the same stale round state. This occurs because conflict resolution happens off-chain without subsequent on-chain re-validation, and the existing validation logic has a bug that fails to detect duplicate order values. The result is multiple miners receiving identical mining timestamps during round termination, causing blockchain forks and consensus degradation.

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Off-chain Conflict Resolution Without State Synchronization**

When miners call `GetConsensusCommand`, the `ApplyNormalConsensusData` method performs conflict resolution locally by checking for existing miners with the same `FinalOrderOfNextRound` and reassigning conflicted miners to different orders. [1](#0-0) 

However, this resolution operates on a local copy of the round state fetched at the time of the call. The results are packaged into `TuneOrderInformation` for later on-chain application. [2](#0-1) 

**2. No On-chain Conflict Re-validation**

When blocks are executed, `ProcessUpdateValue` directly sets each miner's `FinalOrderOfNextRound` to their `SupposedOrderOfNextRound` and applies the pre-calculated `TuneOrderInformation`. [3](#0-2) [4](#0-3) 

There is no re-validation to detect if the `TuneOrderInformation` was calculated based on stale state. If multiple miners calculated their orders from the same state before any blocks were executed, their pre-calculated conflict resolutions become invalid.

**3. Race Condition Scenario**

When two miners (A and B) call `GetConsensusCommand` before either has produced a block:

- Both fetch the same on-chain round state (e.g., all `FinalOrderOfNextRound = 0`)
- Both calculate the same `SupposedOrderOfNextRound` (e.g., 2) via hash modulo operation [5](#0-4) 
- Both see no conflicts locally (all others are 0), so both generate empty `TuneOrderInformation`
- When their blocks execute sequentially at different heights, both end up with `FinalOrderOfNextRound = 2`

**4. Failed Validation**

The `NextRoundMiningOrderValidationProvider` has a critical bug. It calls `.Distinct()` on `MinerInRound` objects rather than on their `FinalOrderOfNextRound` values. [6](#0-5) 

Since `MinerInRound` is a protobuf-generated class without custom equality implementation, each miner object is considered distinct regardless of having identical order values. This validation only checks that the count of miners who determined orders matches those who mined, not that all orders are unique.

**5. Propagation to Next Round and Timestamp Collision**

When the next round is generated, miners are ordered by `FinalOrderOfNextRound`, and each miner's `Order` in the new round is set to their `FinalOrderOfNextRound` value. [7](#0-6) 

Miners with duplicate `Order` values then calculate identical timestamps in `ArrangeAbnormalMiningTime` (used for extra block production during round termination), as the timestamp is directly computed from the `Order` field. [8](#0-7) 

This method is invoked via `TerminateRoundCommandStrategy` for round termination. [9](#0-8) [10](#0-9) 

## Impact Explanation

**Consensus Integrity Impact:**
- Multiple miners receive identical mining timestamps for round termination blocks
- Both attempt to produce extra blocks at the exact same time, creating competing blocks
- Results in temporary blockchain forks during round transitions
- Network must resolve the fork through normal consensus mechanisms
- Increases orphaned blocks and reduces consensus efficiency

**Operational Impact:**
- Degraded network performance during round transitions
- Wasted computational resources on orphaned blocks
- Potential for extended fork resolution if multiple miner pairs have conflicts
- Confusion in block explorers and monitoring tools showing competing chains

**Severity Justification:**
This violates the critical invariant for "Correct round transitions and time-slot validation, miner schedule integrity" in the consensus requirements. While it doesn't directly enable fund theft, it significantly degrades consensus quality and causes recurring operational disruptions during affected round transitions. The impact is HIGH for consensus integrity.

## Likelihood Explanation

**Attack Complexity: LOW**
- No malicious intent required - this is a natural race condition
- Occurs probabilistically during normal mining operations
- Entry point is the public `GetConsensusCommand` method that all miners regularly call

**Feasibility Conditions:**

1. **Hash Collision Probability**: The `SupposedOrderOfNextRound` is calculated via `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [11](#0-10)  With N miners, the probability of two miners calculating the same order is approximately 1/N per pair. For 21 miners (typical mainnet configuration), this is ~4.7% per pair, making conflicts expected to occur regularly.

2. **Timing Window**: Miners naturally generate consensus commands within the same round before blocks propagate. Network latency (100-500ms typical) provides a realistic window where multiple miners fetch the same round state before any updates are committed.

3. **Sequential Block Execution**: Both blocks can be in the canonical chain at different heights (e.g., height H and H+1), which is the normal case - they don't need to be competing forks at the same height for the race condition to manifest.

**Detection Constraints:**
- Difficult to detect in advance as it depends on timing and hash distribution
- Manifests as observable forks during round termination
- May appear as "normal" temporary forks to observers

**Probability Assessment: MEDIUM-HIGH**
Given the hash collision probability and typical network conditions, duplicate orders are expected to occur periodically, making scheduling conflicts and resulting forks a recurring operational issue rather than a rare event.

## Recommendation

**Fix 1: Add On-chain Conflict Re-validation**

In `ProcessUpdateValue`, add validation to detect and reject blocks that would create duplicate `FinalOrderOfNextRound` values:

```csharp
// After line 247, before applying TuneOrderInformation:
// Check if this miner's order conflicts with existing orders
var conflictingMiner = currentRound.RealTimeMinersInformation.Values
    .FirstOrDefault(m => m.Pubkey != _processingBlockMinerPubkey && 
                         m.FinalOrderOfNextRound == updateValueInput.SupposedOrderOfNextRound);
if (conflictingMiner != null)
{
    Assert(false, $"Order conflict: {_processingBlockMinerPubkey} and {conflictingMiner.Pubkey} both have order {updateValueInput.SupposedOrderOfNextRound}");
}
```

**Fix 2: Correct the Validation Logic**

Fix the `NextRoundMiningOrderValidationProvider` to actually check for duplicate order values:

```csharp
var minersWithOrders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0).ToList();
var distinctOrderCount = minersWithOrders
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct().Count();
if (distinctOrderCount != minersWithOrders.Count)
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

**Fix 3: Alternative - Deterministic Order Assignment**

Instead of allowing miners to independently calculate orders, have the contract deterministically assign orders based on a combination of block height and miner pubkey, eliminating the possibility of conflicts.

## Proof of Concept

A complete PoC would require a multi-node testnet environment to reproduce the race condition timing. The test would:

1. Set up 21 miner nodes
2. Ensure miners A and B have signature hashes that modulo to the same value
3. Trigger both miners to call `GetConsensusCommand` simultaneously before any blocks are produced
4. Verify both miners commit blocks with `SupposedOrderOfNextRound = X` and empty `TuneOrderInformation`
5. Verify on-chain state shows both miners with `FinalOrderOfNextRound = X`
6. Advance to next round and verify both miners receive identical timestamps from `ArrangeAbnormalMiningTime`
7. Observe fork when both miners attempt to produce extra blocks simultaneously

The core vulnerable flow can be demonstrated by:
- Examining the on-chain state after multiple miners produce blocks in the same round
- Checking for duplicate `FinalOrderOfNextRound` values
- Monitoring for forks during round termination when such duplicates exist

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-40)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L36-36)
```csharp
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L25-26)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L22-24)
```csharp
        public static Timestamp ArrangeExtraBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return round.ArrangeAbnormalMiningTime(pubkey, currentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```
