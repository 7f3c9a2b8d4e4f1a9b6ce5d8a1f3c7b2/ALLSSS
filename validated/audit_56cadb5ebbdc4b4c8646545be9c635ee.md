# Audit Report

## Title
Hardcoded TinyBlocksCount Breaks Block Production Time Calculations During Blockchain Degradation

## Summary
The AEDPoS consensus contract uses a hardcoded constant `TinyBlocksCount = 8` to calculate block execution time limits, but the actual maximum tiny blocks count is dynamically adjusted (reduced to 1-7) based on blockchain health. This mismatch causes miners to receive grossly insufficient execution time during degraded blockchain conditions, severely hampering recovery and creating a consensus denial-of-service condition.

## Finding Description

The vulnerability stems from a design inconsistency between dynamic block count adjustment and static time limit calculation.

The `CommandStrategyBase` class defines a hardcoded constant that assumes 8 tiny blocks per time slot: [1](#0-0) 

This hardcoded value is used to calculate the time slot interval and subsequently the block mining time limits: [2](#0-1) [3](#0-2) [4](#0-3) 

However, the actual maximum tiny blocks count is dynamically calculated based on blockchain health. In Severe status (when the irreversible block falls critically behind), it returns only 1 block: [5](#0-4) 

In Abnormal status, it returns a reduced count between 2-7: [6](#0-5) 

This dynamic value is passed to `TinyBlockCommandStrategy`: [7](#0-6) 

However, `TinyBlockCommandStrategy` only uses this dynamic value to determine whether the current block is the last one, not to recalculate time limits: [8](#0-7) [9](#0-8) 

The time limits still use the base class's calculation based on hardcoded `TinyBlocksCount = 8`. These limits are enforced as hard timeouts during block execution: [10](#0-9) [11](#0-10) [12](#0-11) 

The developers demonstrate awareness that different consensus behaviors should receive proportional time allocations - `TerminateRoundCommandStrategy` for NEXT_TERM blocks correctly uses the full `MiningInterval`: [13](#0-12) 

This proves that time limits should scale with behavior changes, but this scaling is absent for degraded blockchain states.

## Impact Explanation

**Critical Consensus Availability Failure**: When the blockchain enters Severe status (LIB falls 8+ rounds behind), the system attempts recovery by reducing maximum blocks to 1. However, that single block receives only `(MiningInterval / 8) * 3/5` execution time instead of the proportionally correct `MiningInterval * 3/5`.

**Quantified Impact Example**:
- `MiningInterval = 4000ms`
- `TinyBlockSlotInterval = 4000 / 8 = 500ms` (always divides by hardcoded 8)
- `DefaultBlockMiningLimit = 500 * 3/5 = 300ms`
- Expected for single block: `4000 * 3/5 = 2400ms`
- **Actual allocation: 300ms (12.5% of required time)**

**Who Is Affected**: All miners and the entire network. During degraded conditions when recovery is most critical, miners cannot execute blocks within the timeout window, preventing the blockchain from recovering from temporary synchronization issues.

**Severity**: This creates a **consensus denial-of-service condition** where the system's self-healing mechanism undermines itself. The exact moment when MORE execution time is needed for recovery, the system provides LESS time, potentially causing prolonged or permanent blockchain stalls.

## Likelihood Explanation

**Automatic Trigger**: The vulnerability activates automatically when blockchain health degrades: [14](#0-13) 

**No Attack Required**: Occurs during normal blockchain operation when:
- Network latency temporarily increases
- Miners experience brief downtime
- Geographic distribution causes synchronization delays
- Transaction processing temporarily slows

**High Probability**: In production environments with:
- Variable network conditions
- Distributed miner geography
- Fluctuating computational loads
- Any real-world network variability

The system fires an event to detect Severe status, but insufficient time limits prevent effective recovery: [15](#0-14) 

## Recommendation

Modify `CommandStrategyBase` or `TinyBlockCommandStrategy` to calculate time limits based on the actual maximum blocks count, not a hardcoded constant.

**Option 1**: Pass `maximumBlocksCount` to `CommandStrategyBase` constructor and use it in time calculations:

```csharp
private int TinyBlockSlotInterval => MiningInterval.Div(_actualMaximumBlocksCount);
```

**Option 2**: Override time limit calculation in `TinyBlockCommandStrategy`:

```csharp
protected int AdjustedBlockMiningLimit => 
    MiningInterval.Div(_maximumBlocksCount).Mul(3).Div(5);
```

Then use `AdjustedBlockMiningLimit` instead of `DefaultBlockMiningLimit` in the consensus command.

The fix should ensure that when `maximumBlocksCount = 1`, the single block receives proportionally more execution time, similar to how `LastBlockOfCurrentTermMiningLimit` handles NEXT_TERM blocks.

## Proof of Concept

The vulnerability can be demonstrated by monitoring block execution during Severe status:

1. Trigger Severe status by causing LIB to fall 8+ rounds behind current round
2. Observe `GetMaximumBlocksCount()` returns 1
3. Observe `TinyBlockCommandStrategy` sets `LimitMillisecondsOfMiningBlock = 300ms` (with 4000ms MiningInterval)
4. Observe `MiningService` creates `CancellationTokenSource` with 300ms timeout
5. Observe block execution times out before completion, preventing recovery
6. Expected: Single block should receive ~2400ms execution time for effective recovery

The test would verify that during Severe status:
```csharp
var maxBlocks = consensus.GetMaximumBlocksCount(); // Returns 1
var command = consensus.GetConsensusCommand(TinyBlock);
var expectedTime = miningInterval * 3 / 5; // 2400ms
var actualTime = command.LimitMillisecondsOfMiningBlock; // 300ms
Assert.True(actualTime < expectedTime / 5); // Proves insufficient time allocation
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L17-17)
```csharp
        private const int TinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L42-42)
```csharp
        private int TinyBlockSlotInterval => MiningInterval.Div(TinyBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L49-49)
```csharp
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L54-54)
```csharp
        protected int LastTinyBlockMiningLimit => TinyBlockSlotInterval.Div(2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L57-60)
```csharp
        ///     If this block is of consensus behaviour NEXT_TERM, the producing time is MiningInterval,
        ///     so the limitation of mining is 8 times than DefaultBlockMiningLimit.
        /// </summary>
        protected int LastBlockOfCurrentTermMiningLimit => MiningInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-55)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L123-128)
```csharp
            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L48-50)
```csharp
                var consensusCommand =
                    new ConsensusCommandProvider(new TinyBlockCommandStrategy(currentRound, pubkey,
                        currentBlockTime, GetMaximumBlocksCount())).GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L48-51)
```csharp
                    LimitMillisecondsOfMiningBlock = IsLastTinyBlockOfCurrentSlot()
                        ? LastTinyBlockMiningLimit
                        : DefaultBlockMiningLimit
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L54-63)
```csharp
        private bool IsLastTinyBlockOfCurrentSlot()
        {
            var producedBlocksOfCurrentRound = MinerInRound.ProducedTinyBlocks;
            var roundStartTime = CurrentRound.GetRoundStartTime();

            if (CurrentBlockTime < roundStartTime) return producedBlocksOfCurrentRound == _maximumBlocksCount;

            var blocksBeforeCurrentRound = MinerInRound.ActualMiningTimes.Count(t => t < roundStartTime);
            return producedBlocksOfCurrentRound == blocksBeforeCurrentRound.Add(_maximumBlocksCount);
        }
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L50-62)
```csharp
            using var cts = new CancellationTokenSource();
            var expirationTime = blockTime + requestMiningDto.BlockExecutionTime;
            if (expirationTime < TimestampHelper.GetUtcNow())
            {
                cts.Cancel();
            }
            else
            {
                var ts = (expirationTime - TimestampHelper.GetUtcNow()).ToTimeSpan();
                if (ts.TotalMilliseconds > int.MaxValue) ts = TimeSpan.FromMilliseconds(int.MaxValue);

                cts.CancelAfter(ts);
            }
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L77-78)
```csharp
            var blockExecutedSet = await _blockExecutingService.ExecuteBlockAsync(block.Header,
                systemTransactions, pending, cts.Token);
```
