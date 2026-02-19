### Title
Hardcoded TinyBlocksCount Breaks Block Production Time Calculations During Blockchain Degradation

### Summary
The `TinyBlocksCount = 8` constant in `CommandStrategyBase` is used to calculate block production time limits, but the actual maximum tiny blocks count is dynamically adjusted (can be reduced to 1) based on blockchain health. This inconsistency causes miners to receive only 1/8th of the required block production time during severe blockchain degradation, severely hampering recovery and potentially causing a denial-of-service condition in consensus.

### Finding Description

The root cause is a hardcoded constant that does not account for dynamic blockchain health adjustments: [1](#0-0) 

This hardcoded value is used to calculate time slot intervals: [2](#0-1) 

And subsequently the block mining time limits: [3](#0-2) [4](#0-3) 

However, the actual maximum tiny blocks count is dynamically calculated based on blockchain health status: [5](#0-4) 

In Severe status (when irreversible block height falls too far behind), the function returns 1: [6](#0-5) 

In Abnormal status, it returns a reduced count (typically 2-7): [7](#0-6) 

The dynamic value is passed to `TinyBlockCommandStrategy`: [8](#0-7) 

However, `TinyBlockCommandStrategy` only uses this dynamic value to determine if it's the last tiny block: [9](#0-8) 

The time limits still use the base class's hardcoded calculation: [10](#0-9) 

This time limit is enforced as a hard timeout during block execution via `CancellationTokenSource`: [11](#0-10) [12](#0-11) 

### Impact Explanation

**Concrete Harm:**
When the blockchain enters degraded health status (Abnormal or Severe), the dynamic adjustment mechanism reduces the maximum tiny blocks count to help the system recover. However, the time limit calculations remain based on the hardcoded value of 8, creating a severe operational impact:

**Quantified Impact:**
- **Severe Status Example**: With `MiningInterval = 4000ms`:
  - Expected: 1 block allowed, should get `4000ms * 3/5 = 2400ms` execution time
  - Actual: Still calculates `4000ms / 8 * 3/5 = 300ms` execution time
  - **Result: Miners get only 12.5% (1/8th) of required time**

- **Abnormal Status Example**: With maximum blocks reduced to 4:
  - Expected: Each block should get `1000ms * 3/5 = 600ms` execution time
  - Actual: Still gets `500ms * 3/5 = 300ms` execution time
  - **Result: Miners get only 50% of required time**

**Who is Affected:**
All miners attempting to produce blocks during blockchain degradation. The entire network suffers as the consensus mechanism cannot recover effectively.

**Severity Justification:**
This creates a **consensus denial-of-service condition** where the system's self-healing mechanism is sabotaged by its own time limit calculations. During the exact moments when the blockchain needs MORE time to recover (Severe/Abnormal status), miners are given LESS time, making recovery significantly harder or impossible. This can lead to prolonged blockchain stalls.

### Likelihood Explanation

**Trigger Conditions:**
The vulnerability activates automatically when blockchain health degrades, specifically when:
- Last Irreversible Block (LIB) round number + 2 < Current round number (Abnormal status)
- LIB round number + 8 <= Current round number (Severe status) [13](#0-12) 

**No Attack Required:**
This occurs during normal blockchain operation when:
- Network latency increases
- Miners experience temporary downtime
- Transaction processing slows down
- Any condition causing blocks to fall behind

**Probability:**
**High probability** in production environments with:
- Network congestion
- Geographic distribution of miners
- Variable computational loads
- Any real-world network conditions that cause temporary synchronization issues

**Detection:**
The system fires an `IrreversibleBlockHeightUnacceptable` event when entering Severe status: [14](#0-13) 

However, the insufficient time limits make recovery difficult even after detection.

### Recommendation

**Code-Level Mitigation:**

Replace the hardcoded `TinyBlocksCount` with a dynamic parameter in `CommandStrategyBase`. Modify the constructor to accept the actual maximum blocks count:

1. Add a field in `CommandStrategyBase` to store the dynamic maximum blocks count
2. Pass the result of `GetMaximumBlocksCount()` to all strategy constructors
3. Use this dynamic value instead of the hardcoded constant in time calculations

**Specific Changes:**

In `CommandStrategyBase.cs`:
- Remove the hardcoded `const int TinyBlocksCount = 8`
- Add a protected field: `protected readonly int MaximumBlocksCount`
- Update constructor to accept this parameter
- Change `TinyBlockSlotInterval` calculation to use the dynamic value

In all strategy classes (`TinyBlockCommandStrategy`, `NormalBlockCommandStrategy`, `TerminateRoundCommandStrategy`, `FirstRoundCommandStrategy`):
- Update constructors to accept and pass the maximum blocks count to base class

In `AEDPoSContract_GetConsensusCommand.cs`:
- Pass `GetMaximumBlocksCount()` result to all strategy constructors

**Invariant Checks:**
Add assertion: `TinyBlockSlotInterval > 0` and `DefaultBlockMiningLimit >= TinyBlockMinimumInterval` to ensure time calculations remain valid.

**Test Cases:**
1. Test block production time limits when `GetMaximumBlocksCount()` returns 1 (Severe status)
2. Test block production time limits when `GetMaximumBlocksCount()` returns reduced values (Abnormal status)
3. Verify miners have sufficient time to produce blocks during degraded blockchain health
4. Test that blockchain can recover from Severe status with corrected time limits

### Proof of Concept

**Initial State:**
1. Blockchain operating normally with 17 miners
2. `MiningInterval = 4000ms` (typical production value)
3. Normal status: `GetMaximumBlocksCount()` returns 8

**Degradation Sequence:**
1. Network latency increases, causing miners to miss time slots
2. Last Irreversible Block (LIB) falls 8+ rounds behind current round
3. `GetMaximumBlocksCount()` enters Severe status and returns 1
4. System fires `IrreversibleBlockHeightUnacceptable` event

**Vulnerability Trigger:**
1. Miner calls `GetConsensusCommand()` for tiny block production
2. `TinyBlockCommandStrategy` is created with `_maximumBlocksCount = 1`
3. But `TinyBlockSlotInterval` is still calculated as `4000 / 8 = 500ms`
4. `DefaultBlockMiningLimit` becomes `500 * 3 / 5 = 300ms`
5. This 300ms limit is passed to `MiningService.MineAsync()`
6. `CancellationTokenSource` timeout is set to 300ms
7. Block execution is cancelled after 300ms, even though miner should have 2400ms

**Expected vs Actual:**
- **Expected**: In Severe status with 1 block allowed, miner should get `4000ms * 3/5 = 2400ms` execution time
- **Actual**: Miner gets only `300ms` execution time (8x less than needed)

**Success Condition for Exploit:**
Blockchain remains in degraded state because miners timeout while producing recovery blocks, creating a self-perpetuating denial-of-service condition where the system cannot recover from Severe status.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-79)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");

        // If R_LIB + 2 < R < R_LIB + CB1, CB goes to Min(T(L2 * (CB1 - (R - R_LIB)) / A), CB0), while CT stays same as before.
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

        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
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

        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;

        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L122-128)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L48-50)
```csharp
                    LimitMillisecondsOfMiningBlock = IsLastTinyBlockOfCurrentSlot()
                        ? LastTinyBlockMiningLimit
                        : DefaultBlockMiningLimit
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
