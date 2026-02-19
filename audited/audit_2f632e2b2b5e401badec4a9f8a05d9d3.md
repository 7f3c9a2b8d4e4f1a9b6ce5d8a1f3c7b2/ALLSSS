### Title
Side Chain Round Termination Delay When Extra Block Time Slot Expires

### Summary
When all miners in a side chain round have completed mining their maximum blocks and the extra block producer's time slot (including grace period) has expired, the consensus mechanism schedules the round termination for a future round's timeline rather than immediately. This creates a deterministic gap period where no new blocks can be produced, causing temporary chain stall until the scheduled future time arrives.

### Finding Description

The issue occurs in the side chain consensus behavior and mining time arrangement logic: [1](#0-0) 

For side chains, `GetConsensusBehaviourToTerminateCurrentRound()` correctly returns `NextRound` behavior. However, the mining time scheduling in `ArrangeAbnormalMiningTime()` contains the problematic logic: [2](#0-1) 

**Root Cause:**
When the extra block producer (or any miner) calls `GetConsensusBehaviour()` after all miners have mined their maximum blocks and time slots have passed:

1. Lines 26-30 check if the current time is within the extra block time plus one mining interval (grace period)
2. If `currentBlockTime > GetExtraBlockMiningTime() + miningInterval`, the distance check fails and execution falls through to lines 33-36
3. Lines 33-36 calculate a future round start time and schedule the miner based on their order in the NEXT round
4. This scheduling is done via `CalculateFutureRoundStartTime()`: [3](#0-2) 

The scheduled time becomes: `Round2Start + (minerOrder * miningInterval)`, which is guaranteed to be in the future, creating a gap.

**Why Protections Fail:**
The consensus behavior determination in the base class correctly identifies that round termination is needed: [4](#0-3) 

However, when `TerminateRoundCommandStrategy` is created, it calls `ArrangeExtraBlockMiningTime()`: [5](#0-4) 

This schedules the miner at the calculated future time rather than allowing immediate round termination. The mining service strictly follows this schedule and will not attempt mining until the scheduled time arrives, even though `IsCurrentMiner()` would validate the extra block producer immediately: [6](#0-5) 

### Impact Explanation

**Operational Impact - Temporary Chain Stall:**
- When this condition occurs, NO new blocks can be produced on the side chain during the gap period
- All miners receive `NextRound` behavior but are scheduled for future times (minimum one mining interval away, potentially much longer if significantly delayed)
- The first miner by order is scheduled at: `NextRoundStartTime + (1 * miningInterval)`
- Gap duration = `NextRoundStartTime + miningInterval - currentBlockTime`, which is at least one mining interval

**Affected Operations:**
- User transactions cannot be processed
- Cross-chain operations are delayed
- Time-sensitive smart contract logic stalls
- Side chain dividend releases (triggered during consensus processing) are delayed: [7](#0-6) 

**Recovery:**
The system automatically recovers when the first scheduled miner's time arrives and they successfully produce the NextRound block. If that miner fails, subsequent miners will attempt at their scheduled times.

**Severity Justification:**
Low severity due to:
- Temporary impact (auto-recovers)
- No fund loss or theft
- No permanent state corruption
- Deterministic behavior (not random failure)
- By-design handling of missed rounds (though suboptimal)

### Likelihood Explanation

**Feasible Preconditions:**
- All miners must complete mining their maximum blocks (`ActualMiningTimes.Count >= maximumBlocksCount`)
- Extra block producer's designated time slot must pass
- Grace period (one additional mining interval) must also expire
- This can occur when: extra block producer experiences network delays, node goes offline temporarily, or system experiences high latency

**Attack Complexity:**
This is not an attack - it's an operational edge case that can occur naturally during normal side chain operation. No malicious action required.

**Execution Practicality:**
Highly practical - occurs automatically when timing conditions are met. Common scenarios:
- Network partition affecting extra block producer
- Extra block producer node maintenance/restart
- High network latency during block propagation
- System resource contention on producer node

**Probability:**
Medium probability in production environments where:
- Network conditions are not perfect
- Nodes may experience temporary issues
- Multiple side chains increase surface area for occurrence

### Recommendation

**Code-Level Mitigation:**
Modify `ArrangeAbnormalMiningTime()` to allow immediate scheduling when all miners have completed mining:

1. Add a check before the future round calculation to detect if all miners have finished
2. If the extra block producer's time has passed but they're still within a reasonable window (e.g., 2-3 mining intervals), schedule them immediately rather than for next round
3. Alternatively, modify the grace period calculation to be more generous

Example mitigation in `Round_ArrangeAbnormalMiningTime.cs`:
```csharp
// After line 26, add extended grace period check:
if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
{
    var extendedGracePeriod = miningInterval * 3; // Allow 3 intervals instead of 1
    var distance = (GetExtraBlockMiningTime().AddMilliseconds(extendedGracePeriod) - currentBlockTime)
        .Milliseconds();
    if (distance > 0) return GetExtraBlockMiningTime();
}
```

**Invariant Checks:**
Add monitoring to detect when round termination is delayed:
- Track time between last miner's block and NextRound block
- Alert if gap exceeds expected threshold
- Log when ArrangeAbnormalMiningTime schedules for future round

**Test Cases:**
1. Test case: All miners complete mining, extra block time expires by exactly 1 interval - verify immediate termination
2. Test case: Extra block producer delayed by 2+ intervals - verify reasonable recovery time
3. Test case: Extra block producer offline - verify backup miners can terminate round within acceptable timeframe
4. Integration test: Simulate network delays and verify side chain continues producing blocks without significant gaps

### Proof of Concept

**Required Initial State:**
- Side chain with N miners (e.g., N=5)
- Current round in progress
- Mining interval = 4000ms
- Maximum blocks count = 8

**Transaction Steps:**
1. All 5 miners produce their regular blocks at their designated time slots
2. Each miner produces 8 blocks (reaching maximumBlocksCount)
3. Time advances past all regular time slots: `currentTime = RoundStart + (5 * 4000ms)`
4. Extra block time arrives: `extraBlockTime = RoundStart + (6 * 4000ms)` 
5. Extra block producer is delayed due to network issues
6. Time advances further: `currentTime = RoundStart + (7.5 * 4000ms)` (beyond grace period)
7. Extra block producer (or any miner) calls `GetConsensusCommand()`

**Expected vs Actual Result:**

Expected (ideal behavior):
- `ArrangeAbnormalMiningTime()` schedules NextRound block immediately or within minimal delay
- Round terminates promptly
- New round begins and mining continues

Actual (current behavior):
- `ArrangeAbnormalMiningTime()` calculates: `distance = (24000 + 4000 - 30000) = -2000` (negative, fails check at line 30)
- Falls through to future round calculation at lines 33-36
- Schedules miner at: `(RoundStart + 28000) + (Order * 4000)` for next round
- For Order=1: scheduled at `RoundStart + 32000ms`
- Current time is `RoundStart + 30000ms`
- Gap of 2000ms (0.5 mining intervals) where no blocks are produced

**Success Condition:**
Chain stalls for at least 2000ms, then resumes when Order=1 miner's scheduled time arrives and they produce the NextRound block.

### Notes

This finding represents an operational inefficiency in the side chain consensus mechanism rather than a critical security vulnerability. The system is designed to eventually recover through its built-in redundancy (multiple miners can terminate the round), but the forced delay to future round scheduling creates unnecessary downtime. The issue is most pronounced when the extra block producer experiences delays beyond the grace period, which can realistically occur in distributed systems with network variability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L16-23)
```csharp
        /// <summary>
        ///     Simply return NEXT_ROUND for side chain.
        /// </summary>
        /// <returns></returns>
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L26-36)
```csharp
        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
        }

        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L51-58)
```csharp
    private Timestamp CalculateFutureRoundStartTime(long missedRoundsCount = 0, int miningInterval = 0)
    {
        if (miningInterval == 0)
            miningInterval = GetMiningInterval();

        var totalMilliseconds = TotalMilliseconds(miningInterval);
        return GetRoundStartTime().AddMilliseconds(missedRoundsCount.Add(1).Mul(totalMilliseconds));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L39-83)
```csharp
        public AElfConsensusBehaviour GetConsensusBehaviour()
        {
            // The most simple situation: provided pubkey isn't a miner.
            // Already checked in GetConsensusCommand.
//                if (!CurrentRound.IsInMinerList(_pubkey))
//                {
//                    return AElfConsensusBehaviour.Nothing;
//                }

            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
            }

            return GetConsensusBehaviourToTerminateCurrentRound();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L23-39)
```csharp
        public override ConsensusCommand GetAEDPoSConsensusCommand()
        {
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint
                    {
                        Behaviour = _isNewTerm ? AElfConsensusBehaviour.NextTerm : AElfConsensusBehaviour.NextRound
                    }
                    .ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                MiningDueTime = arrangedMiningTime.AddMilliseconds(MiningInterval),
                LimitMillisecondsOfMiningBlock =
                    _isNewTerm ? LastBlockOfCurrentTermMiningLimit : DefaultBlockMiningLimit
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L172-178)
```csharp
        // Check extra block time slot.
        if (Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime() &&
            supposedExtraBlockProducer == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]EXTRA");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L102-122)
```csharp
    public void Release()
    {
        if (State.TokenHolderContract.Value == null) return;
        var scheme = State.TokenHolderContract.GetScheme.Call(Context.Self);
        var isTimeToRelease =
            (Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.PeriodSeconds.Value) > scheme.Period - 1;
        Context.LogDebug(() => "ReleaseSideChainDividendsPool Information:\n" +
                               $"CurrentBlockTime: {Context.CurrentBlockTime}\n" +
                               $"BlockChainStartTime: {State.BlockchainStartTimestamp.Value}\n" +
                               $"PeriodSeconds: {State.PeriodSeconds.Value}\n" +
                               $"Scheme Period: {scheme.Period}");
        if (isTimeToRelease)
        {
            Context.LogDebug(() => "Ready to release side chain dividends pool.");
            State.TokenHolderContract.DistributeProfits.Send(new DistributeProfitsInput
            {
                SchemeManager = Context.Self
            });
        }
    }
```
