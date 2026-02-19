### Title
Extra Block Producer Scheduled Multiple Rounds Ahead, Causing Invalid Round Skipping and Consensus Delay

### Summary
The `ArrangeAbnormalMiningTime` function contains a flawed missed-rounds calculation that schedules the extra block producer multiple rounds in the future when they are late by more than one round duration. This bypasses the intended immediate round termination mechanism, effectively skipping rounds and causing significant consensus delays or stalls.

### Finding Description

The vulnerability exists in the `ArrangeAbnormalMiningTime` function's fallback logic when the extra block producer misses their time slot. [1](#0-0) 

**Root Cause**: When the extra block producer is late beyond their grace period (`distance <= 0` at line 30), the early return is skipped and execution falls through to the general missed-rounds calculation (lines 33-36). This calculation computes:

```
missedRoundsCount = (currentBlockTime - RoundStartTime) / TotalRoundDuration
futureRoundStartTime = RoundStartTime + (missedRoundsCount + 1) * TotalRoundDuration
```

The formula `(missedRoundsCount + 1)` causes the arranged time to skip rounds. When `currentBlockTime` exceeds `RoundStartTime + TotalRoundDuration`, `missedRoundsCount` becomes >= 1, scheduling the extra block producer in round N+2 or beyond instead of terminating the current round N.

**Example Scenario**:
- Round 2 duration: 24,000ms (start: T=24000, end: T=48000)
- Extra block time: T=44000
- Current time: T=50000 (6000ms past round end)
- Calculation: `missedRoundsCount = (50000-24000)/24000 = 1`
- Arranged time: `24000 + (1+1)*24000 = 72000` (round 4 start)
- **Result**: Round 3 is completely skipped [2](#0-1) 

The `CalculateFutureRoundStartTime` implementation confirms this formula, using `(missedRoundsCount + 1)` as the multiplier.

**Why Existing Protections Fail**: 

The early return protection at line 30 only works when the extra block producer is within the grace period. Once `distance <= 0`, no mechanism prevents the round-skipping calculation from executing. The function comment states it should give a time slot "for terminating current round", but the implementation violates this when delays are significant. [3](#0-2) 

**Execution Path**: This function is called during consensus command generation when the extra block producer needs to terminate a round: [4](#0-3) 

The command is generated through the public `GetConsensusCommand` method when behavior is determined as NextRound or NextTerm. [5](#0-4) 

### Impact Explanation

**Consensus/Cross-Chain Integrity Violation**: The core consensus invariant of correct round transitions is broken. Rounds are not properly terminated in sequence, causing:

1. **Invalid Round Skipping**: Intermediate rounds (e.g., round 3 in the example) are never properly terminated by the designated extra block producer
2. **Consensus State Inconsistency**: The round stored in state may not match the actual time-based round progression
3. **Miner Schedule Disruption**: Miners waiting for their turn in the skipped round cannot produce blocks

**Operational DoS**: The blockchain consensus progression can stall indefinitely:
- If the extra block producer continues to be delayed, the scheduled time keeps jumping further ahead
- Other miners cannot proceed until the current round is terminated
- Network block production halts or becomes severely degraded

**Severity Justification**: This is a **High** severity issue because:
- It directly compromises the fundamental consensus mechanism (round termination)
- It can cause network-wide operational disruption
- The extra block producer role is critical for consensus progression
- No remediation mechanism exists once the round-skipping calculation occurs

**Affected Parties**: All network participants (miners, transaction submitters, dApp users) are impacted by consensus stalls and invalid round progression.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability is triggered through the standard consensus command generation flow when any miner requests their next mining command via the public `GetConsensusCommand` method. [6](#0-5) 

**Feasible Preconditions**: 
- The extra block producer must miss their time slot by more than `ExtraBlockMiningTime + MiningInterval`
- Current time must exceed `RoundStartTime + TotalRoundDuration`
- This can occur through:
  1. Natural network delays/latency spikes exceeding one round duration (~24 seconds typical)
  2. Temporary node downtime or connectivity issues
  3. Malicious behavior by a compromised extra block producer intentionally delaying

**Execution Practicality**: 
- No special privileges required beyond being selected as extra block producer (normal rotation)
- The `missedRoundsCount` calculation is deterministic and automatic
- Attack complexity is **Low** - simply delay block production past the threshold

**Economic Rationality**: 
- For malicious actors: Disrupting consensus has strategic value (competitor sabotage, ransom scenarios)
- Attack cost is minimal - just refusing to produce blocks on time
- For natural occurrence: Zero cost - happens due to network/operational issues

**Detection Constraints**: 
- The scheduled time is returned in the consensus command, but validators don't check if it skips rounds
- No validation prevents accepting blocks that terminate rounds out of sequence
- The issue may go undetected until significant consensus stalls occur

**Probability Assessment**: **Medium-High**
- Natural occurrence probability increases with network load and geographic distribution
- In production with typical mining intervals (4000ms) and round durations (~24000ms), a 24-second delay triggers the bug
- Intentional exploitation requires only control of one extra block producer slot (rotates among miners)

### Recommendation

**Code-Level Mitigation**:

Modify `ArrangeAbnormalMiningTime` to cap the scheduled time within the current round, even when the extra block producer is late:

```csharp
if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
{
    var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
        .Milliseconds();
    if (distance > 0) return GetExtraBlockMiningTime();
    
    // NEW: If late, schedule immediately in current round instead of skipping ahead
    return currentBlockTime.AddMilliseconds(miningInterval);
}
```

**Invariant Checks to Add**:

1. In consensus command generation, validate that `ArrangedMiningTime` does not exceed `CurrentRoundEndTime + grace_period`
2. Add assertion in `ProcessNextRound` to ensure the transition is from round N to N+1, never skipping
3. Implement validation that the extra block producer's scheduled time is within reasonable bounds of current round [7](#0-6) 

**Test Cases**:

1. Test extra block producer delayed by 1.5x round duration - verify no round skipping
2. Test extra block producer delayed by multiple round durations - verify graceful degradation
3. Test rapid-fire delayed terminations - verify rounds process in sequence
4. Negative test: verify malicious extra block producer cannot intentionally skip rounds

### Proof of Concept

**Initial State**:
- Round 2 active (RoundNumber = 2)
- Round duration: 24,000ms (5 miners × 4000ms + 4000ms extra)
- Round 2 start time: T = 24,000ms
- Round 2 expected end: T = 48,000ms
- Extra block producer mining time: T = 44,000ms (5th slot)
- Current blockchain time: T = 50,000ms (6000ms past round end)

**Transaction Steps**:

1. Extra block producer requests consensus command at T=50,000ms
2. System calls `GetConsensusCommand` → determines behavior as `NextRound`
3. `TerminateRoundCommandStrategy` calls `ArrangeExtraBlockMiningTime`
4. `ArrangeAbnormalMiningTime` executes with `currentBlockTime = 50,000ms`

**Actual Result** (Vulnerable Code):
```
distance = (44000 + 4000) - 50000 = -2000
Early return skipped (distance <= 0)
distanceToRoundStartTime = 50000 - 24000 = 26000
missedRoundsCount = 26000 / 24000 = 1
futureRoundStartTime = 24000 + (1+1) * 24000 = 72000
arrangedTime = 72000 + (order * 4000) = ~84000ms (Round 4!)
```

**Expected Result** (Correct Behavior):
The extra block producer should be scheduled immediately or in the current/next round (T ≤ 52,000ms range), not in round 4 (T=72,000-96,000ms range).

**Success Condition**: 
Consensus command contains `ArrangedMiningTime = 84,000ms`, which is in round 4 timeframe (72,000-96,000ms), proving round 3 (48,000-72,000ms) is skipped. This scheduled time is 34 seconds in the future instead of immediate termination, demonstrating the consensus delay vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L11-16)
```csharp
    /// <summary>
    ///     If one node produced block this round or missed his time slot,
    ///     whatever how long he missed, we can give him a consensus command with new time slot
    ///     to produce a block (for terminating current round and start new round).
    ///     The schedule generated by this command will be cancelled
    ///     if this node executed blocks from other nodes.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L51-57)
```csharp
    private Timestamp CalculateFutureRoundStartTime(long missedRoundsCount = 0, int miningInterval = 0)
    {
        if (miningInterval == 0)
            miningInterval = GetMiningInterval();

        var totalMilliseconds = TotalMilliseconds(miningInterval);
        return GetRoundStartTime().AddMilliseconds(missedRoundsCount.Add(1).Mul(totalMilliseconds));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L23-38)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L39-44)
```csharp
            case AElfConsensusBehaviour.NextRound:
            case AElfConsensusBehaviour.NextTerm:
                return new ConsensusCommandProvider(
                        new TerminateRoundCommandStrategy(currentRound, pubkey, currentBlockTime,
                            behaviour == AElfConsensusBehaviour.NextTerm))
                    .GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-54)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();

        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();

        Context.LogDebug(() =>
            $"{currentRound.ToString(_processingBlockMinerPubkey)}\nArranged behaviour: {behaviour.ToString()}");

        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
