### Title
Extra Block Producer ArrangedMiningTime Violates Time Slot Boundaries in Future Rounds

### Summary
The `GetAEDPoSConsensusCommand` method in `TerminateRoundCommandStrategy` delegates to `ArrangeAbnormalMiningTime`, which calculates the extra block producer's mining time for future rounds using the producer's normal Order position instead of the extra block slot position. This causes the arranged time to fall within another miner's time slot rather than the designated extra block slot, violating consensus time slot boundaries and potentially causing round termination failures.

### Finding Description

The vulnerability exists in the time calculation logic when arranging extra block mining time for future rounds.

**Entry Point:** [1](#0-0) 

**Root Cause:**
When `ArrangeExtraBlockMiningTime` is called, it delegates to `Round.ArrangeAbnormalMiningTime`: [2](#0-1) 

In `ArrangeAbnormalMiningTime`, when the extra block producer's designated time has passed (line 30 check fails), the code falls through to line 36: [3](#0-2) 

Line 36 calculates: `futureRoundStartTime + minerInRound.Order * miningInterval`, placing the extra block producer at their normal Order position, not the extra block slot.

**Expected Extra Block Position:**
According to the design, the extra block should be produced after all normal miners: [4](#0-3) 

The extra block mining time is: `LastMiner.ExpectedMiningTime + MiningInterval`, which equals `RoundStartTime + minersCount * MiningInterval`.

**Why Order != MinersCount:**
The extra block producer is assigned a normal Order (1 to minersCount), and due to the `BreakContinuousMining` logic, they are typically NOT the last miner: [5](#0-4) 

Lines 98-107 swap the last miner with another miner if the last miner is the extra block producer, ensuring Order != minersCount.

**Missing Validation:**
None of the validation providers check that extra block arranged time falls within the extra block slot: [6](#0-5) 

This validates against `ExpectedMiningTime` (normal slot), not the extra block slot. [7](#0-6) 

This only validates round number and InValue fields, not time slot boundaries.

### Impact Explanation

**Consensus Integrity Violation:**
The arranged mining time violates the fundamental time slot allocation invariant. Extra blocks must be produced in their designated slot (after all normal miners), but the vulnerable code schedules them in normal miner slots.

**Concrete Example:**
- 5 miners, mining interval = 4000ms
- Extra block producer has Order = 2 (common after BreakContinuousMining)
- Round start time = T
- Extra block slot should be: T + (5 * 4000) = T + 20000ms
- If extra block time passes and arranging for next round:
  - Future round start: T + 48000ms
  - Calculated time: T + 48000 + (2 * 4000) = T + 56000ms (Order slot)
  - Expected time: T + 48000 + (5 * 4000) = T + 68000ms (extra block slot)
  - **Violation: 12000ms (3 time slots) off target**

**Harm:**
1. **Time slot collision**: Extra block producer scheduled during miner Order=2's normal slot
2. **Round termination failure**: Extra block not produced at correct time, delaying round transitions
3. **Consensus disruption**: Multiple miners may attempt to mine simultaneously
4. **Chain progression impact**: Blocks produced out-of-sequence affect consensus finality

**Severity Justification:**
High severity due to direct consensus integrity violation, affecting the core time slot scheduling mechanism that ensures orderly block production.

### Likelihood Explanation

**Attacker Capabilities:**
No malicious actor required - this is a logic error that occurs during normal consensus operation.

**Preconditions (Highly Feasible):**
1. Extra block producer's Order < minersCount (common due to BreakContinuousMining logic)
2. Extra block mining time has passed when `GetAEDPoSConsensusCommand` is called
3. `mustExceededCurrentRound` parameter is false (default value)

**Execution Path:**
Reachable through normal consensus command generation: [8](#0-7) 

When behavior is NextRound or NextTerm, `TerminateRoundCommandStrategy` is instantiated and executed.

**Frequency:**
Occurs whenever a miner queries for consensus command after their extra block time slot has passed. Given network latency, node synchronization delays, or brief outages, this is a regular occurrence in distributed consensus systems.

**Detection Difficulty:**
Low - the vulnerability manifests as observable time slot violations, but may be attributed to network issues rather than the underlying logic flaw.

**Probability:**
High - the conditions naturally occur during normal network operations without requiring adversarial action.

### Recommendation

**Code-Level Mitigation:**
Modify `ArrangeAbnormalMiningTime` to correctly calculate extra block slot position:

```csharp
// In Round_ArrangeAbnormalMiningTime.cs, line 36
// Change from:
return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));

// To:
if (GetExtraBlockProducerInformation().Pubkey == pubkey)
{
    // Extra block producer should be at the end: minersCount * miningInterval
    return futureRoundStartTime.AddMilliseconds(RealTimeMinersInformation.Count.Mul(miningInterval));
}
return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**Invariant Check to Add:**
Add validation in `TerminateRoundCommandStrategy` or a new validation provider:
```csharp
// Verify extra block arranged time is in extra block slot
var extraBlockTime = currentRound.GetExtraBlockMiningTime();
var roundStartTime = CalculateFutureRoundStartTime(...);
var expectedExtraBlockTime = roundStartTime.AddMilliseconds(currentRound.RealTimeMinersInformation.Count * miningInterval);
Assert(arrangedMiningTime >= expectedExtraBlockTime && 
       arrangedMiningTime < expectedExtraBlockTime.AddMilliseconds(miningInterval),
       "Extra block arranged time must fall within extra block slot");
```

**Test Cases:**
1. Test extra block producer with Order < minersCount arranging time after slot expires
2. Test multiple missed rounds for extra block producer
3. Verify arranged time falls in extra block slot, not normal slot
4. Test with varying miner counts and Order positions

### Proof of Concept

**Initial State:**
- Round with 5 miners (A, B, C, D, E)
- Mining interval: 4000ms
- Round start time: T = 1000000ms
- Miner B (Order=2) is designated extra block producer
- Current block time: T + 25000ms (extra block slot at T + 20000ms has passed)

**Transaction Steps:**
1. Miner B calls `GetConsensusCommand` with NextRound behavior
2. `TerminateRoundCommandStrategy.GetAEDPoSConsensusCommand()` is invoked
3. Calls `ArrangeExtraBlockMiningTime(currentRound, "B", T + 25000)`
4. `ArrangeAbnormalMiningTime` is executed:
   - Line 26: B is extra block producer ✓
   - Line 28-30: distance = (T + 20000 + 4000) - (T + 25000) = -1000ms (< 0, check fails)
   - Falls through to line 33-36
   - Line 34: missedRoundsCount = 25000 / 24000 = 1
   - Line 35: futureRoundStartTime = T + (2 * 24000) = T + 48000ms
   - Line 36: returns T + 48000 + (2 * 4000) = **T + 56000ms**

**Expected Result:**
ArrangedMiningTime should be: T + 48000 + (5 * 4000) = **T + 68000ms** (extra block slot)

**Actual Result:**
ArrangedMiningTime is: **T + 56000ms** (miner Order=2's normal slot in future round)

**Success Condition:**
The vulnerability is confirmed when arranged time falls in a normal miner's slot (T + 56000ms = slot for Order=2) instead of the extra block slot (T + 68000ms = after all 5 miners).

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L22-25)
```csharp
        public static Timestamp ArrangeExtraBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return round.ArrangeAbnormalMiningTime(pubkey, currentBlockTime);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L26-37)
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L92-107)
```csharp
        // Last miner of next round != Extra block producer of next round
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;

        var extraBlockProducerOfNextRound = nextRound.GetExtraBlockProducerInformation();
        if (lastMinerOfNextRound.Pubkey == extraBlockProducerOfNextRound.Pubkey)
        {
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
            lastButOneMinerOfNextRound.Order = minersCount;
            lastMinerOfNextRound.Order = minersCount.Sub(1);
            var tempTimestamp = lastButOneMinerOfNextRound.ExpectedMiningTime;
            lastButOneMinerOfNextRound.ExpectedMiningTime = lastMinerOfNextRound.ExpectedMiningTime;
            lastMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
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
