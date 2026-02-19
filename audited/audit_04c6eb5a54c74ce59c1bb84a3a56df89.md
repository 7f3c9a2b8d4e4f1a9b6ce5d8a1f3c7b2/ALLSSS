### Title
Extra Block Producer Receives Regular Time Slot Instead of Extra Block Slot When Distance is Non-Positive

### Summary
In `ArrangeAbnormalMiningTime()`, when the extra block producer's time slot has passed by more than one mining interval (distance ≤ 0), the code falls through from the special handling at lines 26-31 to the generic calculation at lines 33-36. This assigns the extra block producer a regular Order-based time slot in a future round instead of the proper extra block time slot, potentially causing duplicate time slot assignments and consensus conflicts.

### Finding Description

The vulnerability exists in the `ArrangeAbnormalMiningTime` method: [1](#0-0) 

The special handling for the extra block producer only returns if `distance > 0`. When `distance <= 0` (meaning `currentBlockTime >= GetExtraBlockMiningTime() + miningInterval`), no return statement executes, causing execution to fall through to the generic time slot calculation: [2](#0-1) 

**Root Cause:**
The fallthrough calculation uses `minerInRound.Order` from the current round to compute a time slot in a future round. However, this assigns a **regular mining time slot** (position-based) rather than the **extra block time slot** (which should be after all regular miners). The extra block producer's role is to produce a block at the END of the round to terminate it, not at their Order position. [3](#0-2) 

**Why Protections Fail:**
This method is called by `TerminateRoundCommandStrategy` to arrange mining time for extra block production: [4](#0-3) [5](#0-4) 

The consensus command indicates `NextRound` or `NextTerm` behaviour, meaning the miner should produce an extra block to terminate the round, but the arranged time is a regular slot that may conflict with another miner's expected time in that future round.

### Impact Explanation

**Consensus Integrity Compromise:**
- Two miners can be assigned the same time slot: the extra block producer (via `ArrangeAbnormalMiningTime`) and another miner with the same Order in the future round (via round generation logic)
- The extra block producer receives a command to terminate the round at time T, while another miner expects to produce their regular block at the same time T
- This creates a race condition where both miners attempt to produce blocks simultaneously

**Round Termination Disruption:**
- Extra block production is critical for round termination and confirming the next round's mining order, as documented: [6](#0-5) 

- Assigning the wrong time slot type prevents proper round termination
- Can cause indefinite delays in consensus progression if the extra block producer attempts to mine at a conflicting time slot

**Affected Parties:**
All network participants suffer from consensus disruption and potential chain stalling when the extra block producer's slot assignment conflicts with regular miners.

### Likelihood Explanation

**Triggering Conditions:**
The vulnerability triggers when:
1. The extra block producer calls `ArrangeAbnormalMiningTime` (via consensus command generation)
2. `mustExceededCurrentRound = false` (default for `ArrangeExtraBlockMiningTime`)
3. `currentBlockTime >= GetExtraBlockMiningTime() + miningInterval` (distance ≤ 0)

**Realistic Scenarios:**
- Network delays causing the extra block producer to miss their time slot by more than one mining interval
- Node downtime or synchronization issues
- High network latency during peak loads
- These are normal operational conditions, not attack scenarios

**Attacker Capabilities:**
No attacker action required - this is a natural consequence of network conditions and timing. The vulnerability manifests during legitimate consensus operations.

**Probability:**
Medium to High - occurs whenever the extra block producer experiences delays exceeding one mining interval, which can happen in production networks with variable latency or node availability issues.

### Recommendation

**Code-Level Mitigation:**
Add an explicit return statement after the special handling for extra block producers when distance ≤ 0, ensuring they always receive the extra block time slot in the next appropriate round:

```csharp
if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
{
    var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
        .Milliseconds();
    if (distance > 0) return GetExtraBlockMiningTime();
    
    // NEW: If extra block time has passed, calculate extra block slot in future round
    var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
    var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
    var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
    var minersCount = RealTimeMinersInformation.Count;
    return futureRoundStartTime.AddMilliseconds(minersCount.Mul(miningInterval));
}
```

**Invariant Checks:**
- Add validation that extra block producer's arranged time is always after all regular miners' time slots
- Verify no two miners receive the same `ArrangedMiningTime` value

**Test Cases:**
- Test extra block producer receiving consensus command when distance = 0
- Test extra block producer receiving consensus command when distance < 0
- Verify no time slot conflicts across all miners in generated future rounds
- Test rapid succession of missed extra block slots

### Proof of Concept

**Initial State:**
- 5 miners with Orders 1, 2, 3, 4, 5
- Miner with Order 3 is extra block producer (`IsExtraBlockProducer = true`)
- Mining interval = 4000ms
- Round start time = 0ms
- Miners' expected times: 4000ms, 8000ms, 12000ms, 16000ms, 20000ms
- Extra block time = 20000ms + 4000ms = 24000ms
- Total round duration = 24000ms

**Exploitation Steps:**

1. **Current block time advances to 28500ms** (extra block time passed by 4500ms)

2. **TerminateRoundCommandStrategy calls ArrangeExtraBlockMiningTime** for the extra block producer: [7](#0-6) 

3. **ArrangeAbnormalMiningTime executes:**
   - Line 26: Condition met (pubkey is extra block producer, mustExceededCurrentRound = false)
   - Line 28-29: distance = (24000 + 4000 - 28500) = -500ms
   - Line 30: Condition `distance > 0` is FALSE, no return
   - Execution falls through to line 33
   - Line 33: distanceToRoundStartTime = 28500 - 0 = 28500ms
   - Line 34: missedRoundsCount = 28500 / 24000 = 1
   - Line 35: futureRoundStartTime = 0 + (1+1) * 24000 = 48000ms (Round 3 start)
   - Line 36: Return 48000 + (3 * 4000) = **60000ms**

4. **Future round (Round 3) generation assigns:**
   - Some miner gets Order 3
   - That miner's ExpectedMiningTime = 48000 + (3 * 4000) = **60000ms**

**Expected Result:**
Extra block producer should receive time = 48000 + (5 * 4000) = 68000ms (extra block slot in Round 3)

**Actual Result:**
Extra block producer receives time = 60000ms (regular Order 3 slot), creating duplicate assignment with another miner

**Success Condition:**
Two miners have the same arranged mining time (60000ms), causing consensus conflict when both attempt to produce blocks simultaneously.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L24-24)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L26-31)
```csharp
        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L33-36)
```csharp
        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L60-65)
```csharp
    /// <summary>
    ///     In current AElf Consensus design, each miner produce his block in one time slot, then the extra block producer
    ///     produce a block to terminate current round and confirm the mining order of next round.
    ///     So totally, the time of one round is:
    ///     MiningInterval * MinersCount + MiningInterval.
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L22-25)
```csharp
        public static Timestamp ArrangeExtraBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return round.ArrangeAbnormalMiningTime(pubkey, currentBlockTime);
        }
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
