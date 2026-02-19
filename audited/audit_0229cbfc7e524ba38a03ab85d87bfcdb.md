### Title
ArrangeAbnormalMiningTime Returns Past Timestamp for Extra Block Producer, Violating Future Mining Time Invariant

### Summary
The `ArrangeAbnormalMiningTime()` function at line 30 returns a timestamp that can be earlier than `currentBlockTime` when the extra block producer requests consensus command within a specific time window. This violates the critical invariant that arranged mining time must always be in the future, causing the consensus scheduler to receive negative milliseconds and fire immediately, leading to improper block production timing and potential consensus failures.

### Finding Description

The vulnerability exists in the extra block producer path of `ArrangeAbnormalMiningTime()`: [1](#0-0) 

**Root Cause**: Line 28-29 calculates `distance = (GetExtraBlockMiningTime() + miningInterval) - currentBlockTime`, checking if this sum exceeds `currentBlockTime`. However, line 30 returns only `GetExtraBlockMiningTime()` without the `miningInterval` addition. This creates a time window where:
- If `GetExtraBlockMiningTime() ≤ currentBlockTime < GetExtraBlockMiningTime() + miningInterval`
- The condition `distance > 0` passes (because the sum exceeds currentBlockTime)
- But the returned value `GetExtraBlockMiningTime()` is ≤ currentBlockTime (in the past)

**Where GetExtraBlockMiningTime is defined**: [2](#0-1) 

**Entry Point - TerminateRoundCommandStrategy calls ArrangeExtraBlockMiningTime**: [3](#0-2) 

**Which delegates to ArrangeAbnormalMiningTime**: [4](#0-3) 

**Consensus scheduler receives this past timestamp**: [5](#0-4) 

The scheduler calculates `leftMilliseconds = ArrangedMiningTime - currentTime`, which becomes negative, and passes this to `Observable.Timer`: [6](#0-5) 

Observable.Timer with negative/zero milliseconds fires immediately instead of waiting.

**Why Existing Validation Fails**: [7](#0-6) 

Block validation only rejects blocks MORE THAN 30 minutes in the future, not blocks with timestamps in the past.

**Note on Line 36**: Mathematical analysis confirms line 36 always returns a future timestamp because `futureRoundStartTime = GetRoundStartTime() + (missedRoundsCount + 1) * TotalMilliseconds` where `missedRoundsCount = floor((currentBlockTime - GetRoundStartTime()) / TotalMilliseconds)`, guaranteeing `futureRoundStartTime ≥ currentBlockTime`.

### Impact Explanation

**Consensus Integrity Impact**:
- Blocks are produced with incorrect timing, violating the time-slot scheduling invariant
- The extra block producer fires immediately instead of waiting for the proper time slot
- Peers may reject improperly timed blocks, causing consensus disagreements
- Could lead to round termination failures and consensus stalls

**Operational Impact**:
- The consensus scheduler behaves incorrectly when receiving negative delay values
- Mining events fire immediately instead of at the arranged time
- This disrupts the carefully orchestrated block production schedule
- Multiple miners might attempt to produce blocks simultaneously if timing is disrupted

**Affected Parties**:
- Extra block producers attempting to terminate rounds during the vulnerable time window
- All network participants relying on proper consensus timing
- The entire consensus mechanism's reliability and predictability

**Severity Justification**: HIGH - This directly violates a critical consensus invariant (arranged mining time must be in the future), affects core consensus functionality, and has no validation to prevent it.

### Likelihood Explanation

**Attacker Capabilities**: No attacker control needed - this is a timing bug that occurs naturally during normal operations when the extra block producer requests a consensus command.

**Attack Complexity**: LOW - The vulnerability triggers automatically when:
1. The extra block producer calls `GetConsensusCommand` to terminate a round
2. Current time falls in window: `[GetExtraBlockMiningTime(), GetExtraBlockMiningTime() + miningInterval)`
3. This window typically spans the `miningInterval` duration (e.g., 100ms-4000ms)

**Feasibility Conditions**:
- Occurs during normal round termination operations
- Network latency or processing delays easily cause requests to fall within the vulnerable window
- Higher probability with longer mining intervals or network delays
- No special permissions or malicious actions required

**Detection Constraints**: 
- Bug manifests as subtle timing anomalies in block production
- Negative scheduler delays may not be immediately visible
- Blocks might still be produced but at incorrect times
- Difficult to distinguish from normal network timing variations

**Probability**: MEDIUM-HIGH - The vulnerable time window occurs every round during extra block production. With typical mining intervals (100ms-4000ms) and normal network/processing delays, this condition is reasonably likely to occur periodically.

### Recommendation

**Fix Line 30** - Return the corrected timestamp that includes the miningInterval:

```csharp
// Line 28-30 should be:
var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
    .Milliseconds();
if (distance > 0) return GetExtraBlockMiningTime().AddMilliseconds(miningInterval);
```

Alternatively, simplify the logic to always return the sum:

```csharp
if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
{
    return GetExtraBlockMiningTime().AddMilliseconds(miningInterval);
}
```

**Add Invariant Check** - Validate arranged mining time is in the future before scheduling:

```csharp
// In ConsensusService.TriggerConsensusAsync after line 87:
Assert(_consensusCommand.ArrangedMiningTime > TimestampHelper.GetUtcNow(), 
    "Arranged mining time must be in the future");
```

**Add Validation** - Enhance block validation to reject blocks with past timestamps beyond reasonable tolerance:

```csharp
// In BlockValidationProvider.ValidateBeforeAttachAsync:
if (block.Header.Time < TimestampHelper.GetUtcNow().AddSeconds(-AllowedPastBlockTimeSeconds))
{
    Logger.LogDebug("Past block received beyond tolerance");
    return Task.FromResult(false);
}
```

**Test Cases**:
1. Test `ArrangeAbnormalMiningTime` when `currentBlockTime` is between `GetExtraBlockMiningTime()` and `GetExtraBlockMiningTime() + miningInterval`
2. Verify returned timestamp is always `> currentBlockTime`
3. Test scheduler behavior with negative milliseconds input
4. Test block validation rejects blocks with timestamps too far in the past

### Proof of Concept

**Initial State**:
- Round with 5 miners, miningInterval = 100ms
- Last miner's ExpectedMiningTime = 1000ms
- GetExtraBlockMiningTime() returns 1100ms (last miner + miningInterval)
- Extra block producer pubkey = "ExtraBlockProducerPubkey"

**Exploitation Sequence**:
1. Current blockchain time advances to 1150ms (within vulnerable window)
2. Extra block producer calls `GetConsensusCommand` to get termination command
3. `TerminateRoundCommandStrategy.GetAEDPoSConsensusCommand()` is invoked
4. Calls `MiningTimeArrangingService.ArrangeExtraBlockMiningTime(round, pubkey, 1150ms)`
5. Which calls `round.ArrangeAbnormalMiningTime(pubkey, 1150ms, false)`
6. Line 26 condition: `GetExtraBlockProducerInformation().Pubkey == pubkey && !false` → TRUE
7. Line 28-29: `distance = (1100 + 100) - 1150 = 50 > 0` → TRUE
8. Line 30: Returns `GetExtraBlockMiningTime() = 1100ms`

**Expected vs Actual**:
- **Expected**: ArrangedMiningTime should be ≥ 1150ms (future timestamp)
- **Actual**: ArrangedMiningTime = 1100ms (50ms in the past)

**Result**:
- ConsensusService calculates: `leftMilliseconds = 1100 - 1150 = -50ms`
- RxNetScheduler receives: `Observable.Timer(TimeSpan.FromMilliseconds(-50))`
- Timer fires immediately instead of waiting
- Block production scheduled incorrectly, violating consensus timing invariant

**Success Condition**: The arranged mining time 1100ms < currentBlockTime 1150ms, violating the invariant that arranged time must be in the future.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L26-31)
```csharp
        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L25-26)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L22-25)
```csharp
        public static Timestamp ArrangeExtraBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return round.ArrangeAbnormalMiningTime(pubkey, currentBlockTime);
        }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L87-108)
```csharp
        _nextMiningTime = _consensusCommand.ArrangedMiningTime;
        var leftMilliseconds = _consensusCommand.ArrangedMiningTime - TimestampHelper.GetUtcNow();
        leftMilliseconds = leftMilliseconds.Seconds > ConsensusConstants.MaximumLeftMillisecondsForNextBlock
            ? new Duration { Seconds = ConsensusConstants.MaximumLeftMillisecondsForNextBlock }
            : leftMilliseconds;

        var configuredMiningTime = await _miningTimeProvider.GetLimitMillisecondsOfMiningBlockAsync(new BlockIndex
        {
            BlockHeight = chainContext.BlockHeight,
            BlockHash = chainContext.BlockHash
        });
        var limitMillisecondsOfMiningBlock = configuredMiningTime == 0
            ? _consensusCommand.LimitMillisecondsOfMiningBlock
            : configuredMiningTime;
        // Update consensus scheduler.
        var blockMiningEventData = new ConsensusRequestMiningEventData(chainContext.BlockHash,
            chainContext.BlockHeight,
            _nextMiningTime,
            TimestampHelper.DurationFromMilliseconds(limitMillisecondsOfMiningBlock),
            _consensusCommand.MiningDueTime);
        _consensusScheduler.CancelCurrentEvent();
        _consensusScheduler.NewEvent(leftMilliseconds.Milliseconds(), blockMiningEventData);
```

**File:** src/AElf.Kernel.Consensus.Scheduler.RxNet/RxNetScheduler.cs (L60-61)
```csharp
        return Observable.Timer(TimeSpan.FromMilliseconds(countingMilliseconds))
            .Select(_ => consensusRequestMiningEventData).Subscribe(this);
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L133-139)
```csharp
        if (block.Header.Height != AElfConstants.GenesisBlockHeight &&
            block.Header.Time.ToDateTime() - TimestampHelper.GetUtcNow().ToDateTime() >
            KernelConstants.AllowedFutureBlockTimeSpan.ToTimeSpan())
        {
            Logger.LogDebug("Future block received {Block}, {BlockTime}", block, block.Header.Time.ToDateTime());
            return Task.FromResult(false);
        }
```
