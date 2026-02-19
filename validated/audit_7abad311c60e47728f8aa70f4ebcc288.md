# Audit Report

## Title
Inconsistent Time Slot Validation Allows Consensus Disruption via Non-Uniform Mining Intervals

## Summary
The AEDPoS consensus contract contains a critical validation flaw where `CheckRoundTimeSlots` permits mining intervals up to 2x the base interval, while `GetMiningInterval` only examines the first two miners. This mismatch allows any miner to inject non-uniform round data that passes validation but causes consensus disruption by creating time windows where no miner is considered valid, halting block production.

## Finding Description

The vulnerability stems from an inconsistency between validation and consumption of mining interval data:

**Root Cause 1: Overly Permissive Tolerance Check**

The `CheckRoundTimeSlots` method validates time slot equality using a tolerance check that allows intervals to deviate by up to `baseMiningInterval` from the base. [1](#0-0) 

The condition `Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval` only fails when the absolute difference **exceeds** the base interval. This means an interval of exactly 2x the base (where the difference equals the base) passes validation.

**Root Cause 2: Limited Interval Calculation Scope**

The `GetMiningInterval` method only examines miners with `Order == 1 || Order == 2` to calculate the mining interval. [2](#0-1) 

This creates a fundamental mismatch: validation checks all consecutive pairs, but the returned interval only reflects the first two miners' spacing.

**Root Cause 3: No Canonical Round Verification**

The `PreCheck` method only verifies that the transaction sender is in the current or previous round's miner list. [3](#0-2) 

Critically, no verification exists that the submitted `NextRoundInput` matches the canonical output of `GenerateNextRoundInformation`, which always produces uniform intervals. [4](#0-3) 

**Exploitation Path:**

1. Attacker (valid miner) crafts `NextRoundInput` with non-uniform intervals:
   - Miner Order 1: Time T + 4000ms
   - Miner Order 2: Time T + 8000ms  
   - Miner Order 3: Time T + 16000ms

2. Validation via `TimeSlotValidationProvider` calls `CheckRoundTimeSlots`: [5](#0-4) 
   - baseMiningInterval = 4000ms (8000 - 4000)
   - Check orders 1→2: |4000 - 4000| = 0 ≤ 4000 ✓ PASS
   - Check orders 2→3: |8000 - 4000| = 4000 ≤ 4000 ✓ PASS

3. Round accepted via `ProcessNextRound` after `PreCheck` verification [6](#0-5) 

4. Malicious round stored with non-uniform intervals, but `GetMiningInterval()` returns 4000ms

**Downstream Impact:**

Functions that depend on `GetMiningInterval()` break with non-uniform data:

1. **IsCurrentMiner Time Window**: Uses `GetMiningInterval()` to check if current time falls within a miner's slot. [7](#0-6) 
   - For Miner Order 3 with actual 8000ms interval but `GetMiningInterval()` returning 4000ms
   - Valid time window calculated as T+16000 to T+20000 (using 4000ms)
   - Actual slot should be T+16000 to T+24000 (using 8000ms)
   - Creates 4000ms gap (T+20000 to T+24000) where NO miner is considered current → block production halts

2. **IsTimeSlotPassed**: Marks slots as expired using `GetMiningInterval()` [8](#0-7) 
   - Prematurely marks slots passed, disrupting normal round flow

3. **ArrangeAbnormalMiningTime**: Calculates incorrect future mining times [9](#0-8) 
   - Wrong scheduling for missed slots, compounding consensus disruption

## Impact Explanation

**Severity: High - Complete Consensus DoS**

The vulnerability enables a malicious miner to create time windows where the consensus system cannot identify any valid block producer, causing complete block production failure during those periods. This breaks the fundamental consensus guarantee that there is always exactly one valid miner for any given time slot.

The attack affects all network participants:
- **Network-wide block production halt** during gap periods
- **Chain liveness violation** - no new blocks can be produced
- **Transaction processing stoppage** until honest miners trigger a recovery
- **Violation of consensus invariants** - the "uniform time slot" and "continuous miner schedule" guarantees

The impact is particularly severe because:
1. Attack is deterministic and repeatable every round
2. Affects ALL nodes simultaneously (consensus-level issue)
3. Requires only single malicious miner
4. No automatic recovery mechanism exists within affected round

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- Must be a valid miner in current or previous round (common - multiple miners exist)
- Can submit transactions to consensus contract (standard miner capability)

**Attack Complexity: Low**
- Exploitation is deterministic - tolerance boundary at exactly 2x base interval
- No timing constraints or race conditions required
- Single transaction execution
- No sophisticated coordination needed

**Feasibility: High**
- Any miner can craft custom `NextRoundInput` data
- Validation happens before execution via `ValidateConsensusBeforeExecution` [10](#0-9) 
- No additional authorization beyond miner status required
- Validation providers do not verify canonical round generation [11](#0-10) 

**Detection Constraints:**
- Appears as valid round data until downstream functions fail
- No proactive detection mechanism in validation logic
- Manual inspection required to identify malicious rounds

## Recommendation

**Fix 1: Strengthen Time Slot Validation**

Tighten the tolerance check in `CheckRoundTimeSlots` to reject any non-uniform intervals:

```csharp
// Current vulnerable check:
if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)

// Recommended fix:
if (miningInterval != baseMiningInterval)
    return new ValidationResult { Message = "Time slots must be uniform." };
```

**Fix 2: Verify Canonical Round Generation**

Add validation that the submitted `NextRoundInput` matches the canonical generation by comparing it against `GenerateNextRoundInformation` output:

```csharp
// In ProcessNextRound or validation provider:
TryToGetCurrentRoundInformation(out var currentRound);
currentRound.GenerateNextRoundInformation(Context.CurrentBlockTime, 
    GetBlockchainStartTimestamp(), out var canonicalNextRound);
    
// Compare submitted round against canonical
if (!AreRoundsEquivalent(input.ToRound(), canonicalNextRound))
    return new ValidationResult { Message = "Round data does not match canonical generation." };
```

**Fix 3: Update GetMiningInterval Documentation and Usage**

If non-uniform intervals are ever intended, update all consumers of `GetMiningInterval()` to handle variable intervals correctly, or deprecate the method in favor of per-miner interval queries.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MaliciousNonUniformIntervals_CausesConsensusGap()
{
    // Setup: 3 miners in current round
    var currentRound = GenerateTestRound(3, uniformInterval: 4000);
    
    // Attacker crafts NextRoundInput with non-uniform intervals
    var maliciousNextRound = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        RealTimeMinersInformation = 
        {
            ["Miner1"] = new MinerInRound { Order = 1, ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddMilliseconds(4000)) },
            ["Miner2"] = new MinerInRound { Order = 2, ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddMilliseconds(8000)) },
            ["Miner3"] = new MinerInRound { Order = 3, ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddMilliseconds(16000)) } // 8000ms interval!
        }
    };
    
    // Validation check - should fail but passes
    var validationResult = maliciousNextRound.ToRound().CheckRoundTimeSlots();
    validationResult.Success.ShouldBeTrue(); // BUG: Passes with 2x interval
    
    // GetMiningInterval only sees first two miners
    var reportedInterval = maliciousNextRound.ToRound().GetMiningInterval();
    reportedInterval.ShouldBe(4000); // Only 4000ms, not 8000ms
    
    // IsCurrentMiner for Miner3 creates gap
    var miner3StartTime = Timestamp.FromDateTime(DateTime.UtcNow.AddMilliseconds(16000));
    var gapStartTime = Timestamp.FromDateTime(DateTime.UtcNow.AddMilliseconds(20000)); // Start of gap
    var gapEndTime = Timestamp.FromDateTime(DateTime.UtcNow.AddMilliseconds(24000)); // End of gap
    
    // During gap period (20000-24000ms), NO miner is current
    SetBlockTime(gapStartTime);
    var isCurrentResult = await ConsensusStub.IsCurrentMiner.CallAsync(Miner3Address);
    isCurrentResult.Value.ShouldBeFalse(); // BUG: No valid miner during gap!
    
    // Consensus halts - cannot produce blocks
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-54)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L83-90)
```csharp
    public bool IsTimeSlotPassed(string publicKey, Timestamp currentBlockTime)
    {
        var miningInterval = GetMiningInterval();
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
        if (RoundNumber != 1)
            return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } <
                   currentBlockTime;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L20-56)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L157-167)
```csharp
        var miningInterval = currentRound.GetMiningInterval();
        var minerInRound = currentRound.RealTimeMinersInformation[pubkey];
        var timeSlotStartTime = minerInRound.ExpectedMiningTime;

        // Check normal time slot.
        if (timeSlotStartTime <= Context.CurrentBlockTime && Context.CurrentBlockTime <=
            timeSlotStartTime.AddMilliseconds(miningInterval))
        {
            Context.LogDebug(() => "[CURRENT MINER]NORMAL");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L19-37)
```csharp
    public Timestamp ArrangeAbnormalMiningTime(string pubkey, Timestamp currentBlockTime,
        bool mustExceededCurrentRound = false)
    {
        var miningInterval = GetMiningInterval();

        var minerInRound = RealTimeMinersInformation[pubkey];

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```
