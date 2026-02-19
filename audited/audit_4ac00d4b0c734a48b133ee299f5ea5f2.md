# Audit Report

## Title
RoundId Manipulation Bypasses Time Slot Validation in NextRound Consensus Transitions

## Summary
A malicious miner can craft a NextRound with manipulated `ExpectedMiningTime` values that sum to equal `BaseRound.RoundId`, causing the validation logic to skip critical time slot checks. This allows acceptance of consensus rounds with arbitrary, unequal time slots, breaking the core AEDPoS scheduling invariant and disrupting block production.

## Finding Description

The vulnerability exists in the consensus validation flow where `TimeSlotValidationProvider` uses `RoundId` equality to determine whether to validate time slots for a new round. [1](#0-0) 

The `RoundId` property is computed as the sum of all miners' `ExpectedMiningTime.Seconds` values: [2](#0-1) 

**Root Cause:** The validation logic assumes that equal RoundIds indicate the same round, but an attacker can craft a new round where ExpectedMiningTime values are deliberately manipulated to sum to `BaseRound.RoundId`, bypassing the `CheckRoundTimeSlots()` validation.

**Attack Mechanism:**

1. A malicious miner calculates the current `BaseRound.RoundId` (e.g., 28.9 billion)
2. When producing the NextRound block, the miner modifies the consensus extra data with manipulated values:
   - 16 miners: `ExpectedMiningTime.Seconds = 1`
   - 1 miner: `ExpectedMiningTime.Seconds = 28,899,999,984`
   - Result: `ProvidedRound.RoundId = 28.9 billion = BaseRound.RoundId`

3. During validation, `ValidateBeforeExecution` is called: [3](#0-2) 

4. The `RoundTerminateValidationProvider` only validates `RoundNumber` increments and `InValue` nullity: [4](#0-3) 

5. The `TimeSlotValidationProvider` sees equal RoundIds and skips `CheckRoundTimeSlots()`, only checking the miner's individual time slot.

6. The `CheckRoundTimeSlots()` method would normally reject this by verifying equal intervals: [5](#0-4) 

However, this validation never executes due to the bypassed condition.

7. After validation passes, the malicious round is stored: [6](#0-5) 

## Impact Explanation

**Consensus Integrity Violation:**
The accepted malicious round has arbitrary, unequal time slots that violate the fundamental AEDPoS invariant of equal time distribution among miners. This breaks the consensus scheduling mechanism that all miners rely on to determine when to produce blocks.

**Concrete Harms:**
1. **Consensus Disruption:** Miners with compressed time slots (e.g., 1-second intervals) cannot physically produce blocks in time, while the attacker with an extended slot effectively monopolizes block production
2. **Chain Halt Risk:** If critical miners receive invalid time slots, consensus may fail to progress through rounds, halting the chain
3. **Reward Manipulation:** Unequal time slots enable unfair distribution of block production opportunities and mining rewards
4. **Cascading Failures:** Subsequent rounds built on the malicious round inherit broken timing assumptions

**Affected Parties:**
- All network participants experience consensus breakdown
- Honest miners cannot produce blocks in their assigned slots
- Users face degraded or halted transaction finality

**Severity Justification:** HIGH - This directly compromises a core consensus invariant with practical exploitation requiring only current miner privileges.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a current miner (validated by standard consensus participation rules)
- Must mine during their valid time slot to trigger NextRound

**Attack Complexity:** LOW
- Simple arithmetic to calculate target RoundId sum
- No cryptographic breaking required
- No race conditions or precise timing needed
- Single transaction execution via the `NextRound` method [7](#0-6) 

**Feasibility:**
- Miners control their own block production and can modify consensus extra data before broadcasting
- `BaseRound.RoundId` is publicly readable state
- The legitimate round generation happens in `GetConsensusExtraDataForNextRound`, but miners can bypass this: [8](#0-7) 

- No additional validators check `ExpectedMiningTime` reasonableness

**Probability Assessment:** HIGH - Any malicious miner can execute this attack during their time slot with near certainty, limited only by normal consensus flow constraints.

## Recommendation

Add explicit validation of `ExpectedMiningTime` values in the NextRound validation flow:

1. **Immediate Fix:** Modify `TimeSlotValidationProvider` to always validate time slots for NextRound behavior, regardless of RoundId equality:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    
    // For NextRound behavior, always check time slots
    if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextRound)
    {
        validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
        if (!validationResult.Success) return validationResult;
    }
    // If provided round is a new round (and not NextRound which was already checked)
    else if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
    {
        validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
        if (!validationResult.Success) return validationResult;
    }
    else
    {
        // Check individual miner time slot for same round
        if (!CheckMinerTimeSlot(validationContext))
        {
            validationResult.Message = $"Time slot already passed before execution.{validationContext.SenderPubkey}";
            validationResult.IsReTrigger = true;
            return validationResult;
        }
    }

    validationResult.Success = true;
    return validationResult;
}
```

2. **Additional Hardening:** Add validation in `RoundTerminateValidationProvider` to verify that `ExpectedMiningTime` values are reasonable and within acceptable bounds relative to current block time.

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_RoundIdManipulation_BypassesTimeSlotValidation()
{
    // Setup: Initialize consensus with 17 miners
    var initialMiners = GenerateMinerList(17);
    await InitializeConsensusAsync(initialMiners);
    
    // Advance to establish current round with legitimate RoundId
    var currentRound = await GetCurrentRoundAsync();
    var targetRoundId = currentRound.RoundId; // e.g., 28.9 billion
    
    // Attacker is the extra block producer
    var attackerPubkey = currentRound.GetExtraBlockProducerInformation().Pubkey;
    
    // Craft malicious NextRound with manipulated ExpectedMiningTime
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation = { }
    };
    
    // Set 16 miners to 1 second, 1 miner to (targetRoundId - 16)
    for (int i = 0; i < 16; i++)
    {
        maliciousRound.RealTimeMinersInformation[initialMiners[i]] = new MinerInRound
        {
            Pubkey = initialMiners[i],
            Order = i + 1,
            ExpectedMiningTime = new Timestamp { Seconds = 1 }
        };
    }
    
    maliciousRound.RealTimeMinersInformation[initialMiners[16]] = new MinerInRound
    {
        Pubkey = initialMiners[16],
        Order = 17,
        ExpectedMiningTime = new Timestamp { Seconds = targetRoundId - 16 }
    };
    
    // Verify RoundId matches (bypass condition)
    Assert.Equal(targetRoundId, maliciousRound.RoundId);
    
    // Attempt NextRound with malicious data
    var result = await ExecuteNextRoundAsync(attackerPubkey, maliciousRound);
    
    // Vulnerability: Transaction succeeds despite invalid time slots
    Assert.True(result.Success);
    
    // Verify malicious round was stored
    var storedRound = await GetCurrentRoundAsync();
    Assert.Equal(maliciousRound.RoundNumber, storedRound.RoundNumber);
    
    // Verify time slots are invalid (unequal intervals)
    var timeSlotValidation = storedRound.CheckRoundTimeSlots();
    Assert.False(timeSlotValidation.Success); // Would fail if called, but wasn't
}
```

## Notes

This vulnerability demonstrates a critical flaw in using derived values (RoundId as sum) as validation gates. The fix must ensure that NextRound transitions always undergo full time slot validation regardless of computed RoundId values. The attack is particularly dangerous because it requires no special privileges beyond normal miner participation and can be executed atomically in a single block.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-19)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L15-24)
```csharp
    public long RoundId
    {
        get
        {
            if (RealTimeMinersInformation.Values.All(bpInfo => bpInfo.ExpectedMiningTime != null))
                return RealTimeMinersInformation.Values.Select(bpInfo => bpInfo.ExpectedMiningTime.Seconds).Sum();

            return RoundIdForValidation;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

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
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```
