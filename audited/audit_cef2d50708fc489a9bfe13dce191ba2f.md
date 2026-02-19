# Audit Report

## Title
Missing RoundId Validation Allows Bypass of Time Slot Checks for UpdateValue and TinyBlock Behaviors

## Summary
The consensus validation mechanism fails to enforce RoundId matching for UpdateValue and TinyBlock behaviors, allowing malicious miners to bypass critical time slot validation by crafting blocks with mismatched RoundIds. This enables miners to produce blocks outside their assigned time slots, breaking the fundamental AEDPoS time slot mechanism.

## Finding Description

The vulnerability exists in the consensus validation flow where `ValidateBeforeExecution` processes UpdateValue and TinyBlock behaviors without validating that the provided Round's RoundId matches the base Round's RoundId from chain state. [1](#0-0) 

When these behaviors are processed, the code calls `RecoverFromUpdateValue` or `RecoverFromTinyBlock` to update the base round with miner information, but these recovery methods only update miner-level fields and never modify `ExpectedMiningTime` values: [2](#0-1) 

This means `BaseRound.RoundId` (calculated from the original `ExpectedMiningTime` values) remains unchanged while an attacker can provide a Round with different `ExpectedMiningTime` values to create a RoundId mismatch. [3](#0-2) 

The critical bypass occurs in `TimeSlotValidationProvider`. When RoundIds don't match, it treats the block as a "new round" and only calls `CheckRoundTimeSlots()` instead of `CheckMinerTimeSlot()`: [4](#0-3) 

The `CheckMinerTimeSlot()` method validates that a miner's `ActualMiningTimes` fall within their assigned time slot window: [5](#0-4) 

However, `CheckRoundTimeSlots()` only validates structural properties (evenly spaced time slots, positive intervals) and does NOT validate whether the current miner is mining within their assigned slot: [6](#0-5) 

Furthermore, `ProcessUpdateValue` never validates that the input's `round_id` field matches the current round's RoundId: [7](#0-6) 

The protobuf documentation explicitly states that the `round_id` field exists "To ensure the values to update will be apply to correct round by comparing round id," but no such comparison exists: [8](#0-7) 

The after-execution validation does not prevent this attack because `RecoverFromUpdateValue` modifies the current round object in-place and returns it, making both sides of the hash comparison reference the same object: [9](#0-8) 

## Impact Explanation

This vulnerability has **HIGH** severity impact:

**Consensus Integrity Compromise**: Malicious miners can produce blocks outside their assigned time slots, fundamentally breaking the AEDPoS time slot mechanism. This allows miners to produce blocks when other miners should have exclusive mining rights, leading to unfair block production where attackers can produce more blocks than their allocated share.

**Denial of Service**: Attackers can continuously produce blocks during other miners' time slots, potentially blocking legitimate miners from producing blocks during their assigned windows and disrupting orderly round progression and consensus liveness.

**Chain Stability**: Multiple miners producing blocks simultaneously (outside time slot constraints) can cause chain forks, breaking the assumption that only one miner mines at a given time, potentially leading to consensus deadlocks or chain reorganizations.

This directly violates the "Correct round transitions and time-slot validation" invariant that is fundamental to AEDPoS consensus security.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of exploitation:

**Attacker Requirements**: The attacker must be a valid miner in the current round, which is validated by `PreCheck`. This is a realistic constraint as any current miner can exploit this vulnerability.

**Attack Complexity: LOW**
1. Craft a Round object with modified `ExpectedMiningTime` values (to trigger RoundId mismatch)
2. Ensure `ExpectedMiningTime` values are evenly spaced to pass `CheckRoundTimeSlots()`
3. Set `ActualMiningTime` to any desired time (including outside assigned slot)
4. Generate valid `OutValue`/`Signature` for UpdateValue behavior
5. Sign and submit the block

**Detection Difficulty**: The block appears valid from an external perspective (signed by a legitimate miner). Only detailed round validation logic analysis reveals the bypass. There are no obvious anomalies in block structure.

**Economic Cost**: Only requires standard block production resources with no special infrastructure or tokens needed beyond being a miner. There is high reward potential through additional block rewards and MEV opportunities.

**Execution Practicality**: The consensus extra data extraction only validates that `SenderPubkey` matches the block signer—it does NOT validate Round contents, enabling attackers to inject arbitrary Round data.

## Recommendation

Add explicit RoundId validation in `ValidateBeforeExecution` for UpdateValue and TinyBlock behaviors:

```csharp
// In ValidateBeforeExecution method, after RecoverFrom calls:
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue || 
    extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
{
    if (extraData.Round.RoundId != baseRound.RoundId)
        return new ValidationResult 
        { 
            Success = false, 
            Message = "Provided RoundId does not match current round RoundId." 
        };
}
```

Additionally, add RoundId validation in `ProcessUpdateValue` and `ProcessTinyBlock` methods:

```csharp
// In ProcessUpdateValue method, after getting currentRound:
Assert(updateValueInput.RoundId == currentRound.RoundId, 
    "Round ID mismatch - provided round_id does not match current round.");
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. A test where a miner crafts an UpdateValue block with:
   - Modified `ExpectedMiningTime` values (shifted by 1 second each to change RoundId sum)
   - Evenly spaced intervals (to pass `CheckRoundTimeSlots()`)
   - `ActualMiningTime` set to a time outside their assigned slot (e.g., during another miner's slot)

2. The validation flow will:
   - Detect RoundId mismatch in `TimeSlotValidationProvider`
   - Take the "new round" branch and only call `CheckRoundTimeSlots()`
   - Skip `CheckMinerTimeSlot()` which would have caught the out-of-slot mining
   - Pass all validations

3. The state will be updated with the out-of-slot `ActualMiningTime`, proving the bypass is complete and the time slot mechanism is broken.

The test should verify that:
- The block validation succeeds despite mining outside the assigned time slot
- The `ActualMiningTime` recorded in state is outside the miner's expected time slot window
- No validation error is raised when it should be

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-35)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** protobuf/aedpos_contract.proto (L199-200)
```text
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```
