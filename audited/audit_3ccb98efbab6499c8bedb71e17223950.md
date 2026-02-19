### Title
Missing Round Number Validation Does Not Allow Round Skipping

### Summary
While `ProvidedRound.RoundNumber` is not validated to match `BaseRound.RoundNumber` for `UpdateValue` and `TinyBlock` behaviors, this does not allow skipping multiple rounds. The state's round number remains controlled by the actual processing logic which retrieves the current round from state, not from the provided header information.

### Finding Description

The validation flow lacks explicit round number consistency checks for `UpdateValue` and `TinyBlock` behaviors: [1](#0-0) 

The `RoundTerminateValidationProvider`, which validates that `ProvidedRound.RoundNumber == BaseRound.RoundNumber + 1`, is only added for `NextRound` and `NextTerm` behaviors: [2](#0-1) 

This means a miner could craft a block header with `ProvidedRound.RoundNumber` set to any value (e.g., 100 when the actual round is 5) for `UpdateValue` or `TinyBlock` behaviors, and no validation would reject it based on round number mismatch.

**However**, during block processing, the actual state's round is used, not the provided round number: [3](#0-2) 

The `ProcessUpdateValue` method retrieves `currentRound` from state via `TryToGetCurrentRoundInformation`, updates that round's miner information, and saves it back. The `ProvidedRound.RoundNumber` from the header is never used to update the state's round number. [4](#0-3) 

Similarly, `ProcessTinyBlock` uses the current round from state, ignoring the provided round number.

### Impact Explanation

**No Round Skipping Occurs:**
Despite the missing validation, the question's specific concern—"allowing skip of multiple rounds"—does not materialize because:

1. Round number transitions are strictly controlled by `NextRound` and `NextTerm` processing logic
2. `UpdateValue` and `TinyBlock` behaviors only update the current round's miner information
3. The state's `CurrentRoundNumber` is only incremented through validated `NextRound`/`NextTerm` operations [5](#0-4) 

**Minor Side Effect:**
The only observable impact is that `ProvidedRound.RoundNumber` is used in one validation check: [6](#0-5) 

A malicious miner could set `ProvidedRound.RoundNumber = 1` to bypass the continuous blocks limit check, but this:
- Does not allow skipping rounds
- Only affects fork prevention mechanism
- Cannot progress the blockchain state beyond legitimate round transitions

### Likelihood Explanation

While the validation gap exists and is exploitable by any miner, the exploit does not achieve the stated impact of "skipping multiple rounds." The state management architecture inherently prevents round skipping through `UpdateValue`/`TinyBlock` behaviors because these operations are designed only to update the current round, not advance it.

### Recommendation

Despite no round-skipping vulnerability, best practice suggests adding defensive validation:

```csharp
// In RoundTerminateValidationProvider or a new dedicated provider
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue || 
    extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
{
    if (validationContext.ProvidedRound.RoundNumber != validationContext.BaseRound.RoundNumber)
        return new ValidationResult { Message = "Round number mismatch for same-round update." };
}
```

This would prevent misuse of the `RoundNumber` field in validation logic and improve code clarity.

### Proof of Concept

**Initial State:** Current round number = 5

**Attack Attempt:**
1. Malicious miner crafts `TinyBlock` with `ProvidedRound.RoundNumber = 100`
2. Block passes validation (no round number check for `TinyBlock`)
3. Block is executed via `ProcessTinyBlock`

**Expected Malicious Result:** Round advances to 100
**Actual Result:** Round remains at 5 [7](#0-6) 

The state's `CurrentRoundNumber` remains unchanged because `TryToUpdateRoundInformation(currentRound)` saves the round retrieved from state (round 5), not the attacker's provided value (round 100).

**Conclusion:** The validation gap exists but does not enable the critical impact described in the question.

### Notes

The question specifically asks whether missing validation allows "skip of multiple rounds." Based on deep code analysis, the answer is **no**—the state management architecture prevents round skipping regardless of the validation gap. While adding the validation check is good defensive programming, the absence of this check does not create the critical vulnerability described.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-284)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-14)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
```
