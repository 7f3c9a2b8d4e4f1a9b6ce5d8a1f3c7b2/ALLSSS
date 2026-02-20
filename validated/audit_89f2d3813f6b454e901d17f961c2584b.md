# Audit Report

## Title
Consensus Behavior Manipulation Allows Bypass of Critical Validators and Disruption of Consensus Integrity

## Summary
A malicious miner can manipulate the `Behaviour` field in consensus header information to bypass critical validators and skip essential consensus state updates. By switching from `UpdateValue` to `TinyBlock` behavior without validation, the attacker prevents publication of OutValue/Signature and LIB calculation, breaking consensus random number generation and halting chain finality progression.

## Finding Description

The AEDPoS consensus system has a critical validation gap: it never verifies that the `Behaviour` field provided by miners matches what consensus rules dictate.

When a miner produces a block, they should call `GetConsensusCommand` which correctly determines their expected behavior (UpdateValue, TinyBlock, NextRound, or NextTerm) based on current consensus state. [1](#0-0)  However, the miner can then craft trigger information with a different `Behaviour` value and call `GetConsensusExtraData`.

The `GetConsensusBlockExtraData` method switches on the provided `triggerInformation.Behaviour` without any validation that this behavior is correct for the current consensus state: [2](#0-1) 

The validation system in `ValidateBeforeExecution` uses this untrusted `Behaviour` field to determine which validators to apply: [3](#0-2) 

When `Behaviour=TinyBlock`, the `UpdateValueValidationProvider` and `LibInformationValidationProvider` are never added to the validation pipeline, allowing the miner to bypass these critical checks.

The `GetConsensusBehaviour()` method that determines correct behavior is never called during validation to verify the provided behavior is correct. [4](#0-3) 

**Attack Execution Path:**

1. Miner receives correct behavior (UpdateValue) from `GetConsensusCommand`
2. Miner crafts trigger information with `Behaviour=TinyBlock`
3. System generates consensus extra data for TinyBlock instead of UpdateValue
4. Transaction `UpdateTinyBlockInformation` is generated instead of `UpdateValue`: [5](#0-4) 
5. `ProcessTinyBlock` executes, performing minimal state updates: [6](#0-5) 
6. Critical consensus data (OutValue, Signature, PreviousInValue) is never published
7. LIB calculation is completely skipped

In contrast, `ProcessUpdateValue` should update all critical consensus fields including OutValue, Signature, PreviousInValue, and calculate LIB height: [7](#0-6) 

The LIB calculation logic that should execute (lines 268-282) is completely bypassed when ProcessTinyBlock runs instead.

The `TimeSlotValidationProvider` does not prevent this attack because when the miner's `latestActualMiningTime` is null (first block in their time slot), the validation passes immediately: [8](#0-7) 

## Impact Explanation

This vulnerability breaks fundamental consensus invariants with severe consequences:

**Consensus Random Number Generation Broken**: The `OutValue` and `Signature` fields are essential for the consensus random number generation mechanism. Without their publication, the random hash chain breaks, affecting any protocol logic depending on secure randomness.

**Secret Sharing Mechanism Bypassed**: The `PreviousInValue` field is critical for the secret sharing mechanism in AEDPoS. Skipping its update disrupts the distributed random number generation across miners.

**Chain Finality Completely Stalled**: The LIB (Last Irreversible Block) height calculation is skipped entirely. The code in ProcessUpdateValue that computes and updates `ConfirmedIrreversibleBlockHeight` (lines 268-282) never executes, preventing finality from advancing. The `IrreversibleBlockFound` event is never fired, blocking all systems dependent on finality confirmations.

**Critical Validators Bypassed**: Both `UpdateValueValidationProvider` [9](#0-8)  and `LibInformationValidationProvider` [10](#0-9)  are completely bypassed, allowing invalid consensus state transitions.

## Likelihood Explanation

**High Likelihood** - This attack is easily executable by any malicious miner:

**Attacker Prerequisites**: 
- Must be a valid miner in the current round (realistic for compromised or malicious miner)
- Must be in their designated time slot
- Requires no cryptographic breaks or special privileges

**Attack Complexity**: Very low. The attack requires only:
1. Receiving the correct consensus command with `Behaviour=UpdateValue`
2. Manually crafting trigger information with `Behaviour=TinyBlock` 
3. Calling `GetConsensusExtraData` with manipulated trigger
4. Creating and signing block with manipulated consensus extra data

**Feasibility**: The attack bypasses all existing validations because:
- `MiningPermissionValidationProvider` only checks if sender is in miner list ✓
- `TimeSlotValidationProvider` checks timing but not behavior type ✓  
- `ContinuousBlocksValidationProvider` checks block count limits ✓
- No validator checks behavior correctness ✗

**Detection Difficulty**: Medium. The block appears valid to other validators. Monitoring systems would need to independently compute expected `Behaviour` and compare with actual. Symptoms like missing OutValue and stalled LIB would appear but root cause may not be immediately obvious.

**Economic Rationality**: High impact on chain operation with minimal cost - attacker pays only normal block production costs and can repeatedly exploit in their time slots.

## Recommendation

Add a behavior correctness validator to the validation pipeline that:

1. Independently calculates the expected `Behaviour` using the same logic as `GetConsensusBehaviour()`
2. Compares the calculated expected behavior with the provided behavior in the consensus extra data
3. Rejects blocks where the provided behavior doesn't match the expected behavior

Implement a `BehaviourCorrectnessValidationProvider` that should be added to the validation providers list for ALL behaviors:

```csharp
public class BehaviourCorrectnessValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var expectedBehaviour = DetermineExpectedBehaviour(
            validationContext.BaseRound, 
            validationContext.SenderPubkey,
            validationContext.MaximumBlocksCount,
            validationContext.CurrentBlockTime
        );
        
        if (validationContext.ExtraData.Behaviour != expectedBehaviour)
        {
            return new ValidationResult 
            { 
                Success = false,
                Message = $"Incorrect behaviour. Expected: {expectedBehaviour}, Provided: {validationContext.ExtraData.Behaviour}"
            };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Add this validator to the basic providers list in `ValidateBeforeExecution` before the behavior-specific switch statement.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a consensus round with a valid miner
2. Call `GetConsensusCommand` to obtain the correct behavior (UpdateValue)
3. Craft trigger information with `Behaviour=TinyBlock`
4. Call `GetConsensusExtraData` with the manipulated trigger
5. Call `ValidateConsensusBeforeExecution` - observe it passes validation
6. Generate and execute the consensus transaction
7. Verify that `ProcessTinyBlock` was called instead of `ProcessUpdateValue`
8. Verify that OutValue, Signature, and PreviousInValue remain unset
9. Verify that LIB height was not updated

The test would prove that a miner can successfully produce blocks with incorrect behavior, bypassing critical consensus state updates.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L39-46)
```csharp
        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L148-162)
```csharp
            case AElfConsensusBehaviour.TinyBlock:
                var minerInRound = round.RealTimeMinersInformation[pubkey.ToHex()];
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateTinyBlockInformation),
                            new TinyBlockInput
                            {
                                ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
                                ProducedBlocks = minerInRound.ProducedBlocks,
                                RoundId = round.RoundIdForValidation,
                                RandomNumber = randomNumber
                            })
                    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L26-48)
```csharp
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextRound:
                information = GetConsensusExtraDataForNextRound(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextTerm:
                information = GetConsensusExtraDataForNextTerm(pubkey, triggerInformation);
                break;
        }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```
