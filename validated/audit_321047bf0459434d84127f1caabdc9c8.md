# Audit Report

## Title
Consensus Behavior Manipulation Allows Bypass of Critical Validators and Disruption of Consensus Integrity

## Summary
A malicious miner can manipulate the `Behaviour` field in consensus header information to switch from `UpdateValue` to `TinyBlock` behavior, bypassing critical validators (`UpdateValueValidationProvider` and `LibInformationValidationProvider`). This causes wrong consensus transaction execution, breaks random number generation, and halts Last Irreversible Block (LIB) height calculation, stalling chain finality progression.

## Finding Description

The AEDPoS consensus validation system has a critical flaw where the `Behaviour` field from the block header's consensus extra data is used to determine which validators to apply, but there is **no validation** that verifies this `Behaviour` matches what the consensus rules actually dictate.

**The Vulnerability Flow:**

1. **Validator Selection Based on Untrusted Behaviour**: The `ValidateBeforeExecution` method uses the `Behaviour` field directly from deserialized consensus header information to select which validators to apply via a switch statement. [1](#0-0) 

2. **No Behaviour Correctness Check**: The system determines the correct behaviour using `ConsensusBehaviourProviderBase.GetConsensusBehaviour()`, but this calculated behaviour is **never validated** against the `Behaviour` value provided in the block header. [2](#0-1) 

3. **Miner Controls Trigger Information**: The `GetConsensusBlockExtraData` method directly uses `triggerInformation.Behaviour` without validation, and since `GetConsensusExtraData` is a public view method, any miner can call it with arbitrary trigger information. [3](#0-2) [4](#0-3) 

4. **Wrong Transaction Generated**: When `GenerateTransactionListByExtraData` processes the manipulated behaviour, it generates `UpdateTinyBlockInformation` transaction instead of `UpdateValue` transaction based on the behaviour field. [5](#0-4) 

5. **State Corruption**: `ProcessTinyBlock` only updates minimal fields (ActualMiningTimes, ProducedBlocks, ProducedTinyBlocks), while `ProcessUpdateValue` updates critical consensus data including OutValue, Signature, PreviousInValue, and calculates LIB height. [6](#0-5) [7](#0-6) 

**Attack Scenario:**
1. Malicious miner receives consensus command indicating `Behaviour=UpdateValue`
2. Miner manually crafts `AElfConsensusTriggerInformation` with `Behaviour=TinyBlock`
3. Miner calls `GetConsensusExtraData` with manipulated trigger, receiving extra data with `Behaviour=TinyBlock`
4. Miner creates and signs block with this manipulated consensus extra data
5. Block passes validation because `UpdateValueValidationProvider` and `LibInformationValidationProvider` are never added to the validation pipeline for `TinyBlock` behaviour
6. `ProcessTinyBlock` executes instead of `ProcessUpdateValue`, leaving OutValue, Signature, and LIB uncalculated

## Impact Explanation

**Critical Consensus Invariants Broken:**

1. **Random Number Generation Failure**: `OutValue` and `Signature` are never published when `ProcessTinyBlock` executes instead of `ProcessUpdateValue`. The `UpdateValue` transaction should update these fields, but `UpdateTinyBlockInformation` transaction does not include them. These values are essential for the consensus random number generation and verifiable delay function.

2. **Secret Sharing Mechanism Disrupted**: The secret sharing mechanism for consensus random number generation relies on proper `OutValue` and `Signature` publication through `ProcessUpdateValue`, which includes calls to `PerformSecretSharing`. [8](#0-7) 

3. **Chain Finality Stalled**: The LIB (Last Irreversible Block) height calculation only executes in `ProcessUpdateValue` through `LastIrreversibleBlockHeightCalculator` and is completely skipped in `ProcessTinyBlock`, preventing finality from advancing. The `IrreversibleBlockFound` event is never fired, blocking all dependent systems waiting for finality confirmations. [9](#0-8) 

**Validation Bypasses:**

The `UpdateValueValidationProvider` checks that OutValue and Signature are not null and validates PreviousInValue correctness. [10](#0-9) 

The `LibInformationValidationProvider` checks that LIB height doesn't regress. [11](#0-10) 

Both validators are completely bypassed when `Behaviour=TinyBlock` as they are only added for `UpdateValue` behaviour.

**Severity: HIGH** - This breaks fundamental consensus security guarantees, halts finality progression, disrupts random number generation, and can lead to complete chain instability.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a valid miner in the current round (realistic - any miner or compromised miner node)
- Must be operating within their designated time slot (standard mining constraint)
- Has full control over block creation and consensus extra data (inherent miner capability)

**Attack Complexity: LOW**
- Requires only manipulation of a single enum field in the trigger information
- No cryptographic breaks or complex timing attacks required
- Block passes all existing basic validations (mining permission, time slot, continuous blocks)
- Can be repeated in every time slot the malicious miner controls

**Feasibility: HIGH**
- A miner running modified node software can easily manipulate trigger information by directly calling `GetConsensusExtraData` with crafted input
- The consensus contract methods are publicly callable (view methods) without authorization checks [12](#0-11) 
- No detection mechanism exists to identify behaviour manipulation
- Symptoms (missing OutValue, stalled LIB) would appear gradually, obscuring root cause

**Economic Rationality:**
- Attacker incurs only normal block production costs
- High impact on chain operation with minimal investment
- Could be used for ransom (demand payment to stop attack) or to manipulate consensus-dependent systems

## Recommendation

Add behaviour validation in `ValidateBeforeExecution` to verify that the provided `Behaviour` matches what the consensus rules dictate:

1. Calculate the expected behaviour using `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` during validation
2. Compare the calculated behaviour against `extraData.Behaviour` 
3. Reject blocks where the behaviours don't match

Example fix location: In `ValidateBeforeExecution` method, after line 60, add:
- Calculate expected behaviour based on current round state, miner status, and timing
- Validate `extraData.Behaviour == expectedBehaviour`
- Return validation failure if mismatch detected

This ensures that miners cannot arbitrarily manipulate the behaviour field to bypass validators.

## Proof of Concept

A malicious miner can execute the following attack:

1. Call `GetConsensusCommand` to receive the legitimate consensus command with `Behaviour=UpdateValue` in the hint
2. Instead of using the legitimate trigger information provider, construct a custom `AElfConsensusTriggerInformation` message with:
   - `Pubkey` = miner's public key
   - `Behaviour` = `AElfConsensusBehaviour.TinyBlock` (manipulated)
   - Other required fields as needed
3. Call `GetConsensusExtraData` (public view method) with the crafted trigger information
4. Receive consensus header information with `Behaviour=TinyBlock`
5. Include this in the block header and produce the block
6. During `ValidateConsensusBeforeExecution`, the validation will:
   - Extract `Behaviour=TinyBlock` from the header
   - Add only basic validators (MiningPermissionValidationProvider, TimeSlotValidationProvider, ContinuousBlocksValidationProvider)
   - Skip adding UpdateValueValidationProvider and LibInformationValidationProvider
   - Pass validation
7. During block execution, `GenerateConsensusTransactions` will generate `UpdateTinyBlockInformation` transaction instead of `UpdateValue`
8. `ProcessTinyBlock` executes, leaving OutValue, Signature, and LIB height uncalculated

The attack succeeds because there is no validation that checks whether the `Behaviour` field matches what the consensus rules actually require for the current round state and miner status.

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

**File:** protobuf/acs4.proto (L24-27)
```text
    // Generate consensus extra data when a block is generated. 
    rpc GetConsensusExtraData (google.protobuf.BytesValue) returns (google.protobuf.BytesValue) {
        option (aelf.is_view) = true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L136-163)
```csharp
        {
            case AElfConsensusBehaviour.UpdateValue:
                Context.LogDebug(() =>
                    $"Previous in value in extra data:{round.RealTimeMinersInformation[pubkey.ToHex()].PreviousInValue}");
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
                };
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
                };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-49)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
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
