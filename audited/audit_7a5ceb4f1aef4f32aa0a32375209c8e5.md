# Audit Report

## Title
Consensus Behavior Manipulation Allows Bypass of Critical Validators and Disruption of Consensus Integrity

## Summary
A malicious miner can manipulate the `Behaviour` field in consensus header information to switch from `UpdateValue` to `TinyBlock` behavior, bypassing critical validators (`UpdateValueValidationProvider` and `LibInformationValidationProvider`). This causes wrong consensus transaction execution, breaks random number generation, and halts Last Irreversible Block (LIB) height calculation, stalling chain finality progression.

## Finding Description

The AEDPoS consensus validation system has a critical flaw where the `Behaviour` field from the block header's consensus extra data is used to determine which validators to apply, but there is **no validation** that verifies this `Behaviour` matches what the consensus rules actually dictate.

**The Vulnerability Flow:**

1. **Validator Selection Based on Untrusted Behaviour**: The `ValidateBeforeExecution` method uses the `Behaviour` field from deserialized consensus header information to select which validators to apply. [1](#0-0) 

2. **No Behaviour Correctness Check**: The system determines the correct behaviour using `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` [2](#0-1) , but this calculated behaviour is **never validated** against the `Behaviour` value provided in the block header.

3. **Miner Controls Trigger Information**: The `GetConsensusBlockExtraData` method directly uses `triggerInformation.Behaviour` without validation [3](#0-2) , and this trigger information is provided by the block producer (miner).

4. **Wrong Transaction Generated**: When `GenerateConsensusTransactions` processes the manipulated behaviour, it generates `UpdateTinyBlockInformation` transaction instead of `UpdateValue` transaction. [4](#0-3) 

5. **State Corruption**: `ProcessTinyBlock` only updates minimal fields (ActualMiningTimes, ProducedBlocks, ProducedTinyBlocks) [5](#0-4) , while `ProcessUpdateValue` updates critical consensus data including OutValue, Signature, PreviousInValue, and calculates LIB height. [6](#0-5) 

**Attack Scenario:**
1. Malicious miner receives consensus command indicating `Behaviour=UpdateValue`
2. Miner manually crafts trigger information with `Behaviour=TinyBlock`
3. Miner calls `GetConsensusExtraData` with manipulated trigger, receiving extra data with `Behaviour=TinyBlock`
4. Miner creates and signs block with this manipulated consensus extra data
5. Block passes validation because `UpdateValueValidationProvider` and `LibInformationValidationProvider` are never added to the validation pipeline for `TinyBlock` behaviour
6. `ProcessTinyBlock` executes instead of `ProcessUpdateValue`, leaving OutValue, Signature, and LIB uncalculated

## Impact Explanation

**Critical Consensus Invariants Broken:**

1. **Random Number Generation Failure**: `OutValue` and `Signature` are never published when `ProcessTinyBlock` executes instead of `ProcessUpdateValue`. These values are essential for the consensus random number generation and verifiable delay function. Without them, the consensus random hash chain breaks.

2. **Secret Sharing Mechanism Disrupted**: The secret sharing mechanism for consensus random number generation relies on proper `OutValue` and `Signature` publication, which are bypassed when wrong behaviour executes.

3. **Chain Finality Stalled**: The LIB (Last Irreversible Block) height calculation only executes in `ProcessUpdateValue` and is completely skipped in `ProcessTinyBlock`, preventing finality from advancing. The `IrreversibleBlockFound` event is never fired, blocking all dependent systems waiting for finality confirmations.

**Validation Bypasses:**

The `UpdateValueValidationProvider` checks that OutValue and Signature are not null and validates PreviousInValue correctness [7](#0-6) . The `LibInformationValidationProvider` checks that LIB height doesn't regress [8](#0-7) . Both validators are completely bypassed when `Behaviour=TinyBlock`.

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
- A miner running modified node software can easily manipulate trigger information
- The consensus contract methods are publicly callable by miners
- No detection mechanism exists to identify behaviour manipulation
- Symptoms (missing OutValue, stalled LIB) would appear gradually, obscuring root cause

**Economic Rationality:**
- Attacker incurs only normal block production costs
- High impact on chain operation with minimal investment
- Could be used for ransom (demand payment to stop attack) or to manipulate consensus-dependent systems

## Recommendation

Add explicit validation in `ValidateBeforeExecution` to verify the provided `Behaviour` matches the expected behaviour calculated by consensus rules:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // NEW: Validate that the provided Behaviour matches expected behaviour
    var blockchainStartTimestamp = GetBlockchainStartTimestamp();
    var behaviourProvider = IsMainChain
        ? new MainChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
            GetMaximumBlocksCount(), Context.CurrentBlockTime, blockchainStartTimestamp, 
            State.PeriodSeconds.Value)
        : new SideChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
            GetMaximumBlocksCount(), Context.CurrentBlockTime);
    
    var expectedBehaviour = behaviourProvider.GetConsensusBehaviour();
    
    if (extraData.Behaviour != expectedBehaviour)
        return new ValidationResult 
        { 
            Success = false, 
            Message = $"Invalid behaviour. Expected: {expectedBehaviour}, Provided: {extraData.Behaviour}" 
        };

    // Continue with existing validation logic...
}
```

This ensures that miners cannot manipulate the `Behaviour` field to bypass critical validators, as any mismatch between expected and provided behaviour will cause validation to fail.

## Proof of Concept

The following test demonstrates the vulnerability by showing a miner can produce a block with `Behaviour=TinyBlock` when `Behaviour=UpdateValue` is expected, bypassing `UpdateValueValidationProvider` and causing state corruption:

```csharp
[Fact]
public async Task MaliciousMiner_CanBypassValidators_ByManipulatingBehaviour()
{
    // Setup: Get to a state where UpdateValue is expected
    var minerKeyPair = InitialCoreDataCenterKeyPairs[0];
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(minerKeyPair.PublicKey),
        InValue = HashHelper.ComputeFrom("test"),
        PreviousInValue = Hash.Empty,
        Behaviour = AElfConsensusBehaviour.TinyBlock  // MANIPULATED - should be UpdateValue
    };
    
    // Miner calls GetConsensusExtraData with manipulated trigger
    var extraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
        triggerInfo.ToBytesValue());
    
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(
        extraData.Value.ToByteArray());
    
    // Verify manipulation succeeded
    headerInfo.Behaviour.ShouldBe(AElfConsensusBehaviour.TinyBlock);
    
    // Block validation passes (should fail but doesn't due to vulnerability)
    var validationResult = await ConsensusStub.ValidateConsensusBeforeExecution.CallAsync(
        extraData);
    validationResult.Success.ShouldBeTrue();  // Passes when it shouldn't!
    
    // Wrong transaction generated
    var transactions = await ConsensusStub.GenerateConsensusTransactions.CallAsync(
        triggerInfo.ToBytesValue());
    transactions.Transactions.First().MethodName.ShouldBe("UpdateTinyBlockInformation");
    // Should be "UpdateValue" but attacker bypassed it
    
    // Execute the wrong transaction
    await BlockMiningService.MineBlockAsync(transactions.Transactions);
    
    // Verify state corruption - OutValue not set
    var round = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo = round.RealTimeMinersInformation[minerKeyPair.PublicKey.ToHex()];
    minerInfo.OutValue.ShouldBeNull();  // VULNERABILITY: Critical value not updated
    minerInfo.Signature.ShouldBeNull(); // VULNERABILITY: Signature not published
}
```

This test proves that:
1. A miner can manipulate `Behaviour` in trigger information
2. Validation incorrectly passes
3. Wrong transaction executes (`UpdateTinyBlockInformation` instead of `UpdateValue`)
4. Critical consensus state (OutValue, Signature) is not updated, breaking consensus invariants

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L130-163)
```csharp
    private TransactionList GenerateTransactionListByExtraData(AElfConsensusHeaderInformation consensusInformation,
        ByteString pubkey, ByteString randomNumber)
    {
        var round = consensusInformation.Round;
        var behaviour = consensusInformation.Behaviour;
        switch (behaviour)
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
