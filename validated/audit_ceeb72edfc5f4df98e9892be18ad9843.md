# Audit Report

## Title
Consensus Behavior Manipulation Allows Bypass of Critical Validators and Disruption of Consensus Integrity

## Summary
A malicious miner can manipulate the `Behaviour` field in consensus header information to switch from `UpdateValue` to `TinyBlock` behavior, bypassing critical validators and causing wrong consensus transaction execution. This breaks random number generation and halts Last Irreversible Block (LIB) height calculation, stalling chain finality progression.

## Finding Description

The AEDPoS consensus validation system has a critical flaw where the `Behaviour` field from the block header's consensus extra data determines which validators apply, but there is **no validation** that this `Behaviour` matches what consensus rules dictate.

**The Vulnerability Flow:**

1. **Validator Selection Based on Untrusted Behaviour**: The `ValidateBeforeExecution` method switches on `extraData.Behaviour` to determine which validators to apply [1](#0-0) . For `TinyBlock` behaviour, only base validators are added, while `UpdateValue` behaviour adds `UpdateValueValidationProvider` and `LibInformationValidationProvider`.

2. **No Behaviour Correctness Check**: While the system can calculate the correct behaviour using `GetConsensusBehaviour()` [2](#0-1) , this calculated behaviour is **never validated** against the `Behaviour` value provided in the block header.

3. **Miner Controls Trigger Information**: The `GetConsensusBlockExtraData` method directly uses `triggerInformation.Behaviour` without validation [3](#0-2)  and returns consensus header information with the untrusted behaviour value [4](#0-3) .

4. **Wrong Transaction Generated**: When `GenerateConsensusTransactions` processes the manipulated behaviour, it switches on the provided behaviour to generate either `UpdateValue` or `UpdateTinyBlockInformation` transactions [5](#0-4) .

5. **State Corruption**: `ProcessTinyBlock` only updates minimal fields (ActualMiningTimes, ProducedBlocks, ProducedTinyBlocks) [6](#0-5) , while `ProcessUpdateValue` updates critical consensus data including OutValue, Signature, PreviousInValue [7](#0-6)  and calculates LIB height [8](#0-7) .

**Attack Scenario:**
1. Malicious miner should produce `UpdateValue` behaviour per consensus rules
2. Miner crafts trigger information with `Behaviour=TinyBlock`
3. Miner calls `GetConsensusExtraData` with manipulated trigger
4. Creates block with this manipulated consensus extra data
5. Block passes validation because `UpdateValueValidationProvider` and `LibInformationValidationProvider` are never added for `TinyBlock` behaviour
6. `ProcessTinyBlock` executes instead of `ProcessUpdateValue`, leaving OutValue, Signature, and LIB uncalculated

## Impact Explanation

**Critical Consensus Invariants Broken:**

1. **Random Number Generation Failure**: The `UpdateValueValidationProvider` enforces that OutValue and Signature are not null [9](#0-8) . These values are essential for consensus random number generation. When `ProcessTinyBlock` executes, these fields are never set, breaking the random hash chain.

2. **Chain Finality Stalled**: The LIB (Last Irreversible Block) height calculation and `IrreversibleBlockFound` event only execute in `ProcessUpdateValue` [8](#0-7) . The `ProcessTinyBlock` method completely skips this calculation [6](#0-5) , preventing finality from advancing.

3. **Validation Bypasses**: The `LibInformationValidationProvider` checks that LIB height doesn't regress [10](#0-9) . Both this validator and `UpdateValueValidationProvider` are completely bypassed when `Behaviour=TinyBlock`.

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
- The consensus contract methods (`GetConsensusExtraData`, `GenerateConsensusTransactions`) are publicly callable [11](#0-10) 
- No detection mechanism exists to identify behaviour manipulation
- Symptoms (missing OutValue, stalled LIB) would appear gradually, obscuring root cause

## Recommendation

Add behaviour validation in `GetConsensusBlockExtraData` to ensure the provided behaviour matches the calculated correct behaviour:

```csharp
private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
{
    var triggerInformation = new AElfConsensusTriggerInformation();
    triggerInformation.MergeFrom(input.Value);

    Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");

    TryToGetCurrentRoundInformation(out var currentRound);

    var publicKeyBytes = triggerInformation.Pubkey;
    var pubkey = publicKeyBytes.ToHex();

    // VALIDATE BEHAVIOUR CORRECTNESS
    var expectedBehaviour = IsMainChain
        ? new MainChainConsensusBehaviourProvider(currentRound, pubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime, GetBlockchainStartTimestamp(), State.PeriodSeconds.Value)
            .GetConsensusBehaviour()
        : new SideChainConsensusBehaviourProvider(currentRound, pubkey,
            GetMaximumBlocksCount(),
            Context.CurrentBlockTime).GetConsensusBehaviour();
    
    Assert(triggerInformation.Behaviour == expectedBehaviour, 
        $"Invalid behaviour. Expected: {expectedBehaviour}, Provided: {triggerInformation.Behaviour}");

    // Continue with existing logic...
}
```

## Proof of Concept

Due to the complexity of the AElf consensus system setup, a full end-to-end test would require:

1. Initialize a consensus round with multiple miners
2. Set up a scenario where a miner should produce `UpdateValue` behaviour
3. Have the miner call `GetConsensusExtraData` with `Behaviour=TinyBlock` instead
4. Verify the block passes validation despite wrong behaviour
5. Verify `OutValue` and `Signature` remain null, and LIB calculation is skipped

The vulnerability is confirmed by code analysis showing:
- No validation of behaviour correctness exists in any code path
- Validator selection depends on the untrusted behaviour field
- Different code paths execute based on the manipulated behaviour value

## Notes

This vulnerability represents a fundamental trust assumption violation in the AEDPoS consensus design. The system assumes miners will honestly provide correct behaviour values, but provides no enforcement mechanism. This allows a single malicious miner to disrupt critical consensus operations affecting the entire chain.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L128-133)
```csharp
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-75)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }

    public override TransactionList GenerateConsensusTransactions(BytesValue input)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);
        // Some basic checks.
        Assert(triggerInformation.Pubkey.Any(),
            "Data to request consensus information should contain pubkey.");

        var pubkey = triggerInformation.Pubkey;
        var randomNumber = triggerInformation.RandomNumber;
        var consensusInformation = new AElfConsensusHeaderInformation();
        consensusInformation.MergeFrom(GetConsensusBlockExtraData(input, true).Value);
        var transactionList = GenerateTransactionListByExtraData(consensusInformation, pubkey, randomNumber);
        return transactionList;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L134-163)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-30)
```csharp
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
```
