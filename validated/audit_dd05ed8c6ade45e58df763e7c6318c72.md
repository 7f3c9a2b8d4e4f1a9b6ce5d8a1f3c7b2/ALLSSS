# Audit Report

## Title
Missing Consensus Behaviour Validation Allows Miners to Force Incorrect Round Transitions

## Summary
The AEDPoS consensus contract accepts miner-provided consensus behaviour values without validating they match the correct behaviour for the current consensus state. This allows malicious miners to force premature round transitions (NextRound instead of UpdateValue) or incorrect term changes, disrupting consensus integrity and triggering unintended economic events.

## Finding Description

The vulnerability exists in the consensus behaviour validation flow where the contract accepts and processes behaviour values without verifying their correctness against the actual consensus state.

The `GetConsensusBlockExtraData()` function receives a behaviour value from caller-provided trigger information and directly switches on it to determine which consensus logic to execute, without any validation that this behaviour is appropriate for the current consensus state. [1](#0-0) 

The input is passed through `GetConsensusExtraData()` without any validation of behaviour correctness. [2](#0-1) 

The correct behaviour should be determined by `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` which calculates the expected behaviour based on round state, miner status, time slots, and consensus parameters. [3](#0-2) 

However, the validation in `ValidateBeforeExecution()` never recalculates the expected behaviour to compare against the provided one. Instead, it only applies behaviour-specific structural validators. [4](#0-3) 

The `RoundTerminateValidationProvider` only validates structural correctness for NextRound/NextTerm behaviours (round number increments by 1, InValues are null) but never validates WHETHER a round termination should occur at this point based on consensus rules. [5](#0-4) 

**Attack Scenario:**
1. Malicious miner queries `GetConsensusCommand()` which correctly returns UpdateValue behaviour for their current time slot
2. Miner constructs custom `AElfConsensusTriggerInformation` with NextRound behaviour instead
3. Miner calls `GetConsensusExtraData()` with this manipulated trigger information
4. Contract generates NextRound consensus data (round number +1, null InValues)
5. Miner produces block with this NextRound consensus information
6. Block validation passes all structural checks (mining permission, time slot structure, round number increment)
7. NextRound transaction executes, prematurely terminating the round [6](#0-5) 
8. Other miners who should have produced blocks in the current round are skipped

## Impact Explanation

**HIGH Impact** - This vulnerability breaks fundamental consensus guarantees:

1. **Consensus Integrity**: Allows arbitrary manipulation of round transitions, violating the consensus state machine that determines when rounds should end based on miner participation and timing rules.

2. **Miner Participation Bypass**: Premature round transitions skip legitimate miners who haven't produced their blocks yet, disrupting fair block production rotation and violating the consensus algorithm's fairness guarantees.

3. **Economic Impact**: Incorrect term transitions trigger premature treasury releases and election snapshots, affecting reward distribution timing and the economic model. [7](#0-6) 

4. **LIB Calculation Disruption**: Incorrect round data affects Last Irreversible Block height calculations, potentially compromising finality guarantees required for cross-chain operations.

5. **Protocol-Wide Impact**: Since consensus integrity is fundamental to blockchain operations, this affects all protocol functions including token transfers, contract execution, and governance decisions that depend on block finality.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood**:

**Attacker Capabilities**: Any miner in the current miner list can execute this attack. Miners are expected participants obtainable through the standard election mechanism.

**Attack Complexity**: LOW - The attacker only needs to:
- Observe the correct behaviour via `GetConsensusCommand()` (a view method)
- Construct trigger information with a different behaviour value
- Generate structurally valid data (e.g., round number +1, null InValues for NextRound)
- Produce the block during their allocated time slot

**Feasibility**: The attack requires no special permissions beyond normal mining rights. It passes all existing validations because they only check structural correctness (round number increments by 1, InValues are null), not semantic correctness of the behaviour choice (whether a round termination should occur at this point).

**Detection**: The attack is not immediately obvious as all validation checks pass. Detection requires off-chain comparison of expected versus actual behaviour, which is not performed by the contract.

## Recommendation

Add semantic behaviour validation in `ValidateBeforeExecution()` that recalculates the expected consensus behaviour and compares it against the provided behaviour:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // NEW: Calculate expected behaviour and validate against provided
    var blockchainStartTimestamp = GetBlockchainStartTimestamp();
    var expectedBehaviour = IsMainChain
        ? new MainChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
                GetMaximumBlocksCount(), Context.CurrentBlockTime, blockchainStartTimestamp, 
                State.PeriodSeconds.Value).GetConsensusBehaviour()
        : new SideChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
                GetMaximumBlocksCount(), Context.CurrentBlockTime).GetConsensusBehaviour();
    
    if (expectedBehaviour != extraData.Behaviour)
        return new ValidationResult 
        { 
            Success = false, 
            Message = $"Incorrect consensus behaviour. Expected: {expectedBehaviour}, Provided: {extraData.Behaviour}" 
        };

    // Continue with existing validation logic...
}
```

This ensures that the provided behaviour matches what the consensus rules dictate for the current state, preventing miners from arbitrarily forcing incorrect round or term transitions.

## Proof of Concept

A malicious miner can demonstrate this vulnerability by:

1. During their legitimate time slot when `GetConsensusCommand()` returns `UpdateValue`
2. Constructing `AElfConsensusTriggerInformation` with `Behaviour = NextRound` instead
3. Calling `GetConsensusExtraData()` with this manipulated trigger information
4. Producing a block with the resulting NextRound consensus data
5. The block will pass validation despite being semantically incorrect
6. The `NextRound` transaction will execute, prematurely advancing the round and skipping other miners

The test would verify that:
- A miner can successfully produce a block with NextRound behaviour when UpdateValue is expected
- The block passes all validation checks
- The round advances prematurely
- Subsequent miners in the current round are skipped

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L13-53)
```csharp
    private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);

        Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");

        TryToGetCurrentRoundInformation(out var currentRound);

        var publicKeyBytes = triggerInformation.Pubkey;
        var pubkey = publicKeyBytes.ToHex();

        var information = new AElfConsensusHeaderInformation();
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

        if (!isGeneratingTransactions) information.Round.DeleteSecretSharingInformation();

        return information.ToBytesValue();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-218)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```
