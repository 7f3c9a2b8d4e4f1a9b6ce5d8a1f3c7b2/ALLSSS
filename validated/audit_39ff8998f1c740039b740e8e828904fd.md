# Audit Report

## Title
Consensus Permanent DoS via Unconstrained LIB Injection in NextTerm Transactions

## Summary
The `NextTerm` transaction validation path lacks `LibInformationValidationProvider` checks, allowing a malicious miner to inject arbitrarily high `ConfirmedIrreversibleBlockHeight` values into consensus state. Once corrupted, all subsequent `UpdateValue` transactions fail validation, permanently halting block production and requiring a hard fork to recover.

## Finding Description

The consensus validation framework applies different validation providers based on transaction behavior type. While `UpdateValue` transactions receive comprehensive validation including LIB checks, `NextTerm` transactions bypass this critical validation. [1](#0-0) 

The `LibInformationValidationProvider` validates that LIB values cannot move backward, rejecting any round where the base round's confirmed irreversible block height exceeds the provided round's value: [2](#0-1) 

However, `RoundTerminateValidationProvider` (the only validator applied to `NextTerm`) only checks round/term number increments and InValue nullness, completely ignoring LIB values: [3](#0-2) 

When processing `NextTerm`, the transaction input's LIB values are directly copied to the new round without any validation: [4](#0-3) 

This malicious round is then persisted to state through the processing chain: [5](#0-4) [6](#0-5) 

Once the corrupted LIB is in state, subsequent `UpdateValue` transactions calculate the real LIB but fail validation because the loaded `baseRound` contains the corrupted high value, causing the backward movement check to fail.

The critical impact occurs because when a miner's `OutValue` is null (first block in time slot), the consensus behavior logic mandates `UpdateValue`: [7](#0-6) [8](#0-7) 

Without successful `UpdateValue` execution, `OutValue` remains null. TinyBlock production requires `OutValue != null`, as evidenced by the behavior logic structure where TinyBlock is only returned in the else branch after checking for null OutValue: [9](#0-8) 

This creates a deadlock where no blocks can be produced.

## Impact Explanation

**CRITICAL** - Complete consensus halt with catastrophic consequences:

1. **Blockchain Freeze**: Once LIB is corrupted, miners cannot produce any blocks because UpdateValue (required for first block when OutValue is null) fails validation, and TinyBlock (requires OutValue != null) cannot be produced.

2. **Permanent State Corruption**: The corrupted LIB value persists in blockchain state through the State.Rounds mapping and cannot be corrected through normal consensus operations.

3. **Network-Wide Impact**: All validators are affected simultaneously - no subset of honest miners can recover the chain since the corrupted state blocks all consensus progress.

4. **Recovery Cost**: Requires emergency hard fork coordinating all network participants, with significant downtime and coordination overhead.

5. **Transaction Blackout**: All pending user transactions remain unprocessed indefinitely during the halt period.

## Likelihood Explanation

**HIGH** likelihood due to:

1. **Attacker Requirements**: Only requires being an elected miner, which is achievable through the governance election mechanism. The threat model assumes miners may be malicious.

2. **Attack Complexity**: LOW - The attacker:
   - Waits for legitimate term transition period
   - Obtains valid NextTermInput (via GenerateConsensusTransactions)
   - Modifies the `ConfirmedIrreversibleBlockHeight` field to an extremely high value (e.g., Int64.MaxValue - 1000)
   - Submits the modified transaction during their mining slot

3. **Technical Feasibility**: No cryptographic challenges, no race conditions, no complex timing requirements. Miners have full control over transactions they include in blocks they produce.

4. **Detection Difficulty**: The malicious transaction appears valid during submission and only manifests as a problem in subsequent rounds when other miners attempt UpdateValue transactions.

5. **Economic Cost**: Minimal - only standard transaction gas fees required.

## Recommendation

Add `LibInformationValidationProvider` to the validation provider list for `NextTerm` behavior in the `ValidateBeforeExecution` method:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
```

Additionally, consider adding the same protection for `NextRound` behavior to prevent similar attacks during round transitions.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousNextTerm_CorruptsLIB_CausesConsensusHalt()
{
    // Setup: Initialize consensus with normal term
    await InitializeConsensusAsync();
    
    // Attacker (malicious miner) obtains valid NextTermInput
    var validNextTermInput = await GetValidNextTermInputAsync();
    
    // Attacker corrupts LIB value
    var maliciousNextTermInput = validNextTermInput.Clone();
    maliciousNextTermInput.ConfirmedIrreversibleBlockHeight = long.MaxValue - 1000;
    
    // Execute malicious NextTerm - should pass validation (no LIB check)
    var result = await ConsensusStub.NextTerm.SendAsync(maliciousNextTermInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify corrupted LIB is now in state
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    currentRound.ConfirmedIrreversibleBlockHeight.ShouldBe(long.MaxValue - 1000);
    
    // Next miner attempts UpdateValue (required for first block)
    var updateValueInput = await GenerateUpdateValueInputAsync();
    
    // UpdateValue validation should FAIL due to LIB backward movement check
    var updateResult = await ConsensusStub.UpdateValue.SendWithExceptionAsync(updateValueInput);
    updateResult.TransactionResult.Error.ShouldContain("Incorrect lib information");
    
    // Chain is now halted - no more blocks can be produced
    // Verify TinyBlock also cannot be produced
    var tinyBlockInput = await GenerateTinyBlockInputAsync();
    var tinyBlockResult = await ConsensusStub.UpdateTinyBlockInformation.SendWithExceptionAsync(tinyBlockInput);
    // TinyBlock will fail because OutValue is still null (UpdateValue never succeeded)
}
```

## Notes

The vulnerability affects `NextTerm` behavior definitively. While `NextRound` also lacks `LibInformationValidationProvider`, it includes `NextRoundMiningOrderValidationProvider` which may provide some additional constraints. However, both should receive LIB validation for defense in depth.

The attack is particularly dangerous because:
1. It exploits a validation gap in critical consensus state transitions
2. The corrupted state persists permanently in the blockchain
3. Normal recovery mechanisms (like consensus reconfiguration) cannot fix it
4. Detection only occurs after the damage is done (in subsequent rounds)

This represents a severe consensus integrity violation that breaks the fundamental blockchain availability guarantee.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-62)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-114)
```csharp
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;

            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;

            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
```
