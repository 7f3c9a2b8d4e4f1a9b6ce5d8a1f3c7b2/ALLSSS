# Audit Report

## Title
Consensus Permanent DoS via Unconstrained LIB Injection in NextTerm/NextRound Transactions

## Summary
The AEDPoS consensus contract lacks Last Irreversible Block (LIB) validation for `NextTerm` and `NextRound` transaction behaviors. A malicious miner can inject arbitrarily high `ConfirmedIrreversibleBlockHeight` values during term/round transitions, permanently corrupting consensus state and halting all block production until a hard fork is deployed.

## Finding Description

The validation logic in `ValidateBeforeExecution` applies different validation providers based on consensus behavior. For `UpdateValue` behavior, it correctly includes `LibInformationValidationProvider` to ensure LIB values cannot decrease. However, for `NextTerm` and `NextRound` behaviors, this critical validation is omitted. [1](#0-0) 

The `RoundTerminateValidationProvider` applied to `NextTerm` only validates round/term number increments and InValue nullness, but does NOT validate LIB values: [2](#0-1) 

When processing `NextTerm`, the transaction input's LIB values are directly copied to the new round without validation through the `ToRound()` method: [3](#0-2) 

This corrupted round is then persisted to blockchain state: [4](#0-3) [5](#0-4) 

The same vulnerability exists in `NextRound` transactions: [6](#0-5) [7](#0-6) 

Once the LIB is corrupted with a very high value (e.g., `Int64.MaxValue - 1000`), all subsequent `UpdateValue` transactions fail validation because `LibInformationValidationProvider` rejects backward LIB movement: [8](#0-7) 

This creates a permanent consensus deadlock because:

1. When a miner's `OutValue` is `null` (first block in time slot), the consensus system returns `UpdateValue` behavior: [9](#0-8) [10](#0-9) 

2. The `UpdateValue` transaction fails LIB validation (corrupted baseRound LIB > real providedRound LIB)

3. Without `UpdateValue` succeeding, `OutValue` remains `null`

4. `TinyBlock` production requires `OutValue != null`: [11](#0-10) 

5. No blocks can be produced, resulting in complete consensus halt

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables a complete denial-of-service attack on the entire blockchain with permanent consequences:

- **Blockchain Halt:** All block production ceases immediately once miners attempt to produce blocks after the corrupted term/round transition
- **Transaction Impossibility:** No transactions can be included in blocks, effectively freezing all on-chain activity
- **Hard Fork Required:** The only recovery mechanism is deploying a hard fork with corrected state, requiring coordinated emergency response
- **Economic Damage:** All trading, DeFi operations, and smart contract executions are halted indefinitely
- **No Automated Recovery:** Unlike temporary network issues, this corruption is permanent in the blockchain state

The attack breaks the fundamental consensus invariant that Last Irreversible Block height must monotonically increase. Once violated through state corruption rather than legitimate consensus, the system cannot self-recover.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible with minimal barriers:

**Attacker Prerequisites:**
- Must be an active miner in the current consensus round (miners are elected through governance, making this a realistic semi-privileged threat model)
- Multiple miners typically exist in production deployments

**Attack Complexity: LOW**
1. Wait for legitimate term/round transition period
2. Call `GenerateConsensusTransactions` to obtain valid `NextTermInput`/`NextRoundInput`
3. Modify the `ConfirmedIrreversibleBlockHeight` field to a very high value (e.g., `Int64.MaxValue - 1000`)
4. Sign and submit the modified transaction

**Technical Feasibility:**
- No cryptographic challenges or timing races
- Validation gap is systematic and architectural, not a race condition
- Attack is deterministic and 100% reproducible
- Transaction appears valid until corruption manifests in subsequent rounds

**Economic Cost:** Minimal (only standard transaction gas fees)

**Detection:** The malicious transaction may appear normal during validation, with corruption only becoming apparent when miners attempt to produce blocks in the next round and all fail validation.

## Recommendation

Add `LibInformationValidationProvider` to the validation chain for both `NextTerm` and `NextRound` behaviors in the `ValidateBeforeExecution` method:

```csharp
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
}
```

This ensures that LIB values in `NextTerm` and `NextRound` transactions cannot decrease, maintaining the monotonicity invariant across all consensus behaviors.

## Proof of Concept

```csharp
[Fact]
public async Task NextTerm_LIB_Injection_Causes_Consensus_Halt()
{
    // Setup: Complete first round
    await AEDPoSContract_FirstRound_BootMiner_Test();
    await ProduceBlocks(BootMinerKeyPair, InitialCoreDataCenterKeyPairs, 1);
    
    // Get legitimate NextTerm input
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var nextTermInput = GenerateNextTermInput(currentRound);
    
    // ATTACK: Inject extremely high LIB value
    nextTermInput.ConfirmedIrreversibleBlockHeight = long.MaxValue - 1000;
    
    // Execute malicious NextTerm - should pass validation (vulnerability)
    var result = await AEDPoSContractStub.NextTerm.SendAsync(nextTermInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify corruption: LIB is now set to malicious value
    var corruptedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    corruptedRound.ConfirmedIrreversibleBlockHeight.ShouldBe(long.MaxValue - 1000);
    
    // IMPACT: All subsequent UpdateValue transactions fail
    KeyPairProvider.SetKeyPair(InitialCoreDataCenterKeyPairs[0]);
    var consensusCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(
        TriggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue()));
    
    var extraDataBytes = await AEDPoSContractStub.GetConsensusExtraData.CallAsync(
        TriggerInformationProvider.GetTriggerInformationForBlockHeaderExtraData(consensusCommand.ToBytesValue()));
    
    // Validation fails because real LIB < corrupted LIB in state
    var validationResult = await AEDPoSContractStub.ValidateConsensusBeforeExecution.CallAsync(extraDataBytes);
    validationResult.Success.ShouldBeFalse();
    validationResult.Message.ShouldContain("Incorrect lib information");
    
    // Consensus is permanently halted - no blocks can be produced
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw in the consensus validation system where different behaviors receive inconsistent security guarantees. The LIB monotonicity invariant is only enforced for `UpdateValue` transactions but not for round/term transitions, creating a permanent DoS vector. The attack requires miner privileges but these are legitimately obtainable through governance, making this a realistic threat in production environments.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-47)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-156)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-20)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-79)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-115)
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
        }
```
