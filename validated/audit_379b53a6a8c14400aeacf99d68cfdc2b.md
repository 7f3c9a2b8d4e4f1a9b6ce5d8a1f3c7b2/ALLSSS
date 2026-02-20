# Audit Report

## Title
TermNumber State Corruption via Unvalidated NextRound Allows Permanent Consensus Disruption

## Summary
The `ValidationForNextRound` method in the AEDPoS consensus contract fails to validate the TermNumber field, allowing malicious miners to inject arbitrary TermNumber values during NextRound transitions. This creates an irreconcilable state inconsistency between `State.CurrentTermNumber` and the TermNumber stored in `State.Rounds`, permanently blocking all subsequent NextTerm transitions and causing indefinite consensus disruption with no in-protocol recovery mechanism.

## Finding Description

The AEDPoS consensus contract contains a critical validation asymmetry in round/term transition logic. The `ValidationForNextRound` method only validates round number increments and InValue nullity, completely omitting TermNumber validation: [1](#0-0) 

In contrast, `ValidationForNextTerm` correctly validates both round and term number increments: [2](#0-1) 

When a NextRound transaction is processed, the input is converted to a Round object using `ToRound()`, which directly copies all fields including the attacker-controlled TermNumber: [3](#0-2) 

This malicious Round object is then persisted to `State.Rounds` storage via `AddRoundInformation`: [4](#0-3) 

However, `ProcessNextRound` only updates `State.CurrentRoundNumber`, leaving `State.CurrentTermNumber` unchanged: [5](#0-4) 

This creates a critical state desynchronization where:
- `State.CurrentTermNumber` retains the legitimate value N
- `State.Rounds[roundNumber].TermNumber` contains the malicious value (e.g., 999)

The validation context construction reveals this dual-source architecture where `BaseRound` is fetched from corrupted `State.Rounds` while `CurrentTermNumber` comes from the separate legitimate storage: [6](#0-5) 

The `TryToGetCurrentRoundInformation` method retrieves rounds from `State.Rounds`, which will contain the corrupted TermNumber after the attack: [7](#0-6) 

After state corruption, NextTerm transitions become impossible due to contradictory validation requirements. `ValidationForNextTerm` requires `BaseRound.TermNumber + 1 == input.TermNumber` (using the corrupted value from State.Rounds), while `TryToUpdateTermNumber` requires `State.CurrentTermNumber + 1 == input.TermNumber` (using the legitimate value): [8](#0-7) 

When `BaseRound.TermNumber` ≠ `State.CurrentTermNumber`, no input value can simultaneously satisfy both checks. The attacker only needs to be in the current or previous miner list, verified during PreCheck: [9](#0-8) 

## Impact Explanation

This vulnerability enables **permanent denial-of-service of term transitions**, which are critical to consensus and economic operations:

1. **Consensus Integrity Violation**: Once state desynchronization occurs, term progression is permanently blocked. No transaction can satisfy both the validation check (requiring `corrupted_value + 1`) and execution check (requiring `legitimate_value + 1`).

2. **Election Mechanism Failure**: Term transitions trigger miner list updates and election snapshots. Without term progression, the election cycle halts indefinitely, preventing miner set rotation.

3. **Economic Model Breakdown**: ProcessNextTerm contains critical economic operations that become permanently blocked: [10](#0-9) 

Treasury releases, mining reward donations, and election snapshots all depend on term transitions and become permanently halted.

4. **Persistence**: The corruption persists indefinitely. A grep search reveals `State.CurrentTermNumber` is only updated in two places: initialization in `FirstRound` and the now-unreachable `TryToUpdateTermNumber` during NextTerm execution.

5. **No Recovery Mechanism**: No in-protocol mechanism can resolve the desynchronization. Recovery requires out-of-band contract upgrade or manual state migration.

This constitutes **High severity** affecting core consensus, governance, and economic functionality with permanent impact.

## Likelihood Explanation

The attack has **High likelihood** due to:

1. **Low Complexity**: Single transaction with modified TermNumber field in NextRoundInput
2. **No Special Conditions**: Works at any point during normal consensus operation
3. **Realistic Attacker Requirements**: Must be a current or previous miner, which is an expected participant role, not a compromised system component
4. **100% Success Rate**: If attacker can mine a block during their time slot, the attack succeeds
5. **Undetectable During Execution**: No validation flags the malicious TermNumber during NextRound processing
6. **Delayed Discovery**: The corruption only becomes apparent when NextTerm is attempted, by which point state is already corrupted and irrecoverable

Given that miners have elevated but expected privileges in the consensus system, and that a single malicious miner can execute this attack with one transaction, the likelihood is **High**.

## Recommendation

Add TermNumber validation to `ValidationForNextRound` method in `RoundTerminateValidationProvider.cs`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number increment
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD THIS: Validate TermNumber remains unchanged during NextRound
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "TermNumber must remain unchanged during NextRound." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

This ensures the TermNumber field cannot be modified during NextRound transitions, preventing the state desynchronization attack.

## Proof of Concept

```csharp
[Fact]
public async Task TermNumberCorruption_BlocksNextTerm()
{
    // Setup: Initialize consensus with term 1
    var initialMiners = GenerateInitialMiners(3);
    await InitializeConsensus(initialMiners);
    
    // Advance through several normal rounds in term 1
    for (int i = 0; i < 5; i++)
    {
        await ProduceNormalRound();
    }
    
    var currentTermNumber = await GetCurrentTermNumber(); // Returns 1
    var currentRound = await GetCurrentRoundInformation();
    
    // Attack: Malicious miner submits NextRound with corrupted TermNumber
    var maliciousNextRound = GenerateNextRoundInput(currentRound);
    maliciousNextRound.TermNumber = 999; // Inject malicious TermNumber
    
    var result = await ExecuteNextRound(maliciousNextRound);
    result.Status.ShouldBe(TransactionResultStatus.Mined); // Transaction succeeds!
    
    // Verify state corruption
    var storedRound = await GetRoundInformation(currentRound.RoundNumber + 1);
    storedRound.TermNumber.ShouldBe(999); // Corrupted value in State.Rounds
    
    var termNumber = await GetCurrentTermNumber();
    termNumber.ShouldBe(1); // State.CurrentTermNumber unchanged
    
    // Attempt NextTerm - will fail permanently
    var nextTermInput = await GenerateNextTermInput();
    
    // To pass validation, need: input.TermNumber = 999 + 1 = 1000
    nextTermInput.TermNumber = 1000;
    var nextTermResult = await ExecuteNextTerm(nextTermInput);
    nextTermResult.Status.ShouldBe(TransactionResultStatus.Failed);
    nextTermResult.Error.ShouldContain("Failed to update term number"); // TryToUpdateTermNumber rejects 1000 != 1 + 1
    
    // Try with correct term number based on State.CurrentTermNumber
    nextTermInput.TermNumber = 2; // 1 + 1
    nextTermResult = await ExecuteNextTerm(nextTermInput);
    nextTermResult.Status.ShouldBe(TransactionResultStatus.Failed);
    nextTermResult.Error.ShouldContain("Incorrect term number for next round"); // ValidationForNextTerm rejects 2 != 999 + 1
    
    // Verify permanent DoS: No input value can satisfy both checks
    // Term progression is permanently blocked
    // Treasury releases, election snapshots, and miner updates all halted
}
```

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-218)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L98-105)
```csharp
    private bool TryToUpdateTermNumber(long termNumber)
    {
        var oldTermNumber = State.CurrentTermNumber.Value;
        if (termNumber != 1 && oldTermNumber + 1 != termNumber) return false;

        State.CurrentTermNumber.Value = termNumber;
        return true;
    }
```
