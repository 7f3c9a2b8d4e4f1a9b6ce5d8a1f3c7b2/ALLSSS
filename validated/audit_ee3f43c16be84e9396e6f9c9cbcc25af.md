# Audit Report

## Title
TermNumber State Corruption via Unvalidated NextRound Allows Consensus Disruption

## Summary
The AEDPoS consensus contract's `ValidationForNextRound` method fails to validate the TermNumber field in NextRoundInput, allowing malicious miners to inject arbitrary TermNumber values. This creates an irreconcilable state inconsistency between `State.CurrentTermNumber` and the TermNumber stored in `State.Rounds`, permanently blocking all subsequent NextTerm transitions and causing indefinite consensus disruption.

## Finding Description

The AEDPoS consensus contract contains a critical validation asymmetry in round/term transition logic. The `ValidationForNextRound` method only validates round number increments and InValue nullity, completely omitting TermNumber validation. [1](#0-0) 

In contrast, `ValidationForNextTerm` correctly validates TermNumber by first calling `ValidationForNextRound` and then checking the term number increment. [2](#0-1) 

When a NextRound transaction is processed, the malicious Round object (containing attacker-controlled TermNumber) is persisted directly to state storage through `ProcessNextRound`: [3](#0-2) 

The `AddRoundInformation` method saves the entire Round object to `State.Rounds`, while `ProcessNextRound` only updates `State.CurrentRoundNumber`—leaving `State.CurrentTermNumber` unchanged: [4](#0-3) 

The `ToRound()` conversion method copies all fields including the malicious TermNumber: [5](#0-4) 

This creates a critical state desynchronization where `State.CurrentTermNumber` retains the legitimate value while `State.Rounds[roundNumber].TermNumber` contains the malicious value. The state structure confirms this dual-source architecture: [6](#0-5) 

The validation context construction reveals how these separate sources are used: [7](#0-6) 

After state corruption, NextTerm transitions become impossible due to contradictory validation requirements. NextTerm validation checks `BaseRound.TermNumber + 1 == extraData.Round.TermNumber` using the corrupted value from `State.Rounds`, while NextTerm execution validates against `State.CurrentTermNumber`: [8](#0-7) 

When `BaseRound.TermNumber` ≠ `State.CurrentTermNumber`, no input value can simultaneously satisfy both validation (requiring `corrupted_value + 1`) and execution (requiring `legitimate_value + 1`). The attacker only needs to be a current or previous miner: [9](#0-8) 

## Impact Explanation

This vulnerability enables **permanent denial-of-service of term transitions**, which are critical to consensus and economic operations:

1. **Consensus Integrity Violation**: Once state desynchronization occurs, term progression is permanently blocked as no transaction can satisfy both validation and execution requirements.

2. **Election Mechanism Failure**: Term transitions trigger miner list updates and election snapshots. Without term progression, the election cycle halts indefinitely.

3. **Economic Model Breakdown**: Mining rewards depend on term progression for both donation and treasury release operations, as seen in `ProcessNextTerm`: [10](#0-9) 

4. **Persistence**: The corruption persists indefinitely because the only way to update `State.CurrentTermNumber` is through `TryToUpdateTermNumber`, which is exclusively called during NextTerm execution—the very operation that is now blocked.

5. **Manual Intervention Required**: Recovery requires out-of-band contract upgrade or state migration, as no in-protocol mechanism can resolve the desynchronization.

This constitutes a **Critical severity** vulnerability affecting core consensus and economic functionality.

## Likelihood Explanation

The attack has **High likelihood** due to:

1. **Low Complexity**: Single transaction with modified TermNumber field in NextRoundInput
2. **No Special Conditions**: Works at any point during normal consensus operation
3. **Attacker Requirements**: Must be a current or previous miner (realistic privilege in consensus systems)
4. **Success Rate**: 100% if attacker can mine a block during their time slot
5. **Undetectable**: No validation flags the malicious TermNumber during NextRound processing
6. **Delayed Discovery**: The corruption only becomes apparent when NextTerm is attempted, by which point state is already corrupted

Given that a single compromised or malicious miner can execute this attack with one transaction, the likelihood is **High**.

## Recommendation

Add TermNumber validation to `ValidationForNextRound` method to ensure it matches the current term:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number increment
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD: Validate TermNumber matches current term
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "TermNumber must remain constant during NextRound transitions." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

## Proof of Concept

The vulnerability can be demonstrated with the following attack flow:

**Initial State:**
- State.CurrentTermNumber = 1
- State.CurrentRoundNumber = 5
- State.Rounds[5].TermNumber = 1

**Attack Transaction:**
1. Malicious miner (in current miner list) calls `NextRound(NextRoundInput)` where:
   - NextRoundInput.RoundNumber = 6 (valid increment)
   - NextRoundInput.TermNumber = 999 (malicious value)
   - NextRoundInput.RealTimeMinersInformation with all InValues = null

2. `ValidationForNextRound` validates successfully (only checks RoundNumber and InValues)

3. `ProcessNextRound` executes:
   - Converts input to Round via `ToRound()` (copies TermNumber = 999)
   - Calls `AddRoundInformation(nextRound)` → persists State.Rounds[6] = Round{TermNumber: 999}
   - Calls `TryToUpdateRoundNumber(6)` → updates State.CurrentRoundNumber = 6
   - State.CurrentTermNumber remains = 1

**Post-Attack State:**
- State.CurrentTermNumber = 1 (unchanged)
- State.CurrentRoundNumber = 6
- State.Rounds[6].TermNumber = 999 (corrupted)

**Failed NextTerm:**
When any miner attempts NextTerm with NextTermInput{TermNumber: 2, RoundNumber: 7}:

- Validation constructs context with BaseRound = State.Rounds[6] (TermNumber = 999)
- `ValidationForNextTerm` checks: BaseRound.TermNumber + 1 == input.TermNumber → requires 999 + 1 = 1000 ❌ (input is 2)

When attempting with NextTermInput{TermNumber: 1000, RoundNumber: 7}:

- Validation passes (999 + 1 = 1000) ✓
- Execution checks: `TryToUpdateTermNumber(1000)` → requires State.CurrentTermNumber + 1 == 1000 → requires 1 + 1 = 2 ❌ (input is 1000)

**Result:** Permanent consensus deadlock requiring manual intervention.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
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

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L20-26)
```csharp
    public Int64State CurrentRoundNumber { get; set; }

    public Int64State CurrentTermNumber { get; set; }

    public ReadonlyState<Timestamp> BlockchainStartTimestamp { get; set; }

    public MappedState<long, Round> Rounds { get; set; }
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
