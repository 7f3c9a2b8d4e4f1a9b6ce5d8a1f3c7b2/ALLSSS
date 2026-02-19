# Audit Report

## Title
TermNumber Increment Bypass via NextRound Behavior Validation Gap

## Summary
The AEDPoS consensus contract fails to validate TermNumber consistency when processing NextRound behavior transitions. A malicious miner can craft a consensus block with NextRound behavior but an incremented TermNumber, bypassing critical term transition logic and causing persistent state desynchronization between `State.CurrentTermNumber` and stored round data.

## Finding Description

The vulnerability exists in the consensus validation and processing logic. When a block header specifies `AElfConsensusBehaviour.NextRound`, the validation immediately returns `ValidationForNextRound()` result without checking TermNumber consistency. [1](#0-0) 

The `ValidationForNextRound()` function only validates that the round number is incremented by exactly 1 and that InValues are null. It critically does NOT validate that TermNumber remains unchanged. [2](#0-1) 

In contrast, `ValidationForNextTerm()` explicitly checks TermNumber increment, demonstrating that TermNumber consistency is a critical invariant. [3](#0-2) 

When legitimate round generation occurs, `GenerateNextRoundInformation()` explicitly preserves the current TermNumber, confirming NextRound transitions should NOT change the term. [4](#0-3) 

However, `NextRoundInput.ToRound()` blindly copies the TermNumber from input without validation, allowing malicious values to propagate. [5](#0-4) 

During execution, `ProcessNextRound()` only updates `State.CurrentRoundNumber` but never calls `TryToUpdateTermNumber()`, creating desynchronization. [6](#0-5) 

The malicious round (with incremented TermNumber) is stored directly via `AddRoundInformation()`. [7](#0-6) 

## Impact Explanation

**State Inconsistency**: After the attack, `State.CurrentTermNumber` remains at the old value while `State.Rounds[currentRoundNumber].TermNumber` is incremented, creating persistent desynchronization that corrupts term-based lookups and validations throughout the consensus system.

**Bypassed Critical Operations**: The attacker skips all term transition operations in `ProcessNextTerm()`, including:

1. **Mining Reward Misallocation**: `DonateMiningReward()` and `TreasuryContract.Release()` are not executed, preventing mining rewards distribution and treasury fund releases. [8](#0-7) 

2. **Election Corruption**: `ElectionContract.TakeSnapshot()` is skipped, breaking election snapshots that record mined blocks and voting power. [9](#0-8) 

3. **Miner List Desynchronization**: `SetMinerList()` and `State.FirstRoundNumberOfEachTerm` updates are skipped, corrupting term-to-miner-list mappings. [10](#0-9) 

4. **Penalty Evasion**: `CountMissedTimeSlots()` is not called, allowing miners to escape penalties. [11](#0-10) 

The cumulative impact corrupts the economic system, governance mechanisms, and consensus integrity.

## Likelihood Explanation

**Attacker Capabilities**: The attacker must be a miner in the current miner list (achievable through election or genesis configuration) and selected as the extra block producer for the round (occurs deterministically in rotation).

**Attack Execution**: 
1. Miner receives legitimate consensus command indicating NextRound behavior
2. Instead of using legitimate data generation, miner crafts custom consensus data with incremented TermNumber
3. Miner signs and submits the block with modified header
4. Validation passes because `ValidationForNextRound()` doesn't check TermNumber

**Feasibility**: The attack requires running modified node software but no special economic cost. The validation gap guarantees success. Detection is difficult as `State.CurrentTermNumber` remains unchanged while stored round data contains the incremented value.

**Operational Constraints**: The attack can be executed whenever the miner is the extra block producer, happening periodically in the round-robin rotation.

## Recommendation

Add TermNumber validation to `ValidationForNextRound()`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number increment
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD THIS: Validate TermNumber remains unchanged
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "TermNumber must not change for NextRound behavior." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

## Proof of Concept

The proof of concept would require:
1. Setting up a test consensus environment with multiple miners
2. Modifying the consensus data generation to increment TermNumber for NextRound behavior
3. Submitting the malicious block and verifying it passes validation
4. Demonstrating the state desynchronization where `State.CurrentTermNumber` differs from `State.Rounds[roundNumber].TermNumber`
5. Confirming that term transition operations (rewards, snapshots, miner list updates) are skipped

The vulnerability is confirmed through code analysis showing the clear validation gap and the resulting state inconsistency that would occur upon exploitation.

## Notes

This is a critical consensus-level vulnerability that breaks fundamental AEDPoS invariants. The validation gap is not a design choice but an oversight, as evidenced by the explicit TermNumber validation in `ValidationForNextTerm()` and the intentional preservation of TermNumber in `GenerateNextRoundInformation()`. The attack vector is realistic for any malicious miner willing to run modified node software, and the impact affects core protocol guarantees around rewards, governance, and accountability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L14-14)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.NextRound) return ValidationForNextRound(validationContext);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L22-22)
```csharp
        nextRound.TermNumber = TermNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L167-168)
```csharp
        // Count missed time slot of current round.
        CountMissedTimeSlots();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-193)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```
