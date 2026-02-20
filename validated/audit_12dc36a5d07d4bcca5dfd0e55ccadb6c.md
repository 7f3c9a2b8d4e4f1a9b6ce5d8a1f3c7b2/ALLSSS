# Audit Report

## Title
TermNumber State Corruption via Unvalidated NextRound Allows Consensus Disruption

## Summary
The `ValidationForNextRound` method in the AEDPoS consensus contract fails to validate the TermNumber field, allowing malicious miners to inject arbitrary TermNumber values during NextRound transitions. This creates an irreconcilable state inconsistency between `State.CurrentTermNumber` and the TermNumber stored in `State.Rounds`, permanently blocking all subsequent NextTerm transitions and causing indefinite consensus disruption.

## Finding Description

The AEDPoS consensus contract contains a critical validation asymmetry in round/term transition logic. While `ValidationForNextTerm` correctly validates TermNumber increments, `ValidationForNextRound` completely omits this validation, only checking round number increment and InValue nullity. [1](#0-0) 

When a NextRound block is processed, the malicious Round object (containing attacker-controlled TermNumber) is persisted directly to state storage. The `ProcessNextRound` method converts the input to a Round object, stores it via `AddRoundInformation`, and only updates `State.CurrentRoundNumber`—leaving `State.CurrentTermNumber` unchanged. [2](#0-1) 

The `ToRound()` conversion method copies all fields including the malicious TermNumber from the input. [3](#0-2) 

The contract maintains three separate state variables: `CurrentRoundNumber`, `CurrentTermNumber`, and the `Rounds` mapping which stores complete Round objects with their own TermNumber fields. [4](#0-3) 

This creates a critical state desynchronization where `State.CurrentTermNumber` retains the legitimate value while `State.Rounds[roundNumber].TermNumber` contains the malicious value. The validation context construction fetches `BaseRound` from `State.Rounds` (containing corrupted TermNumber) and `CurrentTermNumber` from the separate state variable. [5](#0-4) 

After state corruption, NextTerm transitions become impossible due to contradictory validation requirements. NextTerm validation requires `BaseRound.TermNumber + 1 == extraData.Round.TermNumber` using the corrupted value from `State.Rounds`. [6](#0-5) 

However, NextTerm execution validates against `State.CurrentTermNumber` (the legitimate value), requiring `termNumber == currentTermNumber + 1` or `termNumber == 1`. [7](#0-6) 

When `BaseRound.TermNumber` ≠ `State.CurrentTermNumber`, no input value can simultaneously satisfy both the validation check (requiring `corrupted_value + 1`) and execution check (requiring `legitimate_value + 1`).

The attacker only needs to be a current or previous miner, which is verified during PreCheck. [8](#0-7) 

## Impact Explanation

This vulnerability enables **permanent denial-of-service of term transitions**, which are critical to consensus and economic operations:

1. **Consensus Integrity Violation**: Once the state desynchronization occurs, term progression is permanently blocked. No transaction can satisfy both validation and execution requirements.

2. **Election Mechanism Failure**: Term transitions trigger miner list updates and election snapshots. Without term progression, the election cycle halts indefinitely, preventing validator set updates.

3. **Economic Model Breakdown**: Mining rewards depend on term progression for both donation and treasury release operations. [9](#0-8) 

4. **Persistence**: The corruption persists indefinitely because the only way to update `State.CurrentTermNumber` is through `TryToUpdateTermNumber`, which is exclusively called during NextTerm execution—the very operation that is now blocked.

5. **Manual Intervention Required**: Recovery requires out-of-band contract upgrade or state migration, as no in-protocol mechanism can resolve the desynchronization.

This constitutes a **High severity** vulnerability affecting core consensus and economic functionality.

## Likelihood Explanation

The attack has **High likelihood** due to:

1. **Low Complexity**: Single transaction with modified TermNumber field in NextRoundInput
2. **No Special Conditions**: Works at any point during normal consensus operation
3. **Attacker Requirements**: Must be a current or previous miner (realistic privilege in a consensus system)
4. **Success Rate**: 100% if attacker can mine a block during their time slot
5. **Undetectable**: No validation flags the malicious TermNumber during NextRound processing
6. **Delayed Discovery**: The corruption only becomes apparent when NextTerm is attempted, by which point state is already corrupted

Given that miners have elevated but expected privileges in the consensus system, and that a single compromised or malicious miner can execute this attack with one transaction, the likelihood is **High**.

## Recommendation

Add TermNumber validation to `ValidationForNextRound` method to ensure consistency with the current term:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD: Validate TermNumber matches current term
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "TermNumber must remain unchanged during NextRound." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

## Proof of Concept

**Attack Scenario:**

**Initial State:**
- `State.CurrentTermNumber = 5`
- `State.CurrentRoundNumber = 100`
- `State.Rounds[100].TermNumber = 5`

**Step 1:** Attacker (who is a current miner) calls `NextRound` with:
```
NextRoundInput {
    RoundNumber: 101,
    TermNumber: 999,  // Malicious value
    RealTimeMinersInformation: {...},
    RandomNumber: {...}
}
```

**Step 2:** Validation passes because `ValidationForNextRound` does not check TermNumber

**Step 3:** Execution creates state corruption:
- `State.CurrentTermNumber = 5` (unchanged)
- `State.CurrentRoundNumber = 101` (updated)
- `State.Rounds[101].TermNumber = 999` (corrupted)

**Step 4:** When NextTerm is attempted:
- **Validation requires:** `BaseRound.TermNumber + 1 = 999 + 1 = 1000`
- **Execution requires:** `input.TermNumber = State.CurrentTermNumber + 1 = 5 + 1 = 6`
- **Result:** No input can satisfy both → NextTerm permanently blocked

**Test Function:**
```csharp
[Fact]
public async Task NextRound_TermNumberCorruption_BlocksNextTerm()
{
    // Setup: Initialize consensus with term 1, round 1
    await InitializeConsensus();
    
    // Act: Malicious miner calls NextRound with corrupted TermNumber
    var maliciousInput = new NextRoundInput {
        RoundNumber = 2,
        TermNumber = 999, // Should be 1, but attacker sets arbitrary value
        // ... other fields properly set
    };
    
    var result = await ConsensusContract.NextRound(maliciousInput);
    result.Should().BeSuccess(); // Passes validation
    
    // Verify state corruption
    var currentTermNumber = await ConsensusContract.GetCurrentTermNumber();
    currentTermNumber.Value.Should().Be(1); // Still 1
    
    var round2 = await ConsensusContract.GetRoundInformation(new Int64Value { Value = 2 });
    round2.TermNumber.Should().Be(999); // Corrupted!
    
    // Assert: NextTerm now fails permanently
    var nextTermInput = new NextTermInput {
        RoundNumber = 3,
        TermNumber = 2, // Correct value based on CurrentTermNumber
        // ... other fields
    };
    
    var termResult = await ConsensusContract.NextTerm(nextTermInput);
    termResult.Should().Fail(); // Validation fails: needs TermNumber = 1000
}
```

## Notes

This vulnerability exists because NextRound was designed to transition between rounds within the same term, so the original implementation assumed TermNumber would remain constant. However, the lack of explicit validation allows malicious input to corrupt this invariant, creating a permanent deadlock in the consensus state machine. The fix is straightforward: add explicit TermNumber validation to `ValidationForNextRound` to match the behavior of `ValidationForNextTerm`.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-221)
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
