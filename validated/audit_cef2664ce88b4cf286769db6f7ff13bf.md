# Audit Report

## Title
TermNumber State Corruption via Unvalidated NextRound Allows Consensus Disruption

## Summary
The `ValidationForNextRound` method in the AEDPoS consensus contract fails to validate the TermNumber field, allowing malicious miners to inject arbitrary TermNumber values during NextRound transitions. This creates an irreconcilable state inconsistency between `State.CurrentTermNumber` and the TermNumber stored in `State.Rounds`, permanently blocking all subsequent NextTerm transitions and causing indefinite consensus disruption.

## Finding Description

The AEDPoS consensus contract contains a critical validation asymmetry in round/term transition logic. While `ValidationForNextTerm` correctly validates TermNumber increments, `ValidationForNextRound` completely omits this validation. [1](#0-0) 

The NextRound validation only checks round number increment and InValue nullity, with no validation that the input TermNumber matches the current term.

When a NextRound block is processed, the malicious Round object (containing attacker-controlled TermNumber) is persisted directly to state storage: [2](#0-1) 

The `AddRoundInformation` call saves the entire Round object to `State.Rounds`, while only `State.CurrentRoundNumber` is updated—`State.CurrentTermNumber` remains unchanged. The `ToRound()` conversion method copies all fields including the malicious TermNumber: [3](#0-2) 

This creates a critical state desynchronization where:
- `State.CurrentTermNumber` retains the legitimate value
- `State.Rounds[roundNumber].TermNumber` contains the malicious value

The validation context construction reveals this dual-source architecture: [4](#0-3) 

`BaseRound` is fetched from `State.Rounds` (containing corrupted TermNumber), while `CurrentTermNumber` comes from the separate `State.CurrentTermNumber` storage.

After state corruption, NextTerm transitions become impossible due to contradictory validation requirements. NextTerm validation requires: [5](#0-4) 

This checks `BaseRound.TermNumber + 1 == extraData.Round.TermNumber` using the corrupted value from `State.Rounds`.

However, NextTerm execution requires: [6](#0-5) 

This validates against `State.CurrentTermNumber` (the legitimate value), requiring `termNumber == currentTermNumber + 1` or `termNumber == 1`.

When `BaseRound.TermNumber` ≠ `State.CurrentTermNumber`, no input value can simultaneously satisfy both the validation check (requiring `corrupted_value + 1`) and execution check (requiring `legitimate_value + 1`).

The attacker only needs to be a current or previous miner, which is verified during PreCheck: [7](#0-6) 

## Impact Explanation

This vulnerability enables **permanent denial-of-service of term transitions**, which are critical to consensus and economic operations:

1. **Consensus Integrity Violation**: Once the state desynchronization occurs, term progression is permanently blocked. No transaction can satisfy both validation and execution requirements.

2. **Election Mechanism Failure**: Term transitions trigger miner list updates and election snapshots. Without term progression, the election cycle halts indefinitely.

3. **Economic Model Breakdown**: Mining rewards depend on term progression for both donation and treasury release operations: [8](#0-7) 

4. **Persistence**: The corruption persists indefinitely because the only way to update `State.CurrentTermNumber` is through `TryToUpdateTermNumber`, which is exclusively called during NextTerm execution—the very operation that is now blocked.

5. **Manual Intervention Required**: Recovery requires out-of-band contract upgrade or state migration, as no in-protocol mechanism can resolve the desynchronization.

This constitutes a **High severity** vulnerability affecting core consensus and economic functionality.

## Likelihood Explanation

The attack has **High likelihood** due to:

1. **Low Complexity**: Single transaction with modified TermNumber field in NextRoundInput
2. **No Special Conditions**: Works at any point during normal consensus operation
3. **Attacker Requirements**: Must be a current or previous miner (realistic privilege)
4. **Success Rate**: 100% if attacker can mine a block during their time slot
5. **Undetectable**: No validation flags the malicious TermNumber during NextRound processing
6. **Delayed Discovery**: The corruption only becomes apparent when NextTerm is attempted, by which point state is already corrupted

Given that miners have elevated but expected privileges in the consensus system, and that a single compromised or malicious miner can execute this attack with one transaction, the likelihood is **High**.

## Recommendation

Add TermNumber validation to `ValidationForNextRound` to match the validation performed in `ValidationForNextTerm`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number increment
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // NEW: Validate TermNumber remains unchanged during NextRound
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Term number must not change during NextRound." };

    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

This ensures that NextRound transitions preserve the current TermNumber, while NextTerm transitions properly increment it.

## Proof of Concept

```csharp
[Fact]
public async Task TermNumber_Corruption_Via_NextRound_Blocks_NextTerm()
{
    // Setup: Initialize consensus with term 1, round 1
    await InitializeConsensusContract();
    var initialTermNumber = await ConsensusContract.GetCurrentTermNumber.CallAsync(new Empty());
    var initialRoundNumber = await ConsensusContract.GetCurrentRoundNumber.CallAsync(new Empty());
    Assert.Equal(1, initialTermNumber.Value);
    Assert.Equal(1, initialRoundNumber.Value);
    
    // Attack: Malicious miner crafts NextRound with arbitrary TermNumber
    var maliciousTermNumber = -999; // Arbitrary negative value
    var nextRoundInput = new NextRoundInput
    {
        RoundNumber = initialRoundNumber.Value + 1,
        TermNumber = maliciousTermNumber, // MALICIOUS: Should be 1 but set to -999
        RealTimeMinersInformation = { /* valid miner info */ },
        RandomNumber = GenerateRandomNumber()
    };
    
    // Execute malicious NextRound (passes validation due to missing TermNumber check)
    var result = await MinerKeyPair.ExecuteTransactionAsync(
        ConsensusContract.NextRound, nextRoundInput);
    Assert.True(result.Status == TransactionResultStatus.Mined);
    
    // Verify state corruption
    var currentTermNumber = await ConsensusContract.GetCurrentTermNumber.CallAsync(new Empty());
    var currentRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(1, currentTermNumber.Value); // State.CurrentTermNumber unchanged
    Assert.Equal(maliciousTermNumber, currentRound.TermNumber); // State.Rounds[2].TermNumber corrupted
    
    // Impact: Subsequent NextTerm is now permanently blocked
    var nextTermInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentTermNumber.Value + 1, // Trying legitimate term 2
        RealTimeMinersInformation = { /* valid new term miners */ },
        RandomNumber = GenerateRandomNumber()
    };
    
    // Validation requires: TermNumber = BaseRound.TermNumber + 1 = -999 + 1 = -998
    // But we're sending TermNumber = 2 (legitimate value)
    // Validation fails with "Incorrect term number for next round."
    var nextTermResult = await MinerKeyPair.ExecuteTransactionAsync(
        ConsensusContract.NextTerm, nextTermInput);
    Assert.True(nextTermResult.Status == TransactionResultStatus.Failed);
    Assert.Contains("Incorrect term number", nextTermResult.Error);
    
    // Alternative: Try satisfying validation by sending -998
    nextTermInput.TermNumber = -998;
    nextTermResult = await MinerKeyPair.ExecuteTransactionAsync(
        ConsensusContract.NextTerm, nextTermInput);
    // Now validation passes, but execution fails because:
    // TryToUpdateTermNumber requires: termNumber == State.CurrentTermNumber + 1
    // -998 != 1 + 1, so execution assertion fails
    Assert.True(nextTermResult.Status == TransactionResultStatus.Failed);
    Assert.Contains("Failed to update term number", nextTermResult.Error);
    
    // Conclusion: Term transitions are permanently blocked
}
```

## Notes

The TermNumber field is defined as `int64` in the protobuf specification, allowing both positive and negative values. This vulnerability exploits the validation gap where `ValidationForNextRound` assumes TermNumber preservation but does not enforce it, while `ValidationForNextTerm` explicitly validates TermNumber increments. The resulting state desynchronization between `State.CurrentTermNumber` (single value) and `State.Rounds[roundNumber].TermNumber` (per-round storage) creates an irreconcilable deadlock that can only be resolved through manual contract intervention.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-60)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };

        // Skip the certain initial miner during first several rounds. (When other nodes haven't produce blocks yet.)
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
        }

        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

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
