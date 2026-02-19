### Title
Term Transition Bypass via Behavior Selection Manipulation

### Summary
The AEDPoS consensus validation does not enforce that the correct consensus behavior (NextRound vs NextTerm) is used when terminating rounds. A malicious miner can use NextRound behavior when NextTerm is required, permanently skipping term transitions and preventing critical economic operations including treasury profit releases, election snapshots, and miner list updates.

### Finding Description

The root cause is that `ValidateBeforeExecution()` only adds `RoundTerminateValidationProvider` to validate the correctness of round/term data when NextRound or NextTerm behaviors are declared, but does not validate that the declared behavior itself is appropriate for the current consensus state. [1](#0-0) 

The behavior selection logic in `MainChainConsensusBehaviourProvider` determines when to use NextTerm based on `NeedToChangeTerm()`: [2](#0-1) 

However, this is purely CLIENT-SIDE logic. When a miner submits NextRound instead of NextTerm, `RoundTerminateValidationProvider` validates that the round number increments correctly but does NOT check whether NextTerm should have been used: [3](#0-2) 

The term change requirement is based on whether two-thirds of miners' latest ActualMiningTimes indicate the period threshold has passed: [4](#0-3) 

When NextRound is processed instead of NextTerm, it advances the round number but NOT the term number: [5](#0-4) 

This skips all term transition logic including treasury releases, election snapshots, miner list updates, and counter resets: [6](#0-5) 

### Impact Explanation

**Direct Economic Impact:**
- Treasury profit releases are permanently blocked, preventing distribution of protocol fees to token holders
- Election snapshots are never taken, breaking the delegation and reward distribution mechanisms
- Miner statistics (missed time slots, produced blocks) are never reset, accumulating indefinitely
- The economic model's periodic treasury distribution (designed for term transitions) is completely bypassed

**Consensus Integrity Impact:**
- Term number becomes permanently frozen while round numbers continue incrementing
- Miner list updates for new terms never occur, preventing rotation of validator sets based on election results
- The protocol cannot transition to new terms as designed, breaking the governance cycle

**Affected Parties:**
- All token holders expecting treasury profit distributions
- Delegators expecting rewards from election snapshots
- The protocol's long-term economic sustainability

**Severity:** CRITICAL - This permanently breaks core economic and governance functions designed around term transitions.

### Likelihood Explanation

**Attacker Capabilities:**
The attacker must be a miner (validator) with block production rights, specifically the extra block producer responsible for terminating rounds. This is a privileged position but represents 1 out of ~17 miners in typical configurations.

**Attack Complexity:**
LOW - The attack requires only modifying the client to submit NextRound transactions instead of NextTerm when terminating a round. No complex timing, no multi-step setup, no coordination needed.

**Feasibility Conditions:**
- Attacker is currently the extra block producer (rotates among miners each round)
- `NeedToChangeTerm()` returns true (happens periodically based on configured period)
- The attacker can repeat this attack every time they become the extra block producer during term transition rounds

**Detection:**
The attack would be observable (term number stops incrementing while rounds continue) but by the time it's detected, term transitions have already been skipped. There's no automatic recovery mechanism.

**Economic Rationality:**
A malicious miner could exploit this to:
1. Prevent treasury distributions that might fund competitors
2. Maintain the current miner set indefinitely if they benefit from preventing elections
3. Cause protocol dysfunction as a form of griefing or competitive attack

**Probability:** HIGH - The attack is straightforward for any malicious miner during their turn as extra block producer, with clear incentives for certain attack scenarios.

### Recommendation

**Add Behavior Enforcement Validation:**
Create a new validation provider `BehaviorCorrectnessValidationProvider` that validates the chosen behavior matches what should be used based on consensus state. Add it to the validation pipeline for all behaviors:

```csharp
public class BehaviorCorrectnessValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var baseRound = validationContext.BaseRound;
        
        // If NeedToChangeTerm is true, NextTerm MUST be used
        if (extraData.Behaviour == AElfConsensusBehaviour.NextRound)
        {
            // Get blockchain start timestamp and period from state
            var blockchainStartTimestamp = GetBlockchainStartTimestamp();
            var periodSeconds = State.PeriodSeconds.Value;
            
            if (baseRound.NeedToChangeTerm(blockchainStartTimestamp, 
                validationContext.CurrentTermNumber, periodSeconds))
            {
                return new ValidationResult 
                { 
                    Message = "NextTerm behavior required when term change is needed." 
                };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Then add this provider to the validation pipeline in `ValidateBeforeExecution()` for NextRound behavior.

**Alternative/Additional Fix:**
Add a check in `ProcessNextRound()` that asserts `NeedToChangeTerm()` returns false before proceeding.

**Test Cases:**
1. Test that NextRound fails validation when `NeedToChangeTerm()` returns true
2. Test that NextTerm is required and succeeds when term change conditions are met
3. Test that attempting NextRound during term transition time reverts with appropriate error

### Proof of Concept

**Required Initial State:**
- Main chain with AEDPoS consensus running
- Current term number = 1, round number = N
- Time has advanced such that `NeedToChangeTerm()` returns true (period threshold exceeded)
- Malicious miner is the extra block producer for the current round

**Attack Steps:**
1. All regular miners complete their blocks for round N (all have `OutValue` set)
2. Malicious extra block producer's turn to terminate the round
3. Instead of calling `NextTerm`, attacker calls `NextRound` with properly formed NextRoundInput
4. `ValidateBeforeExecution()` runs:
   - Adds `MiningPermissionValidationProvider` - PASSES (attacker is in miner list)
   - Adds `TimeSlotValidationProvider` - PASSES (within time slot)
   - Adds `ContinuousBlocksValidationProvider` - PASSES (not excessive blocks)
   - Adds `NextRoundMiningOrderValidationProvider` - PASSES (mining order correct)
   - Adds `RoundTerminateValidationProvider` - PASSES (round number increments by 1, InValues null)
   - NO validator checks that NextTerm should have been used
5. `ProcessNextRound()` executes successfully, incrementing round number but NOT term number
6. Treasury profit release never happens (only triggered in `ProcessNextTerm`)
7. Election snapshot never taken (only in `ProcessNextTerm`)

**Expected Result:** Transaction should FAIL with "NextTerm behavior required when term change is needed"

**Actual Result:** Transaction SUCCEEDS, round advances to N+1, term remains at 1, term transition skipped

**Success Condition:** Attacker successfully advances round number while keeping term number frozen, bypassing all term transition logic indefinitely.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
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
