# Audit Report

## Title
Term Transition Bypass via Behavior Selection Manipulation

## Summary
The AEDPoS consensus contract fails to validate that miners use the correct consensus behavior (NextRound vs NextTerm) when terminating rounds. A malicious miner can submit NextRound transactions when NextTerm is required, permanently preventing term transitions and disabling critical economic operations including treasury profit releases, election snapshots, and miner list updates.

## Finding Description

The consensus validation logic validates the internal consistency of round termination data but does not enforce that the appropriate behavior type is used for the current consensus state.

The validation logic adds `RoundTerminateValidationProvider` for both NextRound and NextTerm behaviors: [1](#0-0) 

However, `RoundTerminateValidationProvider.ValidationForNextRound()` only validates that the round number increments correctly and that InValues are null - it does NOT check whether NextTerm should have been used instead: [2](#0-1) 

The decision of whether to use NextRound vs NextTerm is determined by client-side logic in `MainChainConsensusBehaviourProvider`, which checks `NeedToChangeTerm()`: [3](#0-2) 

The `NeedToChangeTerm()` method determines when term changes are required based on whether 2/3 of miners have reached the period threshold: [4](#0-3) 

When a malicious miner submits NextRound instead of NextTerm, the system processes it via `ProcessNextRound()` which only updates the round number: [5](#0-4) 

This bypasses all term transition operations that occur in `ProcessNextTerm()`, including:
- Treasury profit releases via `Treasury.Release()`
- Election snapshots via `Election.TakeSnapshot()` 
- Miner statistics reset (MissedTimeSlots, ProducedBlocks)
- Miner list updates via `SetMinerList()`
- Term number increment via `TryToUpdateTermNumber()` [6](#0-5) 

The `NextRoundInput.ToRound()` conversion preserves whatever term number the attacker provides in the input, allowing the term number to remain unchanged: [7](#0-6) 

## Impact Explanation

This vulnerability has **CRITICAL** severity due to permanent disruption of core protocol economic mechanisms:

**Economic Impact:**
- Treasury profit distributions are permanently blocked, preventing protocol fee distribution to token holders
- Election snapshots never occur, breaking the delegation reward calculation and distribution system
- Mining rewards accumulate in the Treasury but are never released, effectively locking funds
- The periodic economic operations designed around term transitions are completely disabled

**Consensus Governance Impact:**
- Term number freezes while round numbers continue incrementing indefinitely
- Miner list updates never occur, preventing validator set rotation based on election results
- Miner statistics (missed time slots, produced blocks) accumulate indefinitely without reset, potentially breaking evil miner detection logic
- The governance cycle tied to term transitions is permanently disrupted

**Affected Parties:**
- All token holders expecting treasury profit distributions lose access to their share of protocol revenues
- All delegators expecting election-based rewards as snapshots are never taken
- The protocol's long-term economic sustainability as the incentive structure breaks down
- Network security as miner rotation based on elections cannot occur

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Prerequisites:**
- Attacker must be a legitimate miner (validator) in the current consensus round
- Attacker must be designated as the extra block producer for a round where term transition is due
- This rotates among all miners each round, so any malicious miner will eventually have the opportunity

**Attack Complexity:**
The attack is trivially simple - the attacker only needs to:
1. Monitor when `NeedToChangeTerm()` would return true (based on period timing)
2. When designated as extra block producer during such a round, submit `NextRound` transaction instead of `NextTerm`
3. Set `TermNumber` field to current term (instead of current + 1) in the input
4. Set `RoundNumber` field to current round + 1 (normal increment)

No complex timing, state manipulation, or multi-step coordination is required.

**Feasibility:**
- The conditions occur regularly (every period, typically days or weeks)
- Any of the ~17 miners can execute this attack during their rotation
- The attack can be repeated every time the malicious miner becomes extra block producer
- No cryptographic vulnerabilities or key compromise needed

**Detection & Recovery:**
- Attack is observable (term number stops incrementing) but detection may take time
- By the time detected, multiple term transitions may already be skipped
- No automatic recovery mechanism exists in the contract
- Would require governance intervention or contract upgrade to fix

**Economic Incentives:**
A malicious or compromised miner could exploit this to:
- Prevent treasury distributions that might fund competing validator operations
- Maintain current miner set if they benefit from preventing election-based rotation
- Cause protocol dysfunction as competitive attack against the network
- Extract concessions/ransom from other stakeholders to restore functionality

## Recommendation

Add validation in `RoundTerminateValidationProvider` or `ValidateBeforeExecution()` to enforce that the correct behavior is used based on consensus state:

```csharp
// In RoundTerminateValidationProvider.cs
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // NEW: Check that NextTerm is not required
    if (validationContext.BaseRound.NeedToChangeTerm(
        blockchainStartTimestamp, 
        validationContext.CurrentTermNumber, 
        periodSeconds))
    {
        return new ValidationResult { Message = "NextTerm behavior required - term change threshold reached." };
    }
    
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

Alternatively, add the check in `ProcessConsensusInformation` before routing to `ProcessNextRound`:

```csharp
case NextRoundInput nextRoundInput:
    // Verify NextTerm is not required
    if (TryToGetCurrentRoundInformation(out var currentRound) &&
        currentRound.NeedToChangeTerm(...))
    {
        Assert(false, "NextTerm required but NextRound provided");
    }
    randomNumber = nextRoundInput.RandomNumber;
    ProcessNextRound(nextRoundInput);
    break;
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize a chain with miners and configure a short period (e.g., 7 seconds)
2. Advance time past the period threshold so `NeedToChangeTerm()` returns true
3. Have a malicious miner (as extra block producer) submit `NextRound` instead of `NextTerm`
4. Verify the transaction succeeds (vulnerability confirmed)
5. Verify term number remains unchanged while round number increments
6. Verify treasury release and election snapshot are NOT executed
7. Show that subsequent rounds continue without term transitions

The test would demonstrate that the validation accepts the inappropriate behavior and that critical economic operations are permanently skipped.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-91)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-34)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-35)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-223)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
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
