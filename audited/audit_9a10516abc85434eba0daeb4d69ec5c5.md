### Title
Missing Minimum Participation Threshold Validation for Consensus Round Termination

### Summary
The AEDPoS consensus mechanism allows rounds to be terminated without validating that the minimum participation threshold (MinersCountOfConsent = 2/3 + 1 of total miners) has been reached. This enables consensus decisions with fewer than the Byzantine Fault Tolerance requirement, undermining the security guarantees of the distributed consensus protocol and potentially allowing network partitions to proceed independently with insufficient validator participation.

### Finding Description

The `TerminateRoundCommandStrategy.GetAEDPoSConsensusCommand()` method generates consensus commands for round termination without any participation threshold validation: [1](#0-0) 

The behavior selection in `MainChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` only checks time-based conditions for term changes, not participation thresholds: [2](#0-1) 

The validation provider for round termination only validates round/term number increments and in-value nullness: [3](#0-2) 

The processing methods `ProcessNextRound` and `ProcessNextTerm` proceed without checking if sufficient miners participated: [4](#0-3) [5](#0-4) 

While the codebase defines `MinersCountOfConsent` as the Byzantine Fault Tolerance threshold (2/3 + 1 miners): [6](#0-5) 

This threshold is only enforced for LIB (Last Irreversible Block) height calculation: [7](#0-6) 

But NOT for validating round termination eligibility. The `GetMinedMiners()` method identifies participating miners: [8](#0-7) 

However, there is no check comparing `GetMinedMiners().Count` against `MinersCountOfConsent` before allowing round termination in any of the validation or processing flows.

### Impact Explanation

**Consensus Integrity Violation**: The system can make consensus state transitions with fewer than 2/3 + 1 miner participation, violating Byzantine Fault Tolerance requirements. In a network with N miners requiring MinersCountOfConsent participation, rounds can be terminated with as few as 1 participating miner (the extra block producer).

**Network Partition Risk**: During network partitions, different segments of the network can independently terminate rounds and produce blocks with insufficient participation, leading to inconsistent chain states that may be difficult to reconcile.

**Finality Degradation**: While LIB won't advance without sufficient participation, new blocks continue to be produced without proper consensus guarantees, creating uncertainty about transaction finality and increasing reorganization risks.

**Who is Affected**: All network participants relying on the consensus mechanism's security guarantees, including validators, dApps, and end users whose transactions may lack proper finality.

This is a HIGH severity issue because it directly undermines the fundamental security model of the consensus protocol.

### Likelihood Explanation

**Attacker Capabilities Required**: 
- Natural occurrence: Network instability, node failures, or connectivity issues can naturally reduce participation below threshold
- Malicious scenarios: Network partitioning attacks, DoS against subset of miners, or miner collusion to withhold participation

**Attack Complexity**: LOW - The vulnerability is automatically exploitable when participation drops below threshold; the extra block producer among participating miners can terminate the round without any special actions.

**Feasibility Conditions**: 
- Network with N miners where fewer than MinersCountOfConsent participate in a round
- One of the participating miners is selected as extra block producer (pseudo-random based on first miner's signature)
- No additional prerequisites or trusted role compromise needed

**Probability**: MEDIUM to HIGH - In production networks, temporary participation drops can occur naturally due to network issues, node maintenance, or infrastructure problems. The likelihood increases with network size and geographic distribution.

### Recommendation

Add minimum participation threshold validation before allowing round termination:

**In `RoundTerminateValidationProvider.ValidationForNextRound()` and `ValidationForNextTerm()`**, add:

```csharp
var minedMinersCount = validationContext.BaseRound.GetMinedMiners().Count;
if (minedMinersCount < validationContext.BaseRound.MinersCountOfConsent)
    return new ValidationResult { 
        Message = $"Insufficient miner participation for round termination. Required: {validationContext.BaseRound.MinersCountOfConsent}, Actual: {minedMinersCount}" 
    };
```

**Alternatively, in `ProcessNextRound()` and `ProcessNextTerm()`**, add assertion at the beginning:

```csharp
var minedMinersCount = currentRound.GetMinedMiners().Count;
Assert(minedMinersCount >= currentRound.MinersCountOfConsent, 
    $"Insufficient miner participation. Required: {currentRound.MinersCountOfConsent}, Actual: {minedMinersCount}");
```

**Test cases to add**:
1. Attempt to terminate round with participation below MinersCountOfConsent - should fail
2. Verify round termination succeeds only when participation meets or exceeds MinersCountOfConsent
3. Test network partition scenarios to ensure independent segments cannot proceed with low participation

### Proof of Concept

**Initial State**:
- Network with 7 miners (MinersCountOfConsent = 2/3 * 7 + 1 = 5 miners required)
- Current round in progress

**Attack Steps**:

1. **Reduce Participation**: Through network issues, DoS, or collusion, cause only 3 out of 7 miners to participate in the current round (mine blocks and set their `SupposedOrderOfNextRound`)

2. **Wait for Extra Block Producer Selection**: The extra block producer for terminating the round is selected pseudo-randomly from participating miners via `CalculateNextExtraBlockProducerOrder()`

3. **Trigger Round Termination**: The selected extra block producer receives `NextRound` or `NextTerm` behavior from consensus command generation

4. **Execute Termination**: The miner produces a block with the termination behavior, which passes validation despite only 3/7 miners participating (below the required 5/7 threshold)

5. **Result**: Round is successfully terminated and next round begins with insufficient consensus participation

**Expected vs Actual**:
- **Expected**: Round termination should FAIL with validation error indicating insufficient participation (3 < 5)
- **Actual**: Round termination SUCCEEDS, violating Byzantine Fault Tolerance guarantees

**Success Condition**: The vulnerability is confirmed if a round can be terminated via `NextRound` or `NextTerm` when `currentRound.GetMinedMiners().Count < currentRound.MinersCountOfConsent`, without any validation failure or assertion.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L23-39)
```csharp
        public override ConsensusCommand GetAEDPoSConsensusCommand()
        {
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint
                    {
                        Behaviour = _isNewTerm ? AElfConsensusBehaviour.NextTerm : AElfConsensusBehaviour.NextRound
                    }
                    .ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                MiningDueTime = arrangedMiningTime.AddMilliseconds(MiningInterval),
                LimitMillisecondsOfMiningBlock =
                    _isNewTerm ? LastBlockOfCurrentTermMiningLimit : DefaultBlockMiningLimit
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-30)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```
