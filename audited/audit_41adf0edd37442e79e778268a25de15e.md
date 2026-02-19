### Title
Term Transition Bypass via Hardcoded isNewTerm in TinyBlock Termination Strategy

### Summary
When a miner producing tiny blocks terminates their time slot, the `TinyBlockCommandStrategy` hardcodes `isNewTerm=false` when creating a `TerminateRoundCommandStrategy`, bypassing the proper term transition check. This causes the system to execute `NextRound` instead of `NextTerm` when a term transition is required, resulting in the old miner list continuing, mining rewards not being donated to treasury, and blocks being produced with insufficient mining time limit (1/8th of the required time). [1](#0-0) 

### Finding Description

**Root Cause:**

In `TinyBlockCommandStrategy.GetAEDPoSConsensusCommand()`, when the arranged mining time exceeds the current time slot, the code creates a `TerminateRoundCommandStrategy` with `isNewTerm` hardcoded to `false`: [1](#0-0) 

This bypasses the proper term transition logic that should occur in `MainChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()`, which checks `CurrentRound.NeedToChangeTerm()` to determine whether to return `NextTerm` or `NextRound`: [2](#0-1) 

The `NeedToChangeTerm()` method checks if at least two-thirds of miners have produced blocks whose timestamps indicate a term transition is required: [3](#0-2) 

**Why Protections Fail:**

The `isNewTerm` parameter in `TerminateRoundCommandStrategy` directly determines the consensus behaviour and mining time limit: [4](#0-3) 

When `isNewTerm=false`, the system uses `DefaultBlockMiningLimit` instead of `LastBlockOfCurrentTermMiningLimit`, which is 8 times smaller: [5](#0-4) 

The validation in `RoundTerminateValidationProvider` does NOT check whether a term transition should have occurred - it only validates that round/term numbers increment correctly: [6](#0-5) 

**Execution Path:**

1. Extra block producer from previous round is producing tiny blocks
2. `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` returns `TinyBlock` behavior
3. `TinyBlockCommandStrategy` calculates arranged mining time exceeds time slot
4. Creates `TerminateRoundCommandStrategy` with `isNewTerm=false` hardcoded
5. Consensus command generated with `NextRound` behavior and `DefaultBlockMiningLimit`
6. Node creates trigger information with `NextRound` behavior
7. Block extra data generated via `GetConsensusExtraDataForNextRound()` instead of `GetConsensusExtraDataForNextTerm()`
8. Validation passes (no check for whether term transition is required)
9. `ProcessNextRound()` executed instead of `ProcessNextTerm()` [7](#0-6) 

### Impact Explanation

**Consensus and Governance Disruption:**

When `ProcessNextRound()` is executed instead of `ProcessNextTerm()`, the following critical term transition operations are skipped: [8](#0-7) 

1. **Term number not updated** - The blockchain continues with the old term number, breaking the term progression invariant
2. **Miner list not updated** - Old miners continue producing blocks instead of newly elected miners from `State.ElectionContract.GetVictories()`
3. **Mining rewards not donated** - `DonateMiningReward()` not called, Treasury doesn't receive funds
4. **Treasury release not triggered** - `State.TreasuryContract.Release()` not called for the completed term
5. **Election snapshot not taken** - `State.ElectionContract.TakeSnapshot()` not executed, disrupting reward distribution
6. **Miner statistics not reset** - `MissedTimeSlots` and `ProducedBlocks` not cleared for new term
7. **Insufficient mining time** - Block produced with `DefaultBlockMiningLimit` (1/8th of `LastBlockOfCurrentTermMiningLimit`), potentially causing block production to fail or be rejected by other nodes

This represents a complete breakdown of the term transition mechanism, affecting:
- **Elections**: Newly elected miners don't take over
- **Economics**: Mining rewards accumulate incorrectly
- **Treasury**: Scheduled releases don't occur
- **Governance**: Term-based operations fail

### Likelihood Explanation

**Attacker Capabilities:**

The extra block producer from the previous round can trigger this vulnerability. Per the consensus behavior logic, this miner receives `TinyBlock` behavior when:
- They are the `ExtraBlockProducerOfPreviousRound`
- Current time is before round start time
- They haven't exceeded maximum blocks count [9](#0-8) 

**Attack Complexity:**

The attack is relatively simple:
1. Wait until a term transition is required (determined by `NeedToChangeTerm()`)
2. As the extra block producer, produce tiny blocks in the pre-round period
3. Continue producing tiny blocks until the arranged mining time exceeds the time slot
4. The system automatically triggers the bug, generating `NextRound` instead of `NextTerm`

**Feasibility:**

- **Entry Point**: Public consensus command generation flow via ACS4 `GetConsensusCommand()`
- **Preconditions**: Miner must be extra block producer of previous round, which rotates naturally
- **Detection**: Difficult to distinguish from legitimate tiny block production
- **Economic Cost**: No additional cost beyond normal block production

**Probability:**

This can occur accidentally during normal operations when:
- A term transition becomes required while a miner is producing tiny blocks
- The miner naturally continues producing until time slot ends

It can also be intentionally triggered by a malicious extra block producer who wants to:
- Prevent newly elected miners from taking over
- Delay treasury operations
- Maintain current miner set

### Recommendation

**Fix the Root Cause:**

In `TinyBlockCommandStrategy.GetAEDPoSConsensusCommand()`, instead of hardcoding `isNewTerm=false`, check whether a term transition is required:

```csharp
// Line 40-42 in TinyBlockCommandStrategy.cs
return arrangedMiningTime > currentTimeSlotEndTime
    ? new TerminateRoundCommandStrategy(CurrentRound, Pubkey, CurrentBlockTime, 
        CurrentRound.NeedToChangeTerm(GetBlockchainStartTimestamp(), 
            State.CurrentTermNumber.Value, State.PeriodSeconds.Value))
        .GetAEDPoSConsensusCommand()
    : new ConsensusCommand { ... };
```

However, this requires access to blockchain start timestamp and period seconds, which aren't available in the strategy class. A better approach is to pass the correct behavior from the behavior provider.

**Alternative: Fix in Behavior Provider**

Modify `ConsensusBehaviourProviderBase` to handle the tiny block termination case:

```csharp
// In ConsensusBehaviourProviderBase.GetConsensusBehaviour()
// Before returning GetConsensusBehaviourToTerminateCurrentRound() at line 82
// Check if this is a tiny block about to terminate
```

**Add Validation:**

Add a validator that checks whether `NextTerm` should have been used instead of `NextRound` when a term transition is required: [10](#0-9) 

Add a new validation provider that verifies term transition requirements match the behavior.

### Proof of Concept

**Initial State:**
1. Main chain with multiple elected miners
2. Current term has been running for full period (based on `PeriodSeconds`)
3. Two-thirds of miners have produced blocks with timestamps indicating term transition is required (`NeedToChangeTerm()` returns true)
4. Miner A is the extra block producer of previous round

**Attack Sequence:**

1. **Term Transition Required**: At least `MinersCountOfConsent` miners have produced blocks whose timestamps satisfy `IsTimeToChangeTerm()`: [11](#0-10) 

2. **Miner A Produces Tiny Blocks**: As extra block producer, Miner A receives `TinyBlock` behavior and produces several tiny blocks in pre-round period

3. **Time Slot Exceeded**: Next tiny block's arranged mining time exceeds the time slot end time

4. **Bug Triggered**: `TinyBlockCommandStrategy` creates `TerminateRoundCommandStrategy` with `isNewTerm=false` hardcoded

5. **Wrong Command Generated**: Consensus command has `NextRound` behavior with `DefaultBlockMiningLimit` instead of `NextTerm` with `LastBlockOfCurrentTermMiningLimit`

6. **Validation Passes**: `RoundTerminateValidationProvider` only checks round number increment, doesn't verify term transition requirement

7. **Wrong Method Executed**: `ProcessNextRound()` called instead of `ProcessNextTerm()`

**Expected Result:**
- Term number increments from N to N+1
- New miners from election results take over
- Mining rewards donated to treasury
- Election snapshot taken
- Block produced with `LastBlockOfCurrentTermMiningLimit` (8x normal time)

**Actual Result:**
- Term number stays at N
- Old miners continue
- No treasury donation
- No election snapshot
- Block produced with `DefaultBlockMiningLimit` (1/8th required time)
- Complete term transition bypass

### Notes

This vulnerability represents a critical flaw in the term transition mechanism. The issue is architectural - the `TinyBlockCommandStrategy` was implemented without considering term transitions, hardcoding the assumption that tiny block termination always means `NextRound`. The proper check that exists in `MainChainConsensusBehaviourProvider` is bypassed entirely.

The impact extends beyond just consensus to affect governance, economics, and elections. The fix requires either: (1) making term transition state available to the strategy classes, or (2) restructuring the behavior determination logic to handle this case before reaching the strategy layer.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L40-42)
```csharp
            return arrangedMiningTime > currentTimeSlotEndTime
                ? new TerminateRoundCommandStrategy(CurrentRound, Pubkey, CurrentBlockTime, false)
                    .GetAEDPoSConsensusCommand() // The arranged mining time already beyond the time slot.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L46-60)
```csharp
        /// <summary>
        ///     Give 3/5 of producing time for mining by default.
        /// </summary>
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);

        /// <summary>
        ///     If this tiny block is the last one of current time slot, give half of producing time for mining.
        /// </summary>
        protected int LastTinyBlockMiningLimit => TinyBlockSlotInterval.Div(2);

        /// <summary>
        ///     If this block is of consensus behaviour NEXT_TERM, the producing time is MiningInterval,
        ///     so the limitation of mining is 8 times than DefaultBlockMiningLimit.
        /// </summary>
        protected int LastBlockOfCurrentTermMiningLimit => MiningInterval.Mul(3).Div(5);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-114)
```csharp
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
