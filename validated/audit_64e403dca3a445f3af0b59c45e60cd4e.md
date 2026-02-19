# Audit Report

## Title
Consensus Term Change Can Be Indefinitely Delayed Through Miner Availability Manipulation

## Summary
The AEDPoS consensus mechanism's term change logic relies solely on achieving 2/3+1 consensus among miners' `ActualMiningTimes` without any absolute time validation. When 1/3+ miners are offline or controlled by attackers, term changes can be delayed beyond the intended period for up to 3 days, blocking treasury releases and governance operations.

## Finding Description

The vulnerability exists in the term change decision flow. When determining whether to transition to a new term, the system checks `NeedToChangeTerm()` which counts how many miners have `ActualMiningTimes` indicating the term period has elapsed. [1](#0-0) 

The critical issue is that this check requires at least `MinersCountOfConsent` miners (calculated as `Count * 2 / 3 + 1`) to agree. [2](#0-1) 

Miners who have stopped producing blocks remain in `RealTimeMinersInformation` with their stale `ActualMiningTimes` and continue to be counted in the consensus threshold calculation. [3](#0-2) 

The term change decision flows through `MainChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()`, which returns `NextRound` instead of `NextTerm` when the threshold isn't met. [4](#0-3) 

The consensus behaviour determines which hint is embedded in the block through `TerminateRoundCommandStrategy`. [5](#0-4) 

Critically, the `RoundTerminateValidationProvider` validates blocks based only on whether round and term numbers increment correctly, not whether sufficient absolute time has elapsed to justify the behaviour. [6](#0-5) 

Offline miners are only removed after exceeding `TolerableMissedTimeSlotsCount` (4320 slots = 3 days). [7](#0-6) 

During the next round, their `MissedTimeSlots` is incremented. [8](#0-7) 

**Attack Scenario:**
With 17 miners requiring 12 for consensus (2/3+1):
1. After the term period elapses, 6 miners (1/3+) stop producing blocks
2. Only 11 honest miners have recent `ActualMiningTimes` indicating term change
3. 11 < 12, so `NeedToChangeTerm()` returns false
4. Honest miners follow protocol and produce `NextRound` blocks
5. Validation accepts these blocks (only checks incremental correctness)
6. Term change is blocked despite the period having elapsed
7. Can persist for 3 days until evil miner detection removes offline miners

## Impact Explanation

This vulnerability enables critical governance and economic operations to be delayed:

**Treasury Release Delays:** Term changes trigger treasury profit releases through `State.TreasuryContract.Release.Send()`. [9](#0-8) 

**Election Snapshot Delays:** Election snapshots recording miner performance are taken at term changes through `State.ElectionContract.TakeSnapshot.Send()`. [10](#0-9) 

**Miner List Update Delays:** New term elections that update the active miner set cannot occur, allowing potentially malicious miners to extend their control period.

The severity is HIGH because it breaks the fundamental consensus invariant that terms transition at defined intervals, enabling governance manipulation and economic disruption for up to 3 days.

## Likelihood Explanation

**Attacker Capabilities:** An attacker needs to control or coordinate 1/3+ of the miner set (approximately 6 out of 17 miners). Alternatively, natural network partitions affecting 1/3+ miners trigger this vulnerability without malicious intent.

**Execution Complexity:** 
- The attack is triggered through the standard consensus flow accessed via `GetConsensusCommand()` [11](#0-10) 
- No special privileges required - miners simply stop producing blocks
- Honest miners following the protocol inadvertently perpetuate the issue
- Can persist until evil miner detection after 3 days [12](#0-11) 

**Feasibility:** This represents a liveness failure in the BFT consensus design. While BFT systems tolerate 1/3 byzantine participants for safety, this vulnerability shows inadequate liveness guarantees when that threshold is reached. The likelihood is MEDIUM-HIGH given that network partitions or coordinated attacks affecting 1/3+ miners are plausible scenarios.

## Recommendation

Add absolute time validation to prevent term extension beyond the configured period:

1. **Enhance RoundTerminateValidationProvider:** Add a validation check that rejects `NextRound` blocks when the absolute elapsed time exceeds `(currentTermNumber * periodSeconds)` based on current block timestamp minus blockchain start timestamp.

2. **Add Fallback Term Change Logic:** If the 2/3+1 threshold cannot be reached but the absolute term period has elapsed, the validation should require `NextTerm` behaviour or force a term change through an alternative mechanism.

3. **Reduce Evil Miner Detection Threshold:** Consider lowering `TolerableMissedTimeSlotsCount` from 3 days to reduce the maximum delay window.

The core fix should add temporal correctness validation alongside the existing incremental correctness checks in `RoundTerminateValidationProvider.ValidationForNextRound()`.

## Proof of Concept

A valid proof of concept would require setting up a test network with 17 miners, having 6 stop producing blocks after the term period elapses, and demonstrating that the remaining 11 honest miners continue producing `NextRound` blocks while treasury releases and elections remain blocked. This would require integration testing infrastructure beyond simple unit tests, as it involves multi-node consensus behavior validation.

The vulnerability is demonstrated through the code analysis showing:
1. The threshold calculation requiring 12/17 miners [2](#0-1) 
2. The lack of absolute time validation [13](#0-12) 
3. The 3-day delay before offline miner removal [7](#0-6) 

## Notes

This vulnerability represents a protocol-level liveness issue rather than a typical smart contract exploit. The system's reliance on achieving 2/3+1 consensus without fallback mechanisms creates a scenario where governance operations can be blocked when Byzantine fault tolerance assumptions are met (1/3+ offline). The fix requires enhancing the validation layer to enforce temporal constraints alongside consensus-based term changes.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L52-55)
```csharp
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L205-210)
```csharp
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-82)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
```
