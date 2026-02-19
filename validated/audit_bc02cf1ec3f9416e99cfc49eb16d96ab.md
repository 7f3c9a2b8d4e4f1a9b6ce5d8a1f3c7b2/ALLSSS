# Audit Report

## Title
Term Boundary Violation in NextRound Consensus Command Generation Leading to Mining Reward Misallocation

## Summary
The AEDPoS consensus contract allows blocks to be mined with timestamps beyond the current term's end time while maintaining the previous term's number. This occurs when `ArrangeAbnormalMiningTime` calculates mining times without term boundary validation, and less than 2/3 of miners have crossed the term boundary. The vulnerability causes mining reward misallocation as blocks mined in Term N+1's time period are counted toward Term N's rewards.

## Finding Description

The vulnerability stems from a disconnect between mining time calculation and term transition logic.

When `TerminateRoundCommandStrategy.GetAEDPoSConsensusCommand()` is called with `_isNewTerm=false`, it invokes `ArrangeExtraBlockMiningTime` which delegates to `Round.ArrangeAbnormalMiningTime`. [1](#0-0) 

The `ArrangeAbnormalMiningTime` method calculates future mining times based purely on round timing mechanics, projecting forward by calculating missed rounds and adding `(missedRoundsCount + 1) * totalMilliseconds` to the current round start time. Critically, this calculation never validates whether the resulting timestamp exceeds the current term's end time. [2](#0-1) 

The decision between `NextRound` and `NextTerm` behaviors is made by `MainChainConsensusBehaviourProvider`, which only triggers `NextTerm` when 2/3 of miners (MinersCountOfConsent) have already mined blocks past the term boundary. [3](#0-2)  The 2/3 threshold is defined as `RealTimeMinersInformation.Count * 2 / 3 + 1`. [4](#0-3) 

This creates a timing window where blockchain time can be at or past the term boundary, but since less than 2/3 of miners have crossed it yet, the system still generates `NextRound` commands with mining times that extend into the next term's time period.

The validation providers fail to prevent this issue. `RoundTerminateValidationProvider` only checks that the round number increments correctly and that InValues are null for NextRound behavior, but does not validate term boundary alignment. [5](#0-4)  Similarly, `TimeSlotValidationProvider` only validates time slot correctness within the round structure, not term boundaries. [6](#0-5) 

When `ProcessNextRound` executes, it does not update the term number - only `ProcessNextTerm` performs this update. [7](#0-6)  Therefore, rounds created via NextRound behavior maintain the previous term's number even when their blocks are mined beyond the term boundary.

## Impact Explanation

The impact manifests through mining reward misallocation. When rounds are generated for the next round via `GenerateNextRoundInformation`, each miner's `ProducedBlocks` counter is copied from the previous round, creating a cumulative counter that accumulates across all rounds within a term. [8](#0-7) 

When `ProcessNextTerm` is executed, it calls `DonateMiningReward(previousRound)`, which calculates the total mining reward for the term using `previousRound.GetMinedBlocks()`. [9](#0-8)  The `GetMinedBlocks()` method sums the cumulative `ProducedBlocks` counters from all miners in that round. [10](#0-9) 

If rounds 101-104 are mined after Term N's end time but have TermNumber=N (because less than 2/3 of miners had crossed the boundary when those rounds were created), then:
1. These blocks increment the `ProducedBlocks` counters in rounds with TermNumber=N
2. When the system finally transitions to Term N+1, the last round with TermNumber=N includes these inflated block counts
3. The reward donation for Term N includes blocks that were actually mined in Term N+1's time period
4. This causes Term N to receive excess rewards while Term N+1 receives fewer rewards

This breaks the fundamental invariant that term numbers must align with their designated time periods, which is relied upon for:
- Economic distribution periods and reward calculations
- Election timing and miner selection windows  
- Governance action execution timing
- Off-chain monitoring and analytics systems

## Likelihood Explanation

This vulnerability occurs naturally during every term transition without any attacker action required. The preconditions are:

1. Blockchain time approaches the term end boundary (within approximately one round duration)
2. Current block time is at or past the term end time
3. Less than 2/3 of miners (MinersCountOfConsent) have mined blocks past the boundary yet
4. A miner attempts to terminate the current round

These conditions are guaranteed to occur at every term transition (typically every 7 days based on PeriodSeconds). The 2/3 threshold check creates an inevitable race condition where some miners will be generating NextRound commands when the blockchain time is already past the term boundary. The issue is not exploitable by malicious actors but rather is a design flaw that manifests deterministically during normal consensus operation.

Given that term transitions occur regularly (e.g., weekly), and the timing window exists at every transition, the probability of occurrence is HIGH with impact recurring over time.

## Recommendation

Add term boundary validation to `ArrangeAbnormalMiningTime` before returning the calculated timestamp. The method should check if the arranged time exceeds the current term's end time (calculated as `termStartTime + PeriodSeconds`), and if so, either:

1. Force the arranged time to be capped at the term boundary, or
2. Signal that a NextTerm behavior should be used instead of NextRound

Additionally, add a validation provider that checks term boundary alignment for all consensus commands, rejecting blocks that would be mined beyond the current term's end time when using NextRound behavior.

Example fix for `ArrangeAbnormalMiningTime`:
```csharp
public Timestamp ArrangeAbnormalMiningTime(string pubkey, Timestamp currentBlockTime,
    Timestamp termEndTime, bool mustExceededCurrentRound = false)
{
    // ... existing calculation logic ...
    var arrangedTime = futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
    
    // Validate term boundary
    if (arrangedTime > termEndTime)
    {
        // Should trigger NextTerm instead
        return null; // Or throw exception to force NextTerm behavior
    }
    
    return arrangedTime;
}
```

## Proof of Concept

The vulnerability can be demonstrated through the following test scenario:

1. Set up a blockchain at time T with Term N having `PeriodSeconds = 604800` (7 days)
2. Mine blocks normally until blockchain time reaches T + 604790 seconds (10 seconds before term end)
3. Ensure only 1/3 of miners have crossed the T + 604800 boundary
4. Have a miner call the consensus command generation for round termination
5. Observe that `NeedToChangeTerm()` returns false (since less than 2/3 crossed)
6. Observe that `ArrangeAbnormalMiningTime` returns a timestamp beyond T + 604800
7. Observe that the NextRound behavior is used with TermNumber remaining as N
8. Mine several more rounds (all with TermNumber=N) until 2/3 threshold is met
9. When NextTerm finally executes, observe that `DonateMiningReward` counts all these extra blocks toward Term N's rewards

The test would verify that blocks mined at timestamps T + 604850, T + 604920, etc. (well into the next term's time period) are counted in Term N's reward calculation, confirming the reward misallocation.

## Notes

This is a design-level invariant violation in the consensus mechanism rather than an exploitable vulnerability by malicious actors. The issue occurs deterministically during normal operation and affects the integrity of the economic model by misaligning term-based reward calculations with actual time periods. The term boundary is explicitly defined and documented throughout the codebase but is not enforced during mining time arrangement, creating a systemic inconsistency that recurs at every term transition.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L19-37)
```csharp
    public Timestamp ArrangeAbnormalMiningTime(string pubkey, Timestamp currentBlockTime,
        bool mustExceededCurrentRound = false)
    {
        var miningInterval = GetMiningInterval();

        var minerInRound = RealTimeMinersInformation[pubkey];

        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
        }

        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-35)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L21-36)
```csharp
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L124-127)
```csharp
    public long GetMinedBlocks()
    {
        return RealTimeMinersInformation.Values.Sum(minerInRound => minerInRound.ProducedBlocks);
    }
```
