# Audit Report

## Title
Premature Round Termination via Time Slot Bypass in Side Chain Consensus

## Summary
A side chain miner can prematurely terminate the current consensus round before their time slot expires by producing the maximum number of tiny blocks quickly. This causes other miners to lose their block production turns and associated rewards, violating consensus fairness guarantees.

## Finding Description

The vulnerability exists in the consensus behavior determination logic. When a miner has produced blocks in the current round (`OutValue != null`) and their time slot has NOT yet passed (`!_isTimeSlotPassed`), but they have already reached the maximum block count (`ActualMiningTimes.Count >= maximumBlocksCount`), the code falls through to call `GetConsensusBehaviourToTerminateCurrentRound()`. [1](#0-0) 

For side chains, this method unconditionally returns `AElfConsensusBehaviour.NextRound`, instructing the miner to terminate the round. [2](#0-1) 

The `ProcessNextRound` method that handles round termination contains no validation to verify whether the round should legitimately end. It simply records mined miners and updates round information without checking if all miners have had their turns or if sufficient time has elapsed. [3](#0-2) 

The consensus validation layer fails to prevent this premature termination:

1. `RoundTerminateValidationProvider` only validates that the round number increments by 1 and that InValues are null in the next round - it does not check whether termination is legitimate. [4](#0-3) 

2. `TimeSlotValidationProvider` bypasses time slot checks when a new round is provided (i.e., when `ProvidedRound.RoundId != BaseRound.RoundId`), only validating the new round's structure. [5](#0-4) 

3. `NextRoundMiningOrderValidationProvider` validates the consistency of the next round's structure but does not check if the current round should terminate. [6](#0-5) 

**Attack Scenario:**
1. Miner A's time slot begins (duration typically ~4 seconds)
2. Miner A rapidly produces 8 tiny blocks in ~3 seconds
3. Miner A's time slot has NOT yet expired 
4. The consensus behavior logic returns `NextRound` 
5. Miner A submits a `NextRound` transaction
6. Validation passes - no check for premature termination
7. Round terminates immediately
8. Miners B, C, D who haven't had their turns are skipped and lose rewards

## Impact Explanation

This vulnerability breaks the fundamental consensus fairness guarantee that each miner receives their designated time slot to produce blocks. The impact includes:

1. **Direct Reward Loss**: Miners who are skipped lose the opportunity to produce blocks and earn associated mining rewards
2. **Consensus Integrity Violation**: The round-robin scheduling mechanism is bypassed, allowing strategic manipulation of round progression
3. **Cumulative Effect**: If multiple miners exploit this, the system degrades into a race condition where miners compete to produce blocks as fast as possible and terminate rounds prematurely
4. **Side Chain Specific**: Side chains are particularly vulnerable as they lack the additional checks present in main chain consensus

The maximum block count is typically 8 blocks. [7](#0-6)  With a mining interval of approximately 4 seconds, [8](#0-7)  a miner can feasibly produce all 8 blocks before their time slot expires.

## Likelihood Explanation

The exploit has **HIGH** likelihood for the following reasons:

**Attacker Capabilities**: Any regular side chain miner can exploit this - no special privileges required beyond being in the miner list.

**Attack Complexity**: Very low. The attacker simply needs to:
- Produce tiny blocks efficiently during their time slot (normal mining behavior)
- Reach the `maximumBlocksCount` limit before their time slot expires (~500ms per block average)
- Follow the legitimate consensus command they receive

**Feasibility**: With modern hardware, producing 8 empty or tiny blocks in under 4 seconds is trivial. The mining interval check calculates the time slot duration dynamically based on miner count, [8](#0-7)  and the scenario is reachable in normal operations without requiring specific state manipulation.

**Detection Difficulty**: The behavior may appear as normal consensus operations since the miner follows legitimate consensus commands. Only by comparing expected versus actual round durations would the premature termination be detectable.

## Recommendation

Add validation in `ProcessNextRound` to verify round termination is legitimate:

1. Check that the current block time exceeds the expected round end time
2. Verify that a minimum number of miners have had their turns
3. Ensure the terminating miner's time slot has actually passed

Additionally, modify the `GetConsensusBehaviour` logic to not return `NextRound` when `!_isTimeSlotPassed` unless the miner is the designated extra block producer.

Example validation to add in `ProcessNextRound`:
```csharp
// Verify round should actually terminate
var roundEndTime = currentRound.GetExtraBlockMiningTime();
if (Context.CurrentBlockTime < roundEndTime)
{
    Assert(false, "Cannot terminate round before expected end time.");
}
```

## Proof of Concept

While a full executable test would require setting up a side chain test environment, the theoretical proof of concept follows this sequence:

1. **Setup**: Side chain with 5 miners (A, B, C, D, E), mining interval = 4000ms
2. **Round Start**: Miner A's time slot begins at time T
3. **Rapid Mining**: Miner A produces 8 tiny blocks between T and T+3000ms
4. **Query Command**: At T+3000ms, Miner A queries `GetConsensusCommand`
   - `GetConsensusBehaviour` is invoked
   - `_isTimeSlotPassed` = false (time slot ends at T+4000ms)
   - `ActualMiningTimes.Count` = 8 >= `maximumBlocksCount`
   - Not `ExtraBlockProducerOfPreviousRound`
   - Returns `NextRound`
5. **Execute**: Miner A submits `NextRound` transaction
6. **Validation Passes**: No validator checks if termination is premature
7. **Result**: Round terminates at T+3000ms, Miners B, C, D, E lose their turns

The vulnerability is confirmed through code analysis showing the exact logic flow and absence of protective validations.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-82)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
            }

            return GetConsensusBehaviourToTerminateCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L20-23)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L13-19)
```csharp
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```
