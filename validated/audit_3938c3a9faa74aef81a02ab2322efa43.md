# Audit Report

## Title
Byzantine Miner Can Disrupt Consensus by Providing NextRound with Malformed ExpectedMiningTime Values

## Summary
A Byzantine miner producing a NextRound block can inject a Round object with ExpectedMiningTime values set to timestamps in the distant past. The validation logic only checks interval consistency but not absolute time values, allowing corrupted round data to be written to state and disrupting normal block production for all miners.

## Finding Description

The AEDPoS consensus contract contains a critical validation gap in the `CheckRoundTimeSlots` method that validates NextRound consensus extra data. [1](#0-0) 

This validation only verifies:
1. ExpectedMiningTime fields are not null
2. Mining intervals between consecutive miners are greater than zero
3. Mining intervals are relatively equal

**The validation does NOT check that ExpectedMiningTime values are reasonable relative to the current block time or that they are in the future.**

When a new round is proposed, the `TimeSlotValidationProvider` calls `CheckRoundTimeSlots` to validate the round structure. [2](#0-1) 

A Byzantine miner can exploit this by crafting a Round with ExpectedMiningTime values set to very early timestamps (e.g., Seconds=0, 1, 2, 3...) while maintaining proper intervals. The validation passes because intervals are consistent, but once this malicious Round is written to state via `ProcessNextRound` [3](#0-2) , all subsequent miners are affected.

When miners check if their time slot has passed using `IsTimeSlotPassed`, the comparison `minerInRound.ExpectedMiningTime + miningInterval < currentBlockTime` returns TRUE for all miners since their ExpectedMiningTime values are in the distant past. [4](#0-3) 

This causes the `ConsensusBehaviourProviderBase` to set `_isTimeSlotPassed = true` for all miners. [5](#0-4) 

With this flag set, the normal UpdateValue behavior is prevented, and all miners fall through to `GetConsensusBehaviourToTerminateCurrentRound`, forcing everyone to attempt NextRound/NextTerm behavior instead of normal block production. [6](#0-5) 

The legitimate round generation sets ExpectedMiningTime based on `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`, ensuring future timestamps. [7](#0-6)  However, there is no validation enforcing this during NextRound validation.

## Impact Explanation

This vulnerability breaks the consensus protocol's scheduled time slot system, which is fundamental to AEDPoS operation. Once the corrupted round data is in state:

1. **Consensus Disruption**: All miners are prevented from producing normal UpdateValue blocks, as their time slots are incorrectly marked as passed
2. **Scheduled Mining Broken**: The carefully orchestrated mining schedule is completely bypassed
3. **Chaotic Recovery**: All miners simultaneously attempt to produce NextRound blocks, creating confusion and potential delays
4. **Cascading Effect**: The `ArrangeNormalBlockMiningTime` function would consistently return `currentBlockTime` instead of properly scheduled times [8](#0-7) 

The impact is categorized as **MEDIUM** severity because:
- It disrupts consensus operations for one or more rounds
- Recovery is possible through miners producing corrected NextRound blocks, though chaotic
- Does not result in permanent chain halt, fund theft, or permanent state corruption
- The blockchain can eventually recover with corrected round data

## Likelihood Explanation

The likelihood of this vulnerability being exploited is **MEDIUM** because:

**Attacker Requirements:**
- Must be a current miner in the consensus round (requires staking and election)
- Must be selected to produce the NextRound extra block (happens periodically based on schedule)
- Can modify consensus extra data in their produced block (normal miner capability)

**Attack Complexity:**
- **LOW** - The attack only requires modifying the Round object's ExpectedMiningTime values before including it in the block's consensus extra data
- No complex cryptographic operations needed
- No multi-step coordination required
- The validation gap is straightforward to exploit once identified

**Feasibility:**
- The attacker must wait for their turn to produce a NextRound block, which occurs regularly in the consensus cycle
- No special permissions beyond normal miner status are required
- The attack can be executed repeatedly whenever the attacker produces a NextRound block

**Detection:**
- Malformed timestamps would be visible in the block's consensus extra data upon inspection
- Monitoring tools could detect ExpectedMiningTime values far in the past
- The resulting disruption (all miners attempting NextRound) would be immediately observable

## Recommendation

Add validation in `CheckRoundTimeSlots` to ensure ExpectedMiningTime values are reasonable relative to the current block time:

```csharp
public ValidationResult CheckRoundTimeSlots(Timestamp currentBlockTime)
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

    // NEW: Validate that ExpectedMiningTime values are in the future
    var firstMinerTime = miners[0].ExpectedMiningTime;
    if (firstMinerTime <= currentBlockTime)
        return new ValidationResult { Message = "ExpectedMiningTime must be in the future" };

    var baseMiningInterval = (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();
    if (baseMiningInterval <= 0)
        return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

    // NEW: Validate reasonable maximum time (e.g., not more than 1 hour in future per miner)
    var maxReasonableTime = currentBlockTime.AddMilliseconds(baseMiningInterval.Mul(miners.Count).Mul(10));
    if (miners.Any(m => m.ExpectedMiningTime > maxReasonableTime))
        return new ValidationResult { Message = "ExpectedMiningTime values exceed reasonable bounds" };

    for (var i = 1; i < miners.Count - 1; i++)
    {
        var miningInterval = (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
        if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
            return new ValidationResult { Message = "Time slots are so different." };
    }

    return new ValidationResult { Success = true };
}
```

Additionally, update the `TimeSlotValidationProvider` to pass the current block time to `CheckRoundTimeSlots`:

```csharp
validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots(validationContext.CurrentBlockTime);
```

## Proof of Concept

A proof of concept would require:

1. Setting up a test environment with multiple consensus nodes
2. Modifying one node to act as a Byzantine miner
3. When it's the Byzantine node's turn to produce a NextRound block, inject malformed Round data with ExpectedMiningTime values set to timestamps near epoch zero (e.g., Seconds = 0, 1, 2, 3...) with proper intervals
4. Observe that the validation passes and the corrupted Round is written to state
5. Verify that subsequent miners have `IsTimeSlotPassed` return TRUE and cannot produce normal UpdateValue blocks
6. Confirm all miners fall into NextRound termination behavior

The test would demonstrate that the `CheckRoundTimeSlots` validation accepts past timestamps as long as intervals are consistent, breaking the consensus time slot system.

---

**Notes:**

This vulnerability exploits a gap in the consensus validation logic where relative timing (intervals) is checked but absolute timing (whether ExpectedMiningTime is in the future) is not validated. The legitimate round generation always sets future timestamps, but there is no enforcement of this invariant during validation. This allows a Byzantine miner to inject corrupted round data that disrupts the carefully orchestrated consensus scheduling system, though the blockchain can eventually recover through subsequent NextRound blocks with corrected timestamps.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L83-99)
```csharp
    public bool IsTimeSlotPassed(string publicKey, Timestamp currentBlockTime)
    {
        var miningInterval = GetMiningInterval();
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
        if (RoundNumber != 1)
            return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } <
                   currentBlockTime;

        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;

        var actualStartTime = actualStartTimes.First();
        var runningTime = currentBlockTime - actualStartTime;
        var expectedOrder = runningTime.Seconds.Div(miningInterval.Div(1000)).Add(1);
        return minerInRound.Order < expectedOrder;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L26-37)
```csharp
        protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;

            _pubkey = pubkey;
            _maximumBlocksCount = maximumBlocksCount;
            _currentBlockTime = currentBlockTime;

            _isTimeSlotPassed = CurrentRound.IsTimeSlotPassed(_pubkey, _currentBlockTime);
            _minerInRound = CurrentRound.RealTimeMinersInformation[_pubkey];
        }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L33-33)
```csharp
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L17-20)
```csharp
        public static Timestamp ArrangeNormalBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return TimestampExtensions.Max(round.GetExpectedMiningTime(pubkey), currentBlockTime);
        }
```
