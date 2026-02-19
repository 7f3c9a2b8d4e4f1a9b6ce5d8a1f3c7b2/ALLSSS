# Audit Report

## Title
Miner List Manipulation Bypasses Solitary Miner Detection via Unvalidated Round Transitions

## Summary
The AEDPoS consensus contract fails to validate that the miner list in `NextRound` and `NextTerm` transactions matches the expected miner set. A malicious miner can submit a round with a reduced miner list (≤2 miners) to permanently bypass the solitary miner detection mechanism, enabling indefinite solo mining and consensus centralization.

## Finding Description

The `SolitaryMinerDetection` mechanism prevents a single miner from producing blocks alone for extended periods by checking if more than 2 miners are configured and monitoring solo mining patterns. [1](#0-0) 

However, when processing `NextRound` transitions, the validation logic has a critical gap. The validation pipeline adds only two providers for NextRound behavior: `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`. [2](#0-1) 

**RoundTerminateValidationProvider** only validates that the round number increments by 1 and InValues are null, but does not validate the miner count or list membership. [3](#0-2) 

**NextRoundMiningOrderValidationProvider** only checks internal consistency within the provided round (miners with FinalOrderOfNextRound > 0 equals miners with OutValue != null), not against the baseline miner list. [4](#0-3) 

**ProcessNextRound** directly accepts the provided round and stores it without validating that the miner list matches the current round's miners. [5](#0-4) 

The legitimate round generation includes all miners from the current round, maintaining the complete miner set. [6](#0-5) 

**Attack Execution:**
1. Attacker is a legitimate miner in the current round
2. Crafts a malicious `NextRoundInput` with only 2 or fewer miner entries (including themselves)
3. Ensures internal consistency: miners with `FinalOrderOfNextRound > 0` equals those with `OutValue != null`
4. Ensures all `InValue` fields are null and round number increments correctly
5. Submits the `NextRound` transaction
6. Validation passes because no validator compares the miner list against the expected set
7. Malicious round is stored in state
8. Future solitary miner detection reads from state and finds `Count ≤ 2`, causing the protection to be disabled
9. Attacker can mine alone indefinitely without triggering detection

The same vulnerability applies to `NextTerm` transitions. [7](#0-6) 

## Impact Explanation

**Critical Consensus Integrity Compromise:**

1. **Solitary Mining Protection Bypass**: The fundamental security mechanism that prevents single-party control is permanently disabled by manipulating the stored round state.

2. **Consensus Centralization**: Once the malicious round is accepted, the attacker effectively controls the blockchain through solo mining without triggering any protection mechanisms.

3. **Honest Miner Exclusion**: All other miners are removed from the consensus set and cannot produce blocks or earn rewards.

4. **Network-Wide Impact**: All nodes validate using the same flawed logic and accept the manipulated round, making the attack persistent across the entire network.

5. **Permanent State Corruption**: Future rounds build upon the corrupted state, maintaining the reduced miner set indefinitely unless corrected through term transitions (which are also vulnerable).

This breaks the core security guarantee of decentralized consensus and degrades the network to single-party control.

## Likelihood Explanation

**High Feasibility:**

1. **Attacker Prerequisites**: Only requires being a legitimate miner in the current consensus set, which is achievable through normal election/staking mechanisms.

2. **No Special Timing**: The attack succeeds whenever the attacker produces blocks, which happens naturally through round rotation.

3. **Deterministic Success**: The validation logic deterministically accepts malicious input that passes the minimal checks (round number, InValue nullness, internal consistency).

4. **Low Complexity**: No cryptographic breaking, race conditions, or complex state manipulation required. Simply craft and submit a properly-formatted but malicious round.

5. **Minimal Cost**: Only requires standard transaction fees.

6. **No Detection**: The manipulation occurs silently through valid consensus transactions, making it difficult to detect before the damage is done.

## Recommendation

Add miner list validation to the consensus validation pipeline:

**For NextRound:**
Add a new validation provider that ensures the provided round contains exactly the same miners as the base round:

```csharp
public class MinerListConsistencyValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var providedMiners = validationContext.ProvidedRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        
        if (baseMiners.Count != providedMiners.Count || !baseMiners.SequenceEqual(providedMiners))
        {
            validationResult.Message = "Miner list in provided round does not match current round.";
            return validationResult;
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

Add this validator to the NextRound validation pipeline in `AEDPoSContract_Validation.cs`.

**For NextTerm:**
Add validation that the provided round's miner list matches the result from `GetVictories` in the Election Contract before accepting the term transition.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MaliciousMiner_CanBypassSolitaryDetection_WithReducedMinerList()
{
    // Setup: Initialize consensus with 5 miners
    var initialMiners = new[] { "miner1", "miner2", "miner3", "miner4", "miner5" };
    await InitializeConsensusWithMiners(initialMiners);
    
    // Current round has all 5 miners
    var currentRound = await GetCurrentRound();
    Assert.Equal(5, currentRound.RealTimeMinersInformation.Count);
    
    // Malicious miner crafts NextRound with only 2 miners
    var maliciousNextRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation =
        {
            { "miner1", new MinerInRound { Pubkey = "miner1", Order = 1, FinalOrderOfNextRound = 1, OutValue = Hash.FromString("out1") }},
            { "miner2", new MinerInRound { Pubkey = "miner2", Order = 2, FinalOrderOfNextRound = 2, OutValue = Hash.FromString("out2") }}
        }
    };
    
    var maliciousInput = new NextRoundInput();
    maliciousInput.MergeFrom(maliciousNextRound.ToByteString());
    
    // Attacker submits malicious NextRound - this should fail but doesn't
    var result = await ConsensusContract.NextRound(maliciousInput);
    
    // Verify attack succeeded
    var newRound = await GetCurrentRound();
    Assert.Equal(2, newRound.RealTimeMinersInformation.Count); // Only 2 miners!
    
    // Verify solitary detection is now bypassed
    var isSolitaryDetectionActive = newRound.RealTimeMinersInformation.Count > 2;
    Assert.False(isSolitaryDetectionActive); // Detection is disabled!
    
    // Miner1 can now mine alone indefinitely without triggering protection
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L66-96)
```csharp
    private bool SolitaryMinerDetection(Round currentRound, string pubkey)
    {
        var isAlone = false;
        // Skip this detection until 4th round.
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
        {
            // Not single node.

            var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
            isAlone = minedMinersOfCurrentRound.Count == 0;

            // If only this node mined during previous round, stop mining.
            if (TryToGetPreviousRoundInformation(out var previousRound) && isAlone)
            {
                var minedMiners = previousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }

            // check one further round.
            if (isAlone && TryToGetRoundInformation(previousRound.RoundNumber.Sub(1),
                    out var previousPreviousRound))
            {
                var minedMiners = previousPreviousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }
        }

        return isAlone;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```
