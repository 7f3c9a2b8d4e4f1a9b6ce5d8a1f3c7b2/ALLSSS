# Audit Report

## Title
Missing Miner List Validation in NextRound Transitions Allows Consensus Disruption via Inflated Miner Count

## Summary
The NextRound consensus validation logic fails to verify that the provided next round's miner list matches the current round's authorized miners. A malicious miner can inject fake entries into `RealTimeMinersInformation`, causing consensus disruption through incorrect order assignments, wasted time slots, and persistent corruption until the next term transition.

## Finding Description

**Root Cause - Missing Miner Set Validation:**

During NextRound validation, the system applies two validators but neither checks that the miner set (keys) in the provided round matches the authorized miners in the base round: [1](#0-0) 

The `NextRoundMiningOrderValidationProvider` only validates internal consistency by checking that the count of miners with `FinalOrderOfNextRound > 0` equals the count with `OutValue != null`: [2](#0-1) 

For a freshly generated next round, all miners have `FinalOrderOfNextRound = 0` and `OutValue = null`, so this check passes as `0 == 0` regardless of whether fake miners are present.

The `RoundTerminateValidationProvider` only checks that the round number increments correctly and all `InValue` fields are null: [3](#0-2) 

Fake miners with default values satisfy this check.

The validation context provides both `BaseRound` (trusted current state) and `ProvidedRound` (from block header): [4](#0-3) 

However, no validator compares `ProvidedRound.RealTimeMinersInformation.Keys` against `BaseRound.RealTimeMinersInformation.Keys`.

**Exploitation Path:**

1. A malicious miner generates a legitimate next round via the consensus extra data method: [5](#0-4) 

2. Before including in the block, the miner modifies `nextRound.RealTimeMinersInformation` to add fake `MinerInRound` entries with default values

3. Validation passes all checks since no validator performs miner set verification

4. The corrupted round is stored to state: [6](#0-5) 

5. When the next round is generated from this corrupted round, fake miners are carried forward because `GenerateNextRoundInformation` iterates through all entries in `RealTimeMinersInformation`: [7](#0-6) 

6. The inflated miner count corrupts the consensus order assignment algorithm: [8](#0-7) 

The modulus operation uses `RealTimeMinersInformation.Count`, producing incorrect results with an inflated count.

## Impact Explanation

**Consensus Integrity Breach:**
The inflated miner count directly affects deterministic order assignment. The calculation `GetAbsModulus(sigNum, blockProducerCount) + 1` produces different results with manipulated counts, causing legitimate miners to receive incorrect order assignments and disrupting the expected block production sequence.

**Operational Disruption:**
Fake miners are assigned time slots and expected mining times but cannot produce blocks, creating persistent gaps in the block production schedule. Each fake miner represents a missed time slot that delays network progress and degrades blockchain liveness.

**Persistent Corruption:**
The corruption persists through subsequent rounds because `GenerateNextRoundInformation` propagates all miners from the current round. Only a NextTerm transition (which rebuilds the miner list from election results) can recover: [9](#0-8) 

**Severity:** High - A single malicious miner can disrupt consensus for all validators, degrade block production reliability, and maintain the corruption across multiple rounds.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a current miner (moderate barrier - requires winning election)
- Must be producing the NextRound transition block (periodic opportunity - every round has a NextRound transition)
- Must modify node software to inject fake miners (low technical complexity - simple dictionary manipulation)

**Attack Feasibility:**
The attack is straightforward: generate legitimate consensus data via the contract method, modify the `RealTimeMinersInformation` dictionary to add entries with default field values, and include it in the block header. No complex cryptographic operations or state manipulation required.

**Detection Difficulty:**
The corrupted state appears valid to all validation logic. Fake miners manifest as missed time slots during block production, which could be attributed to network issues rather than recognized as an attack.

**Probability:** High if any current miner is malicious, as the validation gap makes execution trivial and detection difficult.

## Recommendation

Add a miner set validation provider for NextRound behavior that verifies the provided round's miner list matches the base round:

```csharp
public class MinerListValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        
        // Only validate for NextRound behavior
        if (validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.NextRound)
        {
            validationResult.Success = true;
            return validationResult;
        }
        
        var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var providedMiners = validationContext.ProvidedRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        
        if (!baseMiners.SequenceEqual(providedMiners))
        {
            validationResult.Message = "Miner list mismatch between base and provided rounds.";
            return validationResult;
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

Register this provider in the validation flow: [1](#0-0) 

Add the new provider before `NextRoundMiningOrderValidationProvider`.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanInjectFakeMinersIntoNextRound()
{
    // Setup: Initialize consensus with 3 legitimate miners
    var initialMiners = GenerateMiners(3);
    await InitializeConsensus(initialMiners);
    
    // Attacker (miner 0) generates legitimate NextRound
    var currentRound = await GetCurrentRoundInformation();
    var legitimateNextRound = GenerateNextRoundFromCurrent(currentRound);
    
    // Attack: Add fake miners to RealTimeMinersInformation
    var fakeMiner1 = GenerateFakeMiner("FAKE_MINER_1");
    var fakeMiner2 = GenerateFakeMiner("FAKE_MINER_2");
    legitimateNextRound.RealTimeMinersInformation[fakeMiner1.Pubkey] = fakeMiner1;
    legitimateNextRound.RealTimeMinersInformation[fakeMiner2.Pubkey] = fakeMiner2;
    
    // Create NextRoundInput with inflated miner list
    var maliciousInput = NextRoundInput.Create(legitimateNextRound, randomNumber);
    
    // Verify: Validation should fail but currently passes
    var result = await ConsensusContract.NextRound.SendAsync(maliciousInput);
    
    // Assert: Round is accepted with fake miners
    var storedRound = await GetCurrentRoundInformation();
    storedRound.RealTimeMinersInformation.Count.ShouldBe(5); // 3 real + 2 fake
    storedRound.RealTimeMinersInformation.Keys.ShouldContain(fakeMiner1.Pubkey);
    storedRound.RealTimeMinersInformation.Keys.ShouldContain(fakeMiner2.Pubkey);
    
    // Impact: Next round generation propagates fake miners
    var subsequentRound = GenerateNextRoundFromCurrent(storedRound);
    subsequentRound.RealTimeMinersInformation.Count.ShouldBe(5); // Corruption persists
}
```

## Notes

This vulnerability represents a critical flaw in the AEDPoS consensus validation logic. The absence of miner set verification allows any current miner to manipulate the consensus state, breaking the fundamental assumption that the miner list remains consistent across round transitions (except during term changes). The attack is particularly dangerous because:

1. It bypasses all existing validation providers
2. The corrupted state propagates automatically through `GenerateNextRoundInformation`
3. Detection is difficult as fake miners appear as legitimate missed time slots
4. Recovery only occurs at term boundaries when election results are queried

The fix should be implemented immediately to prevent consensus manipulation by malicious miners.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L19-27)
```csharp
    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-177)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-191)
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

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-56)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```
