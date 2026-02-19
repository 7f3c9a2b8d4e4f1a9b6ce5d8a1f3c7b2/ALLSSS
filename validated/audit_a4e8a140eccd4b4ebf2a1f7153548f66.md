# Audit Report

## Title
Missing Miner List Validation in NextRound Enables Consensus DoS via Bloated RealTimeMinersInformation Dictionary

## Summary
The AEDPoS consensus contract fails to validate that the miner list in submitted `NextRound` inputs matches the current round's miner list. A malicious miner can inject a `Round` object with an inflated `RealTimeMinersInformation` dictionary, causing excessive gas consumption in subsequent consensus operations and leading to denial of service.

## Finding Description

The vulnerability stems from insufficient validation when processing `NextRound` transactions. The contract stores the submitted `Round` object without verifying that the miner keys in `RealTimeMinersInformation` match the current round's miner list.

**Missing Validation:**

The `RoundTerminateValidationProvider` only validates round number increments and that InValues are null, but does not validate miner list composition: [1](#0-0) 

The `NextRoundMiningOrderValidationProvider` only validates internal consistency of the provided round, not comparison with the current round's miner list: [2](#0-1) 

**Exploitation Path:**

1. A malicious miner submits a `NextRound` transaction with a crafted `Round` object containing thousands of fake entries in `RealTimeMinersInformation`

2. The malicious round passes validation and gets stored directly without miner list verification: [3](#0-2) 

3. The malicious round is stored via `AddRoundInformation`: [4](#0-3) 

4. When subsequent rounds are generated, `GenerateNextRoundInformation` derives from the bloated round, propagating all fake miners: [5](#0-4) 

5. When producing the next NextRound block (two rounds after injection), `RevealSharedInValues` iterates over the bloated `previousRound.RealTimeMinersInformation`, causing excessive gas consumption: [6](#0-5) 

The iteration with `OrderBy` at line 25 has O(m log m) complexity where m is the bloated dictionary size. Even though miners without sufficient encrypted/decrypted pieces are skipped (lines 35-36), the iteration and sorting overhead still occurs.

## Impact Explanation

**Consensus Denial of Service:**
- Miners attempting to produce NextRound blocks will experience excessive gas consumption in `RevealSharedInValues`
- The bloated miner list persists across all subsequent rounds within the term, causing sustained disruption
- Consensus progression becomes extremely expensive or impossible until NextTerm is called

**Protocol Disruption:**
- All network participants are affected as consensus operations degrade
- Round transitions may fail or become prohibitively expensive
- The attack persists for an entire term (potentially days/weeks)

**Severity Justification:**
While transaction size limits may constrain the magnitude, even moderate inflation (100-1000 fake miners) could cause significant performance degradation. The complete absence of miner list validation violates critical consensus integrity invariants that should be enforced at the contract level.

## Likelihood Explanation

**Attacker Capabilities:**
- Must be a current miner with block production rights (achievable through election)
- Can craft arbitrary `NextRoundInput` messages and include them in blocks

**Attack Complexity:**
- Low: Create a `Round` object with inflated `RealTimeMinersInformation` and submit via `NextRound`
- The fake miner entries need minimal data to pass existing validations
- No special privileges beyond normal miner status required

**Feasibility:**
- Transaction size limits provide some bounds but don't prevent the attack
- Even 100-1000 fake miners could cause significant DoS
- No detection mechanism exists to identify malicious round data
- The attack is reproducible and straightforward to execute

## Recommendation

Add validation in the `NextRound` processing path to verify that the submitted miner list matches the current round's miner list:

```csharp
// In RoundTerminateValidationProvider or a new validator
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Validate miner list matches
    var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.ToHashSet();
    var providedMiners = extraData.Round.RealTimeMinersInformation.Keys.ToHashSet();
    
    if (!baseMiners.SetEquals(providedMiners))
        return new ValidationResult { Message = "Miner list mismatch in next round." };
    
    return new ValidationResult { Success = true };
}
```

For `NextTerm`, allow miner list changes but validate them against the Election contract's expected miner list.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanInflateRealTimeMinersInformation_CausingDoS()
{
    // Setup: Initialize consensus with 3 legitimate miners
    var legitimateMiners = new[] { "MinerA", "MinerB", "MinerC" };
    await InitializeConsensusWithMiners(legitimateMiners);
    
    // Get current round (Round N)
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(3, currentRound.RealTimeMinersInformation.Count);
    
    // Malicious miner crafts NextRound with 1000 fake miners
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation = { }
    };
    
    // Add legitimate miners
    foreach (var miner in legitimateMiners)
    {
        maliciousRound.RealTimeMinersInformation[miner] = new MinerInRound
        {
            Pubkey = miner,
            Order = 1,
            InValue = null // Required by validation
        };
    }
    
    // Add 1000 fake miners
    for (int i = 0; i < 1000; i++)
    {
        maliciousRound.RealTimeMinersInformation[$"FakeMiner{i}"] = new MinerInRound
        {
            Pubkey = $"FakeMiner{i}",
            Order = i + 4,
            InValue = null
        };
    }
    
    // Submit malicious NextRound - should fail but doesn't
    var result = await AEDPoSContractStub.NextRound.SendAsync(new NextRoundInput
    {
        RoundNumber = maliciousRound.RoundNumber,
        RealTimeMinersInformation = { maliciousRound.RealTimeMinersInformation }
    });
    
    // Verify malicious round was stored
    var storedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(1003, storedRound.RealTimeMinersInformation.Count); // VULNERABILITY: Should be 3, is 1003
    
    // Subsequent NextRound operations will experience DoS when RevealSharedInValues iterates over 1003 miners
}
```

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L13-54)
```csharp
    private void RevealSharedInValues(Round currentRound, string publicKey)
    {
        Context.LogDebug(() => "About to reveal shared in values.");

        if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
    }
```
