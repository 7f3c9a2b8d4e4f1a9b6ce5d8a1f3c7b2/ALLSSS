# Audit Report

## Title
Missing Miner List Validation in NextRound/NextTerm Enables Consensus DoS via Bloated RealTimeMinersInformation Dictionary

## Summary
The AEDPoS consensus contract fails to validate that the miner list in submitted `NextRound` or `NextTerm` inputs matches the current round's miner list. A malicious miner can inject a `Round` object with an arbitrarily large `RealTimeMinersInformation` dictionary, which persists in state and causes excessive gas consumption during subsequent consensus operations, leading to denial of service.

## Finding Description

The consensus contract accepts `NextRoundInput` containing a `Round` structure with a `RealTimeMinersInformation` dictionary (a protobuf `map<string, MinerInRound>` field). [1](#0-0) 

When `NextRound` is called, it processes the input through `ProcessConsensusInformation`, which converts the input to a `Round` object and stores it directly. [2](#0-1) 

The `Round` object is stored via `AddRoundInformation` which simply persists it to state without validating miner composition. [3](#0-2) 

**Missing Validation:**

The validation system for `NextRound` behavior includes only these providers: [4](#0-3) 

The `RoundTerminateValidationProvider` only validates that the round number increments by 1 and that InValues are null in the new round, but does NOT validate miner list composition. [5](#0-4) 

The `NextRoundMiningOrderValidationProvider` only validates internal consistency within the PROVIDED round (that miners with FinalOrderOfNextRound > 0 match those with OutValue != null), but does NOT compare the miner keys against the current round's miners. [6](#0-5) 

**Exploitation Path:**

1. A malicious miner crafts a `NextRoundInput` with a bloated `RealTimeMinersInformation` dictionary containing hundreds or thousands of fake miner entries
2. The input passes validation because no validator checks that the miner keys match the current round
3. The bloated `Round` is stored to state and becomes the `previousRound` for the next consensus operation
4. When subsequent miners try to produce NextRound blocks, `GetConsensusExtraDataForNextRound` calls `RevealSharedInValues` which iterates through the entire bloated dictionary. [7](#0-6) 

The `RevealSharedInValues` method iterates through `previousRound.RealTimeMinersInformation` with `OrderBy`, and performs nested `First()` searches within the loop, creating O(n*m) complexity where n is the bloated dictionary size. [8](#0-7) 

5. The bloated miner list persists because `GenerateNextRoundInformation` derives the next round from the current round's `RealTimeMinersInformation.Count` and iterates through its entries. [9](#0-8) 

## Impact Explanation

**Consensus DoS**: The excessive gas consumption in `RevealSharedInValues` during NextRound block production prevents legitimate miners from successfully producing blocks. This blocks round transitions and consensus progression.

**Protocol Disruption**: The attack creates sustained disruption because the malicious miner list propagates to all subsequent rounds within the term (only `NextTerm` would reset the miner list with explicit validation).

**Severity**: While transaction size limits may bound the attack magnitude, the complete absence of miner list validation violates critical consensus integrity invariants. Even moderate dictionary inflation (100-1000 entries) could cause significant performance degradation. The contract must enforce that only legitimate miners are included in Round structures, regardless of infrastructure protections.

## Likelihood Explanation

**Attacker Requirements**: Must be a current miner with block production rights - this is within the consensus threat model for malicious but authorized participants.

**Attack Complexity**: Low - simply craft a `NextRoundInput` with inflated `RealTimeMinersInformation` and submit via the public `NextRound` method. [10](#0-9) 

**Feasibility**: The `NextRoundInput.ToRound()` method directly copies the `RealTimeMinersInformation` map without any filtering, enabling arbitrary entries. [11](#0-10) 

Transaction size limits provide some bound but don't prevent the attack entirely - minimal data per fake miner entry is needed, and even 100-1000 fake entries could cause significant DoS while potentially fitting within transaction limits.

## Recommendation

Add a validation provider that explicitly checks the miner list composition. The validator should:

1. Extract the miner keys from the provided `Round.RealTimeMinersInformation`
2. Compare against the miner keys in the current round's `RealTimeMinersInformation`
3. Reject the input if the key sets don't match (allowing for term transitions where miner list legitimately changes)

Example validation logic:
```csharp
public class MinerListCompositionValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        var baseRound = validationContext.BaseRound;
        
        // For NextRound, miner list should match current round
        if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextRound)
        {
            var providedMiners = providedRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
            var currentMiners = baseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
            
            if (!providedMiners.SequenceEqual(currentMiners))
            {
                return new ValidationResult { Message = "Miner list in next round must match current round." };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Then add this provider to the validation pipeline in `ValidateBeforeExecution` for both `NextRound` and `NextTerm` behaviors.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanInjectBloatedMinerList_CausingDoS()
{
    // Arrange: Setup consensus with legitimate miners
    var initialMiners = new[] { "miner1", "miner2", "miner3" };
    await InitializeConsensusWithMiners(initialMiners);
    
    // Act: Malicious miner crafts NextRoundInput with bloated RealTimeMinersInformation
    var currentRound = await GetCurrentRoundInformation();
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation = { }
    };
    
    // Add legitimate miners
    foreach (var miner in currentRound.RealTimeMinersInformation)
    {
        maliciousInput.RealTimeMinersInformation[miner.Key] = miner.Value;
    }
    
    // Add 1000 fake miners to bloat the dictionary
    for (int i = 0; i < 1000; i++)
    {
        maliciousInput.RealTimeMinersInformation[$"fake_miner_{i}"] = new MinerInRound
        {
            Pubkey = $"fake_miner_{i}",
            Order = 0,
            // Other fields default/null to pass NextRoundMiningOrderValidationProvider
        };
    }
    
    // Malicious miner submits via NextRound
    var result = await ConsensusContract.NextRound.SendAsync(maliciousInput);
    
    // Assert: Transaction succeeds (vulnerability - should have been rejected)
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify bloated round was stored
    var storedRound = await GetCurrentRoundInformation();
    storedRound.RealTimeMinersInformation.Count.ShouldBe(1003); // 3 legitimate + 1000 fake
    
    // Demonstrate DoS: Next miner trying to produce block hits gas limit
    await AdvanceToNextMinerTimeSlot();
    var nextBlockResult = await ProduceNextRoundBlock();
    
    // Gas consumption will be excessive due to RevealSharedInValues iterating through bloated dict
    nextBlockResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    nextBlockResult.TransactionResult.Error.ShouldContain("gas");
}
```

### Citations

**File:** protobuf/aedpos_contract.proto (L243-264)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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
