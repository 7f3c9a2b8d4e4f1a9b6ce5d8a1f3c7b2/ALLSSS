### Title
Malicious Miner Can Inject Arbitrary ImpliedIrreversibleBlockHeight Values During NextRound Transition, Causing Consensus DoS

### Summary
A malicious miner producing a NextRound block can inject arbitrarily high `ImpliedIrreversibleBlockHeight` values into the new round's data structure. Because NextRound operations lack `LibInformationValidationProvider` validation, these malicious values are stored without verification. This causes all subsequent UpdateValue transactions in that round to fail validation, effectively blocking normal consensus operations for the entire round.

### Finding Description

The vulnerability exists in the consensus round transition mechanism. When a new round is created: [1](#0-0) 

The `GenerateNextRoundInformation` method correctly creates fresh `MinerInRound` objects with `ImpliedIrreversibleBlockHeight` defaulting to 0. However, during NextRound block production: [2](#0-1) 

The generated round data is returned in the consensus header. A malicious miner can modify the `RealTimeMinersInformation` in the `NextRoundInput` before submitting the block. [3](#0-2) 

The validation for NextRound operations does NOT include `LibInformationValidationProvider`: [4](#0-3) 

When the NextRound block is processed, the modified round data (including inflated `ImpliedIrreversibleBlockHeight` values) is stored: [5](#0-4) 

Subsequently, when honest miners attempt UpdateValue transactions with their actual `ImpliedIrreversibleBlockHeight` (set to current block height): [6](#0-5) 

The validation fails because `LibInformationValidationProvider` checks that the value should not decrease: [7](#0-6) 

If `baseRound.ImpliedIrreversibleBlockHeight` (malicious value like 999999999) is greater than `providedRound.ImpliedIrreversibleBlockHeight` (honest miner's current height like 1010), validation fails with "Incorrect implied lib height."

### Impact Explanation

**Consensus Disruption**: All UpdateValue transactions in the affected round fail validation, preventing normal consensus operations. Miners cannot update their consensus information, signatures, or order for the next round.

**LIB Calculation Impact**: The Last Irreversible Block calculation depends on miners' `ImpliedIrreversibleBlockHeight` values from the previous round: [8](#0-7) 

With malicious values, the LIB calculation in the subsequent round would use inflated heights, potentially causing incorrect finality determination.

**Operational DoS**: The affected round becomes unusable for normal consensus updates, though miners may still produce TinyBlocks (which don't validate `ImpliedIrreversibleBlockHeight`). However, TinyBlocks preserve existing values, so the attack persists throughout the round.

**Affected Parties**: All network miners and nodes are affected, as consensus cannot progress normally during the compromised round.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be an elected miner in the consensus set. In AElf's DPoS system, this is a realistic constraint as miners are regularly elected.

**Attack Opportunity**: The attack can be executed whenever the malicious miner's turn comes to produce the NextRound block, which occurs regularly in the mining rotation. The extra block producer determines the NextRound, giving periodic opportunities.

**Attack Complexity**: Low. The attacker needs to:
1. Intercept the result from `GetConsensusExtraDataForNextRound`
2. Modify the `ImpliedIrreversibleBlockHeight` fields in the round data
3. Submit the modified data in their block

**Detection**: The attack would be immediately noticeable as UpdateValue transactions start failing, but by then the malicious round is already stored in state.

**Persistence**: The attack affects only the targeted round (round N+1). Round N+2 would be generated fresh from round N+1 using `GenerateNextRoundInformation`, which creates new objects with reset values. However, the attacker can repeat the attack on every NextRound opportunity.

### Recommendation

Add `LibInformationValidationProvider` to the validation pipeline for NextRound operations:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
``` [9](#0-8) 

Additionally, strengthen validation in `LibInformationValidationProvider` to check that `ImpliedIrreversibleBlockHeight` values in NextRound/NextTerm inputs match the values from the newly generated round (all should be 0 for fresh rounds).

Add regression tests that:
1. Verify NextRound with inflated `ImpliedIrreversibleBlockHeight` values is rejected
2. Confirm UpdateValue transactions succeed after a valid NextRound
3. Test that repeated NextRound attacks are prevented

### Proof of Concept

**Initial State:**
- Current round: N (round number 100)
- Multiple miners have produced blocks with legitimate `ImpliedIrreversibleBlockHeight` values (e.g., 1000-1010)

**Attack Steps:**

1. Malicious miner's turn to produce NextRound block (transition to round 101)
2. Miner calls `GetConsensusExtraDataForNextRound` which generates correct nextRound with all `ImpliedIrreversibleBlockHeight = 0`
3. Before submitting block, attacker modifies the round data:
   ```
   For each miner in nextRound.RealTimeMinersInformation:
       miner.ImpliedIrreversibleBlockHeight = 999999999
   ```
4. Submit NextRound block with modified data
5. Block passes validation (no LibInformationValidationProvider for NextRound)
6. Modified round 101 is stored in `State.Rounds[101]`

**Result:**
- Honest miners attempt UpdateValue in round 101
- Their `ImpliedIrreversibleBlockHeight` is set to current height (~1020)
- Validation compares: baseRound (999999999) > providedRound (1020)
- Validation fails: "Incorrect implied lib height"
- All UpdateValue transactions rejected
- Consensus disrupted for entire round 101

**Success Condition:** Miner produces NextRound block with arbitrarily high `ImpliedIrreversibleBlockHeight` values that get accepted and stored, causing subsequent UpdateValue validations to fail until round 102 begins.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L7-23)
```csharp
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```
