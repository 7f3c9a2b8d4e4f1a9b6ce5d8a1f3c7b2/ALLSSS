### Title
NextRound Blocks Can Decrease Last Irreversible Block Height Without Validation

### Summary
The `ValidateBeforeExecution` function only adds `LibInformationValidationProvider` for `UpdateValue` behavior but not for `NextRound` behavior. Since `NextRoundInput` contains `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields that are directly stored in state without validation, a malicious extra block producer can submit a `NextRound` block with decreased LIB information, breaking the fundamental blockchain invariant that LIB height must be monotonically increasing.

### Finding Description

In [1](#0-0) , the validation pipeline for `NextRound` behavior (lines 84-88) does not include `LibInformationValidationProvider`, which is only added for `UpdateValue` behavior (line 82).

However, [2](#0-1)  shows that `NextRoundInput` contains `ConfirmedIrreversibleBlockHeight` (line 16) and `ConfirmedIrreversibleBlockRoundNumber` (line 17) fields that are included when creating next round data.

The [3](#0-2)  validates that LIB information does not decrease by checking if `baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight` (line 16) and similarly for round numbers and implied heights. This critical check is bypassed for `NextRound` behavior.

When `NextRound` is processed in [4](#0-3) , the input is converted to a Round object (line 110) and directly stored via `AddRoundInformation(nextRound)` (line 156) without any LIB validation or recalculation. Unlike `ProcessUpdateValue` which calculates LIB using `LastIrreversibleBlockHeightCalculator` [5](#0-4) , `ProcessNextRound` simply accepts the provided LIB values.

The next round generation in [6](#0-5)  copies LIB information from the current round (lines 69-70), perpetuating any corruption.

### Impact Explanation

**Consensus State Corruption**: A malicious extra block producer can permanently corrupt the consensus contract's view of the Last Irreversible Block height by submitting a `NextRound` block with artificially decreased `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` values.

**Block Production Disruption**: The corrupted LIB information is used in [7](#0-6)  where `currentRound.ConfirmedIrreversibleBlockHeight` (line 26) and `currentRound.ConfirmedIrreversibleBlockRoundNumber` (line 25) determine blockchain mining status. A decreased LIB can trigger false `Abnormal` or `Severe` status detection:
- In Abnormal status (lines 42-55): Maximum blocks count is artificially reduced based on incorrect gap between current round and LIB round
- In Severe status (lines 58-67): Maximum blocks count drops to 1 and `IrreversibleBlockHeightUnacceptable` events are fired, severely limiting block production

**Invariant Violation**: This breaks the critical blockchain invariant that LIB height must be monotonically increasing. Once decreased, the corrupted LIB propagates to all subsequent rounds via [8](#0-7) , creating persistent inconsistency between the consensus contract's LIB view and the actual chain's irreversible block height.

**Protocol-Wide Impact**: All honest miners and users are affected as the consensus mechanism itself is compromised, potentially causing network-wide disruption of block production and cross-chain operations that rely on accurate LIB information.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be an extra block producer, which is a legitimate miner role within the consensus protocol. Extra block producers are responsible for round transitions and are determined by consensus algorithm rotation [9](#0-8) .

**Attack Complexity**: LOW. The attack is straightforward:
1. When designated as extra block producer, generate legitimate `NextRound` consensus data via [10](#0-9) 
2. Modify the `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields in the generated `NextRoundInput` to lower values
3. Submit the modified block

**Feasibility**: HIGH. The consensus extra data is generated locally by the block producer. While the `RoundTerminateValidationProvider` [11](#0-10)  validates round number and InValues for NextRound, it does NOT validate LIB information. There is no cryptographic commitment or hash validation that would prevent modification of the LIB fields before block submission.

**Economic Rationality**: The attacker could disrupt the network for competitive advantage or as part of a coordinated attack. The cost is minimal (just being a rotating miner), while the impact is severe and persistent.

**Detection**: The attack may go undetected initially since the decreased LIB values are stored in consensus state without triggering immediate failures. The kernel's LIB won't decrease due to the check in [12](#0-11) , but this creates a dangerous divergence between consensus contract state and chain state.

### Recommendation

**Immediate Fix**: Add `LibInformationValidationProvider` to the validation pipeline for `NextRound` behavior in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextRound:
    // Is sender's order of next round correct?
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    // Add LIB validation to prevent decreased LIB information
    validationProviders.Add(new LibInformationValidationProvider());
    break;
```

**Additional Validation**: Consider adding explicit LIB validation in `ProcessNextRound` before storing the round:
- Verify that `nextRound.ConfirmedIrreversibleBlockHeight >= currentRound.ConfirmedIrreversibleBlockHeight`
- Verify that `nextRound.ConfirmedIrreversibleBlockRoundNumber >= currentRound.ConfirmedIrreversibleBlockRoundNumber`
- Verify that implied irreversible block heights in miner information do not decrease

**Test Cases**: Add regression tests that:
1. Attempt to submit a `NextRound` block with decreased `ConfirmedIrreversibleBlockHeight` and verify rejection
2. Attempt to submit a `NextRound` block with decreased `ConfirmedIrreversibleBlockRoundNumber` and verify rejection
3. Verify that LIB information properly propagates across round transitions
4. Test that both `UpdateValue` and `NextRound` behaviors enforce the same LIB monotonicity invariant

### Proof of Concept

**Initial State**:
- Current round R with `ConfirmedIrreversibleBlockHeight = 1000` and `ConfirmedIrreversibleBlockRoundNumber = 10`
- Attacker is designated as extra block producer for round transition

**Attack Steps**:
1. Attacker calls `GetConsensusCommand` and `GetConsensusExtraData` to generate legitimate NextRound consensus data
2. Attacker intercepts the generated `NextRoundInput` and modifies:
   - `ConfirmedIrreversibleBlockHeight = 900` (decreased from 1000)
   - `ConfirmedIrreversibleBlockRoundNumber = 9` (decreased from 10)
3. Attacker produces block with modified `NextRoundInput`
4. Block passes validation since `LibInformationValidationProvider` is not in the pipeline for `NextRound`
5. `ProcessNextRound` stores the malicious round via `AddRoundInformation`

**Expected Result**: Validation should fail with "Incorrect lib information" error from `LibInformationValidationProvider`

**Actual Result**: Validation passes, and round R+1 is stored with `ConfirmedIrreversibleBlockHeight = 900`, corrupting the consensus state

**Success Condition**: Query `GetCurrentRoundInformation` and observe that the stored round contains the decreased LIB values, violating the monotonicity invariant and causing subsequent blocks to use the incorrect baseline for mining status calculations in `GetMaximumBlocksCount`.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-79)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");

        // If R_LIB + 2 < R < R_LIB + CB1, CB goes to Min(T(L2 * (CB1 - (R - R_LIB)) / A), CB0), while CT stays same as before.
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }

        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }

        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;

        return AEDPoSContractConstants.MaximumTinyBlocksCount;
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L60-61)
```csharp
            if (chain.LastIrreversibleBlockHeight > irreversibleBlockFound.IrreversibleBlockHeight)
                return;
```
