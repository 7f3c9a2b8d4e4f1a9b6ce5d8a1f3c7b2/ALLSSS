# Audit Report

## Title
Insufficient Time Slot Validation Allows Zero Intervals Between Miners in Subsequent Pairs

## Summary
The `CheckRoundTimeSlots()` validation function contains a boundary condition flaw that allows zero mining intervals between subsequent miner pairs to pass validation. A malicious extra block producer can inject a Round where multiple miners share identical `ExpectedMiningTime` values, violating the fundamental AEDPoS consensus invariant that each miner must have a distinct time slot.

## Finding Description

The vulnerability exists in the `CheckRoundTimeSlots()` method's validation logic for subsequent miner pairs. [1](#0-0) 

The function correctly validates that the first mining interval (between miners[0] and miners[1]) is positive at lines 43-47, but for subsequent pairs it only checks if the absolute difference from the base interval exceeds the base interval itself at line 53. When a subsequent `miningInterval = 0` (two miners with identical `ExpectedMiningTime`) and `baseMiningInterval = 1000ms`, the condition `Math.Abs(0 - 1000) > 1000` evaluates to `1000 > 1000` which is `false`, causing validation to incorrectly pass.

The validation is invoked by `TimeSlotValidationProvider` when processing new rounds during the NextRound behavior. [2](#0-1) 

The Round data being validated comes from the block producer's consensus extra data, accessed via `ConsensusValidationContext.ProvidedRound`. [3](#0-2) 

While honest nodes generate proper Round data via `GenerateNextRoundInformation`, [4](#0-3)  a malicious extra block producer can modify the `ExpectedMiningTime` values before including the Round in their block's consensus extra data. [5](#0-4) 

The `AElfConsensusHeaderInformation` structure contains no cryptographic signature protecting the Round data's integrity. [6](#0-5) 

Once the malicious Round passes validation, it is stored in state and becomes the active round information. [7](#0-6) 

## Impact Explanation

**Consensus Integrity Violation**: This vulnerability directly breaks the core AEDPoS invariant that each miner must have a unique, isolated time slot for block production. When multiple miners share identical `ExpectedMiningTime` values:

1. **Timing Conflicts**: Two or more miners simultaneously believe it is their turn to produce blocks, leading to competing blocks at the same height and potential chain forks
2. **Consensus Disruption**: Different nodes may accept different miners' blocks, causing state inconsistency and blockchain reliability degradation
3. **Schedule Corruption**: The malicious round persists in state, affecting all subsequent block production until the next round transition

All network participants are impacted - honest miners cannot produce blocks reliably, validators see inconsistent state, and overall chain liveness is compromised. The severity is Medium-High because while this requires the attacker to be the extra block producer, it fundamentally breaks consensus time slot isolation.

## Likelihood Explanation

**Attacker Requirements**: The attacker must be a current block producer and specifically the extra block producer who triggers the NextRound transition. The extra block producer role rotates deterministically among all miners [8](#0-7) , so any miner eventually gets this opportunity.

**Attack Feasibility**: The attack is practically executable:
- The extra block producer generates consensus extra data locally before submitting their block
- They can modify the Round's `ExpectedMiningTime` values (e.g., set miners[2].ExpectedMiningTime = miners[1].ExpectedMiningTime)
- No cryptographic signatures protect the Round structure's field-level integrity
- The boundary condition bug in `CheckRoundTimeSlots()` allows zero intervals to pass
- All nodes run identical validation logic via `ValidateBeforeExecution` [9](#0-8) , so the malicious round is universally accepted

The attack complexity is Low-Medium, requiring only modification of locally-generated Round data before block submission. Detection occurs when multiple miners attempt simultaneous block production, but by then the malicious round is already in state.

## Recommendation

Change the boundary condition check in `CheckRoundTimeSlots()` from strict inequality to inclusive inequality. The fix should be applied at line 53:

**Current code:**
```csharp
if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
```

**Fixed code:**
```csharp
if (Math.Abs(miningInterval - baseMiningInterval) >= baseMiningInterval)
```

This ensures that when `miningInterval = 0` and two miners have identical `ExpectedMiningTime` values, the validation will correctly fail since `Math.Abs(0 - 1000) >= 1000` evaluates to `true`.

Additionally, consider adding explicit validation that all `ExpectedMiningTime` values are unique across all miners in the round.

## Proof of Concept

```csharp
[Fact]
public void CheckRoundTimeSlots_ZeroInterval_ShouldFail()
{
    // Arrange: Create a round with 3 miners where miners[1] and miners[2] have identical ExpectedMiningTime
    var round = new Round
    {
        RoundNumber = 1,
        TermNumber = 1
    };
    
    var baseTime = TimestampHelper.GetUtcNow();
    
    // Add three miners with orders 1, 2, 3
    round.RealTimeMinersInformation["miner1"] = new MinerInRound
    {
        Pubkey = "miner1",
        Order = 1,
        ExpectedMiningTime = baseTime
    };
    
    round.RealTimeMinersInformation["miner2"] = new MinerInRound
    {
        Pubkey = "miner2",
        Order = 2,
        ExpectedMiningTime = baseTime.AddMilliseconds(1000) // 1000ms interval
    };
    
    round.RealTimeMinersInformation["miner3"] = new MinerInRound
    {
        Pubkey = "miner3",
        Order = 3,
        ExpectedMiningTime = baseTime.AddMilliseconds(1000) // SAME as miner2 - zero interval!
    };
    
    // Act: Call CheckRoundTimeSlots
    var result = round.CheckRoundTimeSlots();
    
    // Assert: This SHOULD fail but currently passes due to boundary condition bug
    // Expected: result.Success == false
    // Actual: result.Success == true (BUG!)
    Assert.False(result.Success); // This will fail, proving the vulnerability
}
```

## Notes

This vulnerability is particularly severe because:

1. **Universal Impact**: Once the malicious round is validated and stored, all nodes in the network use the corrupted schedule
2. **No Recovery Within Round**: The malicious round persists until the next round transition
3. **Simple Exploit**: Requires only local data modification by the extra block producer, no complex cryptographic attacks needed
4. **No Additional Validation**: Other validators (`NextRoundMiningOrderValidationProvider`, etc.) do not check for duplicate `ExpectedMiningTime` values

The fix is straightforward - changing `>` to `>=` in the boundary condition - but the impact of the unfixed vulnerability is significant for consensus stability.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-18)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
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

**File:** protobuf/aedpos_contract.proto (L303-310)
```text
message AElfConsensusHeaderInformation {
    // The sender public key.
    bytes sender_pubkey = 1;
    // The round information.
    Round round = 2;
    // The behaviour of consensus.
    AElfConsensusBehaviour behaviour = 3;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-104)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };

        // Skip the certain initial miner during first several rounds. (When other nodes haven't produce blocks yet.)
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
        }

        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };

        /* Ask several questions: */

        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

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

        var service = new HeaderInformationValidationService(validationProviders);

        Context.LogDebug(() => $"Validating behaviour: {extraData.Behaviour.ToString()}");

        var validationResult = service.ValidateInformation(validationContext);

        if (validationResult.Success == false)
            Context.LogDebug(() => $"Consensus Validation before execution failed : {validationResult.Message}");

        return validationResult;
    }
```
