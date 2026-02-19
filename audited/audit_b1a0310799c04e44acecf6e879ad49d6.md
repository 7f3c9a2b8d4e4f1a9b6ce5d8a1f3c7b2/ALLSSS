# Audit Report

## Title
Missing Time Validation Allows Premature Round Transition in NextRound Consensus Behavior

## Summary
The AEDPoS consensus contract fails to validate that the current block time has reached the extra block mining time before allowing round termination. This permits a malicious extra block producer to prematurely end the current round, violating the fundamental consensus timing invariant and denying other miners their designated time slots.

## Finding Description

The vulnerability exists in the NextRound consensus flow where timing validation is completely absent.

**Entry Point**: The `GetConsensusExtraDataForNextRound` method calls `GenerateNextRoundInformation` without any time validation [1](#0-0) 

**Missing Validation Layer 1**: The contract wrapper method does not validate timing [2](#0-1) 

**Missing Validation Layer 2**: The core round generation method accepts the timestamp but never validates it [3](#0-2) 

**Round Duration Invariant**: The system explicitly documents that round duration must be `MiningInterval * MinersCount + MiningInterval` [4](#0-3) 

**Extra Block Mining Time Definition**: The proper termination time is defined as the last miner's expected time plus one interval [5](#0-4) 

**Insufficient TimeSlotValidationProvider**: Only validates the structural correctness of the NEW round, not whether current time justifies ending the PREVIOUS round [6](#0-5) 

**Insufficient RoundTerminateValidationProvider**: Only checks round number increment and InValue nullness, with no timing constraint [7](#0-6) 

**Validation Orchestration Gap**: The validation flow for NextRound behavior adds multiple providers but none validate timing [8](#0-7) 

**Mining Permission Check Insufficient**: The permission validator only checks miner list membership, not timing [9](#0-8) 

## Impact Explanation

**Consensus Integrity Violation**: The system has a documented invariant that rounds last `MiningInterval * (MinersCount + 1)`. Premature termination directly breaks this invariant, compromising the fundamental timing guarantees of the consensus mechanism.

**Fairness Impact**: Miners who have not yet reached their time slots in the current round will lose their mining opportunity entirely. This creates an unfair advantage for the attacker and disadvantages honest miners who were waiting for their designated time.

**Block Production Skew**: The extra block producer can maximize their own block production by repeatedly triggering early round transitions when they rotate into the extra block producer role, systematically excluding slower or later-scheduled miners.

**Random Number Security**: The AEDPoS consensus uses miner signatures to generate random numbers. If the round terminates before all miners have contributed their signatures, the randomness pool may be reduced, potentially affecting applications that depend on consensus-provided randomness.

**Cascading Schedule Disruption**: Premature round transitions disrupt the carefully calculated mining schedule for subsequent rounds, as the next round's timing is based on when the previous round actually ended rather than when it should have ended.

## Likelihood Explanation

**Attacker Prerequisites**: The attacker must be a legitimate miner and must wait until they are designated as the extra block producer for the current round. The extra block producer is determined algorithmically based on the first miner's signature [10](#0-9) , so this role rotates among all miners over time.

**Attack Simplicity**: Once the attacker is the extra block producer, the attack requires only producing a NextRound block before the proper time. The attacker generates valid next round information and submits it—no complex state manipulation or race conditions are required.

**Validation Bypass**: All existing validation checks will pass because they only verify structural correctness (round number increments by 1, InValues are null, mining order is correct) but never check timing. The malicious block appears completely valid to all validators.

**Detection Difficulty**: The premature round transition appears as a normal consensus operation. There are no automatic alerts or validation failures. Other nodes will accept and execute the early round transition as valid.

**Exploitation Frequency**: Every miner will eventually rotate into the extra block producer role. A persistent attacker can exploit this vulnerability every time they become the extra block producer, creating repeated fairness violations.

## Recommendation

Add explicit timing validation in the `RoundTerminateValidationProvider` for NextRound behavior:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // NEW: Validate timing - current time must be >= extra block mining time
    var extraBlockMiningTime = validationContext.BaseRound.GetExtraBlockMiningTime();
    if (validationContext.CurrentBlockTime < extraBlockMiningTime)
    {
        return new ValidationResult 
        { 
            Message = $"Cannot terminate round before extra block mining time. Current: {validationContext.CurrentBlockTime}, Required: {extraBlockMiningTime}" 
        };
    }
    
    // Existing validations
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

Additionally, the `ConsensusValidationContext` should include `CurrentBlockTime` if not already present to support this validation.

## Proof of Concept

A complete PoC would require:
1. Setting up a test consensus environment with multiple miners
2. Designating a test miner as the extra block producer
3. Having that miner produce a NextRound block before `GetExtraBlockMiningTime()` is reached
4. Verifying that validation passes and the round terminates prematurely
5. Confirming that miners who hadn't yet mined lose their time slots

The vulnerability is evident from code inspection: no validator in the consensus validation pipeline checks `Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime()` for NextRound behavior, making the premature termination attack possible.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L176-176)
```csharp
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L285-346)
```csharp
    private void GenerateNextRoundInformation(Round currentRound, Timestamp currentBlockTime, out Round nextRound)
    {
        TryToGetPreviousRoundInformation(out var previousRound);
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();
        var isMinerListChanged = false;
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
        }

        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L61-72)
```csharp
    ///     In current AElf Consensus design, each miner produce his block in one time slot, then the extra block producer
    ///     produce a block to terminate current round and confirm the mining order of next round.
    ///     So totally, the time of one round is:
    ///     MiningInterval * MinersCount + MiningInterval.
    /// </summary>
    /// <param name="miningInterval"></param>
    /// <returns></returns>
    public int TotalMilliseconds(int miningInterval = 0)
    {
        if (miningInterval == 0) miningInterval = GetMiningInterval();

        return RealTimeMinersInformation.Count * miningInterval + miningInterval;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```
