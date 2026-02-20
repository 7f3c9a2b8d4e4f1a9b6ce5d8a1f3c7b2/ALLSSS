# Audit Report

## Title
Consensus Behavior Substitution Allows Miners to Bypass Cryptographic Value Publication

## Summary
A miner producing their first block in a round can incorrectly use `TinyBlock` behavior instead of the required `UpdateValue` behavior, avoiding publication of essential consensus values (OutValue, Signature, PreviousInValue). This breaks the consensus randomness mechanism and creates inconsistent state where miners produce blocks without contributing to the cryptographic chain.

## Finding Description

The AEDPoS consensus system defines two distinct block production behaviors with different cryptographic requirements. Both `UpdateValue` and `UpdateTinyBlockInformation` are public methods callable by any miner. [1](#0-0) 

The vulnerability exists because the validation logic does not enforce that miners with `OutValue == null` must use `UpdateValue` behavior. During validation, the system recovers round state based on the **claimed** behavior in the header information without verifying the behavior matches the miner's actual state. [2](#0-1) 

When a miner submits TinyBlock behavior, the `UpdateValueValidationProvider` is never added to the validation pipeline. The validation providers are added conditionally based on the claimed behavior, and UpdateValueValidationProvider is only included for UpdateValue behavior. [3](#0-2) 

The `RecoverFromTinyBlock` function only copies `ActualMiningTimes` and `ImpliedIrreversibleBlockHeight`, completely ignoring OutValue, Signature, and PreviousInValue that are essential consensus fields. [4](#0-3) 

During processing, `ProcessTinyBlock` only updates block production counters (`ProducedBlocks` and `ProducedTinyBlocks`) without setting any consensus cryptographic values. [5](#0-4)  In contrast, `ProcessUpdateValue` properly sets OutValue, Signature, and SupposedOrderOfNextRound. [6](#0-5) 

## Impact Explanation

This vulnerability creates a critical consensus integrity breach with multiple cascading effects:

**State Inconsistency**: Miners can produce blocks (incrementing `ProducedBlocks` counter) while their OutValue, Signature, and PreviousInValue remain null, violating the fundamental invariant that block production requires cryptographic commitment.

**Next Round Misclassification**: During next round generation, the `GetMinedMiners()` function identifies miners by checking `SupposedOrderOfNextRound != 0`. [7](#0-6)  Miners who exploited this vulnerability have `SupposedOrderOfNextRound == 0` (since ProcessTinyBlock doesn't set it), so they are incorrectly included in `GetNotMinedMiners()` [8](#0-7)  and receive a `MissedTimeSlots` penalty despite having produced blocks. [9](#0-8) 

**Randomness Degradation**: The extra block producer selection mechanism relies on signature availability to calculate randomized mining order. [10](#0-9)  If multiple miners exploit this vulnerability, the system may have no signatures to work with, defaulting to a predictable order 1 assignment, severely compromising consensus randomness.

**Cryptographic Chain Break**: The consensus protocol's commit-reveal scheme for randomness generation depends on the continuous chain of OutValue/Signature pairs. Missing values create gaps in this chain, preventing proper randomness contribution and potentially enabling manipulation of future block producer ordering.

## Likelihood Explanation

**Attacker Prerequisites**: The attacker must be a legitimate consensus miner with active block production rights. This is a reasonable assumption as the vulnerability targets miner behavior, not external attackers.

**Execution Simplicity**: Both methods are public and callable by any miner. The attack requires only sending a TinyBlock transaction instead of UpdateValue when OutValue is null - no complex state manipulation or timing attacks needed.

**Detection vs. Prevention**: While the attack is observable on-chain (miners with blocks produced but null consensus values), there is no preventive validation. The common validators (MiningPermission, TimeSlot, ContinuousBlocks) do not check whether the claimed behavior matches the miner's state. [11](#0-10) [12](#0-11) 

**Realistic Threat Scenario**: A malicious or compromised miner could exploit this during their first block in each round. More significantly, a coordinated attack by multiple miners could systematically degrade consensus randomness, making block producer ordering predictable or manipulable.

## Recommendation

Add validation in `ValidateBeforeExecution` to enforce behavior correctness based on miner state:

```csharp
// After line 50 in AEDPoSContract_Validation.cs, add:
if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
{
    var minerInRound = baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()];
    if (minerInRound.OutValue == null)
    {
        return new ValidationResult 
        { 
            Success = false, 
            Message = "TinyBlock behavior requires OutValue to be set. Use UpdateValue for first block." 
        };
    }
}
```

This ensures that miners with `OutValue == null` cannot use TinyBlock behavior and must properly publish their cryptographic commitment through UpdateValue.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanBypassCryptographicCommitmentWithTinyBlock()
{
    // Setup: Initialize first round with a miner
    await AEDPoSContract_FirstRound_BootMiner_Test();
    
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerPubkey = BootMinerKeyPair.PublicKey.ToHex();
    
    // Verify miner has OutValue == null (hasn't mined yet this round)
    currentRound.RealTimeMinersInformation[minerPubkey].OutValue.ShouldBeNull();
    
    // Attack: Use TinyBlock instead of UpdateValue for first block
    BlockTimeProvider.SetBlockTime(currentRound.RealTimeMinersInformation[minerPubkey].ExpectedMiningTime);
    
    var tinyBlockInput = new TinyBlockInput
    {
        RoundId = currentRound.RoundId,
        ActualMiningTime = BlockTimeProvider.GetBlockTime(),
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(BootMinerKeyPair))
    };
    
    // Transaction succeeds despite being the first block
    var result = await AEDPoSContractStub.UpdateTinyBlockInformation.SendAsync(tinyBlockInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify state inconsistency
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo = updatedRound.RealTimeMinersInformation[minerPubkey];
    
    // Miner produced blocks but OutValue/Signature remain null
    minerInfo.ProducedBlocks.ShouldBeGreaterThan(0);
    minerInfo.OutValue.ShouldBeNull();
    minerInfo.Signature.ShouldBeNull();
    minerInfo.SupposedOrderOfNextRound.ShouldBe(0);
    
    // Next round will misclassify this miner as not mined
    var minedMiners = updatedRound.GetMinedMiners();
    minedMiners.ShouldNotContain(m => m.Pubkey == minerPubkey);
}
```

## Notes

The intended behavior determination logic exists in `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` [13](#0-12) , which correctly returns UpdateValue when OutValue is null. However, this is only used for command generation (client-side), not for validation enforcement (contract-side). The contract accepts whatever behavior the miner claims without verifying it matches their state, creating the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-112)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }

    #endregion

    #region UpdateTinyBlockInformation

    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-83)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-47)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-56)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L131-135)
```csharp
    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L39-83)
```csharp
        public AElfConsensusBehaviour GetConsensusBehaviour()
        {
            // The most simple situation: provided pubkey isn't a miner.
            // Already checked in GetConsensusCommand.
//                if (!CurrentRound.IsInMinerList(_pubkey))
//                {
//                    return AElfConsensusBehaviour.Nothing;
//                }

            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
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
        }
```
