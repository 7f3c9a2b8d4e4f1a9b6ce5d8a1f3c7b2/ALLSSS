# Audit Report

## Title
Consensus Behavior Substitution Allows Miners to Bypass Cryptographic Value Publication

## Summary
The AEDPoS consensus validation lacks enforcement of correct behavior type selection based on miner state. Miners producing their first block in a round can use `TinyBlock` behavior instead of the required `UpdateValue` behavior, bypassing publication of cryptographic consensus values (OutValue, Signature, PreviousInValue). This breaks the consensus randomness mechanism and creates state inconsistency where miners produce blocks without contributing to the cryptographic chain.

## Finding Description

The consensus system defines two distinct block production behaviors:
- `UpdateValue`: Required for first block in round, must include OutValue, Signature, PreviousInValue
- `TinyBlock`: For subsequent blocks within time slot, excludes these cryptographic fields

**Behavior Determination Logic**: The system correctly determines that miners with `OutValue == null` should use `UpdateValue` behavior [1](#0-0) 

**Missing Validation**: However, the validation logic fails to enforce this requirement. The validator only recovers data based on the *claimed* behavior without verifying the behavior itself matches the miner's state [2](#0-1) 

**Validation Provider Bypass**: For `TinyBlock` behavior, `UpdateValueValidationProvider` is never added to the validation pipeline, allowing miners to avoid OutValue/Signature validation entirely [3](#0-2) 

**Incomplete Recovery**: The `RecoverFromTinyBlock` function only copies `ActualMiningTimes` and `ImpliedIrreversibleBlockHeight`, completely ignoring OutValue, Signature, and PreviousInValue even if present in the input [4](#0-3) 

In contrast, `RecoverFromUpdateValue` properly recovers all cryptographic fields [5](#0-4) 

**Processing Divergence**: During consensus information processing:
- `ProcessUpdateValue` sets OutValue, Signature, and SupposedOrderOfNextRound [6](#0-5) 
- `ProcessTinyBlock` only updates block counts without setting any consensus cryptographic values [7](#0-6) 

**State Inconsistency Result**: Since `SupposedOrderOfNextRound` remains at its default value of 0, the next round generation logic incorrectly classifies the miner as non-mining despite block production:
- Miners with `SupposedOrderOfNextRound == 0` are considered non-mining [8](#0-7) 
- These miners have their `MissedTimeSlots` incremented even though they produced blocks [9](#0-8) 

**Extra Block Producer Degradation**: The extra block producer selection relies on signature availability, defaulting to order 1 when no signatures exist [10](#0-9) 

## Impact Explanation

**Consensus Integrity Breach**: This vulnerability breaks fundamental AEDPoS security guarantees:

1. **Cryptographic Chain Broken**: The commit-reveal scheme requires all miners to publish OutValue (commitment) and Signature. Missing values prevent proper randomness contribution and break the cryptographic chain that secures consensus ordering.

2. **State Inconsistency**: The protocol enters an inconsistent state where:
   - `ProducedBlocks` counter increments (miner produced blocks)
   - `OutValue`, `Signature`, `PreviousInValue` remain null (no consensus contribution)
   - `SupposedOrderOfNextRound` remains 0 (classified as non-mining)
   - `MissedTimeSlots` increments (penalty applied incorrectly)

3. **Consensus Randomness Degradation**: If multiple miners exploit this:
   - Signature-based mining order determination fails
   - Extra block producer selection becomes predictable
   - Protocol reverts to deterministic ordering (order 1 default)
   - Consensus security model collapses

4. **Network-Wide Impact**: All participants suffer from compromised consensus integrity and potentially manipulable block producer ordering.

The impact extends beyond individual miner self-harm to protocol-level consensus security degradation.

## Likelihood Explanation

**Attacker Requirements**:
- Must be a legitimate consensus miner in the active miner set
- Must be within their assigned time slot
- Requires ability to construct and send TinyBlock transaction

**Attack Complexity**: Low - simply send `TinyBlock` input instead of `UpdateValue` input when producing first block in round. No complex state manipulation or timing attacks required.

**Feasibility**: 
- Validation providers check mining permission, time slot, and continuous blocks [11](#0-10) 
- None verify behavior type correctness for miner state
- Attack execution is straightforward for any miner

**Detection**: Observable on-chain through missing OutValue/Signature fields in round state for miners with non-zero ProducedBlocks.

**Economic Considerations**: 
- Individual miner suffers penalty (MissedTimeSlots, next round exclusion)
- More viable as coordinated griefing attack by multiple miners
- Can manipulate consensus ordering if enough participants collude

**Probability**: Medium - requires miner role (limited access) but trivial execution once obtained.

## Recommendation

Add validation to enforce correct behavior type based on miner state in `ValidateBeforeExecution`:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    // ... existing code ...
    
    // Add behavior type validation
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
    
    if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
    {
        baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
        
        // Validate that TinyBlock is only used after UpdateValue
        var minerInRound = baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()];
        if (minerInRound.OutValue == null)
        {
            return new ValidationResult 
            { 
                Success = false, 
                Message = "TinyBlock behavior requires prior UpdateValue in current round." 
            };
        }
    }
    
    // ... rest of validation ...
}
```

This ensures miners cannot use `TinyBlock` behavior when `OutValue == null`, enforcing the required `UpdateValue` behavior for first block in round.

## Proof of Concept

A proof of concept would require:
1. Setting up an AEDPoS consensus test environment with multiple miners
2. Miner produces first block in round (OutValue == null)
3. Miner sends `TinyBlockInput` transaction instead of `UpdateValueInput`
4. Verification that validation passes and block is produced
5. Verification that OutValue/Signature remain null in round state
6. Verification that next round generation treats miner as non-mining (SupposedOrderOfNextRound == 0)
7. Verification that MissedTimeSlots increments despite block production

The attack demonstrates that the protocol accepts incorrect behavior type, resulting in state inconsistency and broken consensus randomness mechanism.

---

**Notes**: This vulnerability represents a protocol-level security gap where validation fails to enforce critical consensus invariants. While individual exploitation involves miner self-harm (penalties), the attack breaks consensus integrity and enables coordinated manipulation of block producer ordering, constituting a valid security issue beyond mere self-harm scenarios.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L49-114)
```csharp
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

        /// <summary>
        ///     If this miner come to a new round, normally, there are three possible behaviour:
        ///     UPDATE_VALUE (most common)
        ///     TINY_BLOCK (happens if this miner is mining blocks for extra block time slot of previous round)
        ///     NEXT_ROUND (only happens in first round)
        /// </summary>
        /// <returns></returns>
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;

            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;

            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
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

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

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

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L39-56)
```csharp
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
