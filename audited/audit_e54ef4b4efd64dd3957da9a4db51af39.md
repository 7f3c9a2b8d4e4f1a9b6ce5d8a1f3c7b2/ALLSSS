# Audit Report

## Title
Miner Can Bypass Consensus Data Submission by Submitting TinyBlock Instead of UpdateValue

## Summary
A malicious miner can avoid providing critical consensus data (OutValue, Signature, PreviousInValue) by submitting TinyBlock behavior when UpdateValue behavior is expected. The validation logic does not verify that the submitted behavior type matches the miner's state in the current round, allowing miners who have not yet mined (OutValue == null) to bypass UpdateValue submission requirements.

## Finding Description

The AEDPoS consensus system determines expected behavior based on miner state. When a miner's OutValue is null (hasn't mined in current round) and their time slot hasn't passed, the system expects UpdateValue behavior. [1](#0-0) 

The consensus system uses different Round structures for different behaviors. GetUpdateValueRound includes consensus-critical fields (OutValue, Signature, PreviousInValue), [2](#0-1)  while GetTinyBlockRound only includes mining timestamps and block counts. [3](#0-2) 

However, the validation in ValidateBeforeExecution does not check whether the submitted behavior matches what the miner's state requires. The validation applies different validators based on the submitted behavior type, not the expected behavior. [4](#0-3) 

For TinyBlock behavior, only three validators are applied: MiningPermissionValidationProvider, TimeSlotValidationProvider, and ContinuousBlocksValidationProvider. [5](#0-4) 

None of these validators check whether the miner's OutValue is null in the base round. MiningPermissionValidationProvider only verifies the sender is in the miner list, [6](#0-5)  TimeSlotValidationProvider only checks time slot compliance, [7](#0-6)  and ContinuousBlocksValidationProvider only checks continuous block limits. [8](#0-7) 

The recovery process for TinyBlock only extracts ActualMiningTimes and ImpliedIrreversibleBlockHeight, ignoring consensus-critical fields, [9](#0-8)  while RecoverFromUpdateValue updates OutValue, Signature, and PreviousInValue. [10](#0-9) 

The processing functions show the critical difference. ProcessUpdateValue updates consensus data and calculates LIB height, [11](#0-10)  while ProcessTinyBlock only updates mining counters. [12](#0-11) 

At round transition, SupplyCurrentRoundInformation fills in fake/derived values for miners who didn't provide real data. For miners with OutValue == null, it generates fake previousInValue and signature using HashHelper.ComputeFrom(miner). [13](#0-12) 

## Impact Explanation

**Consensus Integrity Compromise:** This vulnerability breaks fundamental AEDPoS consensus guarantees:

1. **Random Number Generation Broken:** OutValue and Signature are used for generating random numbers and preventing predictability. Without authentic values from all miners, the randomness mechanism is compromised.

2. **Secret Sharing Disrupted:** PreviousInValue is required for the secret sharing protocol. Missing values prevent proper verification by other miners, breaking the distributed trust model.

3. **LIB Height Stalled:** The Last Irreversible Block height calculation only occurs during UpdateValue processing. Bypassing this prevents LIB advancement, affecting finality guarantees and potentially stalling the chain's confirmation mechanism.

4. **Fake Value Injection:** The system compensates for missing consensus data by generating deterministic fake values, which can be predicted by attackers and used to manipulate consensus outcomes.

Multiple colluding miners could systematically degrade consensus integrity while still receiving mining rewards, undermining the security assumptions of the entire blockchain.

## Likelihood Explanation

**High Likelihood:** This vulnerability is easily exploitable:

1. **Reachable Entry Point:** Any miner can submit consensus data through normal block production. The behavior type is self-declared in the consensus header.

2. **No Special Permissions Required:** The attacker only needs to be in the validator set, which is a normal operational requirement.

3. **Simple Execution:** The attacker submits TinyBlock behavior when they should submit UpdateValue. All existing validators pass.

4. **Low Detection Risk:** The submitted data appears valid (correct time slot, valid miner, within block limits). Only checking the base round's OutValue state could detect this, and no validator performs this check.

5. **Rational Attack Vector:** An attacker could selectively withhold consensus data to manipulate random number generation outcomes while still earning mining rewards.

## Recommendation

Add a validator that checks whether the submitted behavior matches the expected behavior based on the miner's state. Specifically:

1. Create a new `BehaviorMatchValidationProvider` that:
   - Retrieves the miner's OutValue from the base round
   - If OutValue is null and time slot hasn't passed, expects UpdateValue behavior
   - If OutValue is not null and within time slot/block limits, expects TinyBlock behavior
   - Rejects if submitted behavior doesn't match expected behavior

2. Add this validator to the list of basic validators applied to all behaviors in `ValidateBeforeExecution`:

```csharp
var validationProviders = new List<IHeaderInformationValidationProvider>
{
    new MiningPermissionValidationProvider(),
    new TimeSlotValidationProvider(),
    new ContinuousBlocksValidationProvider(),
    new BehaviorMatchValidationProvider() // Add this new validator
};
```

This ensures miners cannot bypass consensus data submission requirements by misrepresenting their intended behavior.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a round with a miner who has OutValue == null (hasn't mined yet)
2. Have that miner submit TinyBlock behavior instead of UpdateValue
3. Verify that validation passes (it should but shouldn't)
4. Verify that only mining counters are updated, not consensus data (OutValue, Signature, PreviousInValue remain null)
5. Advance to next round and verify fake values are injected via SupplyCurrentRoundInformation

The test would show that a miner can produce blocks and receive rewards without providing authentic consensus data, breaking the fundamental security assumptions of AEDPoS consensus.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L11-56)
```csharp
    public Round GetUpdateValueRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = pubkey,
                    OutValue = minerInRound.OutValue,
                    Signature = minerInRound.Signature,
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    PreviousInValue = minerInRound.PreviousInValue,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
                    Order = minerInRound.Order,
                    IsExtraBlockProducer = minerInRound.IsExtraBlockProducer
                }
            }
        };
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
            }

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-82)
```csharp
    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = minerInRound.Pubkey,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight
                }
            }
        };

        foreach (var otherPubkey in RealTimeMinersInformation.Keys.Except(new List<string> { pubkey }))
            round.RealTimeMinersInformation.Add(otherPubkey, new MinerInRound());

        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-221)
```csharp
    private void SupplyCurrentRoundInformation()
    {
        var currentRound = GetCurrentRoundInformation(new Empty());
        Context.LogDebug(() => $"Before supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
        var notMinedMiners = currentRound.RealTimeMinersInformation.Values.Where(m => m.OutValue == null).ToList();
        if (!notMinedMiners.Any()) return;
        TryToGetPreviousRoundInformation(out var previousRound);
        foreach (var miner in notMinedMiners)
        {
            Context.LogDebug(() => $"Miner pubkey {miner.Pubkey}");

            Hash previousInValue = null;
            Hash signature = null;

            // Normal situation: previous round information exists and contains this miner.
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
                }
            }

            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
            }

            // Fill this two fields at last.
            miner.InValue = previousInValue;
            miner.Signature = signature;

            currentRound.RealTimeMinersInformation[miner.Pubkey] = miner;
        }

        TryToUpdateRoundInformation(currentRound);
        Context.LogDebug(() => $"After supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
    }
```
