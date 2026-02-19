### Title
Miner Can Bypass Consensus Data Submission by Submitting TinyBlock Instead of UpdateValue

### Summary
A malicious miner can avoid providing critical consensus data (OutValue, Signature, PreviousInValue) by submitting TinyBlock behavior when UpdateValue behavior is expected. The validation logic does not verify that the submitted behavior type matches the miner's state in the current round, allowing miners who have not yet mined (OutValue == null) to bypass UpdateValue submission requirements.

### Finding Description

The consensus system uses different Round structures for different behaviors. `GetUpdateValueRound()` includes consensus-critical fields (OutValue, Signature, PreviousInValue), while `GetTinyBlockRound()` only includes mining timestamps and block counts. [1](#0-0) [2](#0-1) 

The behavior type is supposed to be determined by `GetConsensusBehaviour()` based on the miner's current state. When a miner's OutValue is null (hasn't mined in current round) and their time slot hasn't passed, the system expects UpdateValue behavior: [3](#0-2) [4](#0-3) 

However, the validation in `ValidateBeforeExecution` does not check whether the submitted behavior matches what the miner's state requires. When TinyBlock behavior is submitted, different validators are applied: [5](#0-4) 

The recovery process for TinyBlock only extracts ActualMiningTimes and ImpliedIrreversibleBlockHeight, ignoring consensus-critical fields: [6](#0-5) 

None of the validators applied to TinyBlock behavior (MiningPermissionValidationProvider, TimeSlotValidationProvider, ContinuousBlocksValidationProvider) check whether the miner's OutValue is null in the base round, which would indicate that UpdateValue should have been submitted instead.

The processing functions show the critical difference - ProcessUpdateValue updates consensus data and calculates LIB height: [7](#0-6) 

While ProcessTinyBlock only updates mining counters: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Compromise:** A malicious miner can produce blocks in their designated time slot without providing OutValue, Signature, or PreviousInValue, which are fundamental to the AEDPoS consensus mechanism:

1. **Random Number Generation Broken:** OutValue and Signature are used for generating random numbers and preventing predictability. Without these, the randomness mechanism fails.

2. **Secret Sharing Disrupted:** PreviousInValue is required for the secret sharing protocol used in consensus. Missing values prevent proper verification by other miners.

3. **LIB Height Stalled:** The Last Irreversible Block height calculation only occurs during UpdateValue processing. Bypassing this prevents LIB advancement, affecting finality guarantees.

4. **Fake Value Injection:** At round transition, `SupplyCurrentRoundInformation()` fills in fake/derived values for miners who didn't provide real data: [9](#0-8) 

This allows attackers to receive mining rewards while corrupting the consensus mechanism that other honest miners depend on. Multiple colluding miners could systemically degrade consensus integrity.

### Likelihood Explanation

**High Likelihood:** This vulnerability is easily exploitable by any miner in the consensus set:

1. **Reachable Entry Point:** Any miner can call the consensus update functions through normal block production. The behavior type is self-declared in the consensus header information.

2. **No Special Permissions Required:** The attacker only needs to be a validator in the miner set, which is the normal operational requirement for consensus participation.

3. **Simple Execution:** The attacker simply submits TinyBlock behavior with a TinyBlock round structure when they should submit UpdateValue. The existing validation does not prevent this.

4. **Low Detection Risk:** The submitted data appears valid to all validators (correct time slot, valid miner, not too many blocks). Only by checking the base round's OutValue state could this be detected, and no validator performs this check.

5. **Rational Attack:** An attacker could selectively provide or withhold consensus data based on whether it's advantageous, manipulating random number generation while still receiving mining rewards.

### Recommendation

**Add Behavior Type Validation:** Implement a new validator that checks whether the submitted behavior type is appropriate for the miner's current state:

```csharp
public class BehaviourTypeValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var minerInBaseRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var behaviour = validationContext.ExtraData.Behaviour;
        
        // If OutValue is null, miner must submit UpdateValue, NextRound, or NextTerm (not TinyBlock)
        if (minerInBaseRound.OutValue == null && behaviour == AElfConsensusBehaviour.TinyBlock)
        {
            return new ValidationResult 
            { 
                Message = "Cannot submit TinyBlock when OutValue is null. UpdateValue required." 
            };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Add this validator to the basic provider list in ValidateBeforeExecution: [10](#0-9) 

**Test Cases:** Add tests verifying:
1. TinyBlock submission fails when OutValue is null
2. UpdateValue is required for first block in a miner's time slot
3. TinyBlock is only allowed after UpdateValue has been submitted
4. Round transitions handle all miners providing proper UpdateValue

### Proof of Concept

**Initial State:**
- Current round R, miner M is in the miner list
- Miner M's time slot is active (current time within M's expected mining time)
- Miner M has not mined in round R yet (OutValue == null in state)

**Attack Sequence:**

1. **Expected Behavior:** GetConsensusBehaviour() would return UpdateValue for miner M based on line 114 logic (OutValue == null && !timeSlotPassed)

2. **Attacker Action:** Miner M ignores this and creates consensus header with:
   - Behaviour = TinyBlock
   - Round = GetTinyBlockRound(M) (without OutValue, Signature, PreviousInValue)

3. **Validation Passes:**
   - ValidateBeforeExecution calls RecoverFromTinyBlock (only extracts ActualMiningTimes, ImpliedIrreversibleBlockHeight)
   - MiningPermissionValidationProvider passes (M is in miner list)
   - TimeSlotValidationProvider passes (time is valid, ActualMiningTimes.Count == 0 so returns true at line 42)
   - ContinuousBlocksValidationProvider passes (not too many continuous blocks)
   - **No validator checks OutValue is null in baseRound**

4. **Processing Succeeds:**
   - ProcessTinyBlock executes, updating only ActualMiningTimes and block counts
   - OutValue, Signature, PreviousInValue remain null

**Expected Result:** Validation should reject TinyBlock submission when OutValue is null, requiring UpdateValue instead.

**Actual Result:** Validation passes, miner produces block without providing consensus data, OutValue remains null, consensus mechanism compromised.

**Success Condition:** After block execution, query `GetCurrentRoundInformation()` and verify miner M's OutValue is still null despite having ActualMiningTimes recorded, confirming the bypass.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-115)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-220)
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
```
