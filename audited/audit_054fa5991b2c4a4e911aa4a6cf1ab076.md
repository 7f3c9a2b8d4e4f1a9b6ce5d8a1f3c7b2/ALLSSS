### Title
Missing Behavior Validation Allows Miners to Bypass Consensus Contribution via TinyBlock Abuse

### Summary
The `ValidateBeforeExecution` function lacks validation to ensure TinyBlock behavior is only used by miners who have already published their consensus values (`OutValue != null`) in the current round. A malicious miner can submit `TinyBlock` instead of `UpdateValue` for their first block in a round, bypassing `UpdateValueValidationProvider` and `LibInformationValidationProvider`, allowing them to collect block rewards without contributing cryptographic consensus data or Last Irreversible Block (LIB) calculations, degrading consensus security.

### Finding Description

The vulnerability exists in the validation logic that processes different consensus behaviors: [1](#0-0) 

**Root Cause:**
The switch statement at lines 77-92 only adds behavior-specific validators for `UpdateValue`, `NextRound`, and `NextTerm` behaviors. When `extraData.Behaviour` is `TinyBlock`, the switch statement has no matching case, so only the three basic validators (MiningPermission, TimeSlot, ContinuousBlocks) are applied.

**Missing Validation:**
According to the intended consensus logic, TinyBlock behavior should only be used when:
1. The miner has already published their `OutValue` in the current round (`OutValue != null`), OR
2. The miner is the extra block producer from the previous round mining before the current round starts [2](#0-1) 

However, no validator enforces this requirement. A miner with `OutValue == null` (who should use `UpdateValue`) can maliciously submit `TinyBlock` instead.

**Why Existing Protections Fail:**

The bypassed validators provide critical checks:

`UpdateValueValidationProvider` ensures consensus values are properly published: [3](#0-2) 

`LibInformationValidationProvider` prevents LIB regression: [4](#0-3) 

When TinyBlock is processed, it only updates counters without setting consensus values: [5](#0-4) 

The miner's `OutValue`, `Signature`, and `PreviousInValue` remain null, and no LIB calculation occurs (which only happens in `ProcessUpdateValue`): [6](#0-5) 

### Impact Explanation

**Consensus Integrity Degradation:**
When miners abuse TinyBlock to avoid publishing real consensus values, the system falls back to generating fake values at round termination: [7](#0-6) 

This substitutes cryptographically-secure VRF-based random values with deterministic fake values (`HashHelper.ComputeFrom(miner)`), compromising the randomness and security properties of the consensus mechanism.

**LIB Calculation Failure:**
The Last Irreversible Block height is only calculated and updated during `UpdateValue` processing. Miners bypassing this prevent LIB from advancing properly, which impacts:
- Cross-chain indexing and verification
- Finality guarantees for transactions
- Overall blockchain security model

**Reward Without Work:**
Malicious miners receive full block production rewards while avoiding their consensus obligations, creating an economic imbalance where honest miners bear the full cost of consensus security while dishonest miners profit without contribution.

**Cumulative Effect:**
If multiple miners exploit this simultaneously, the consensus mechanism degrades significantly with mostly fake values and stalled LIB progression, potentially rendering the blockchain unreliable.

### Likelihood Explanation

**Reachable Entry Point:**
The attack is trivially accessible via the public `UpdateTinyBlockInformation` method: [8](#0-7) 

**Feasible Preconditions:**
- Attacker must be a valid miner in the current round (legitimate miner status)
- Attacker's time slot must be active
- No additional privileges or state manipulation required

**Execution Practicality:**
Instead of calling `UpdateValue(UpdateValueInput)` for their first block in a round, the miner simply calls `UpdateTinyBlockInformation(TinyBlockInput)`. The basic validators will pass:
- `MiningPermissionValidationProvider`: Passes (miner is in list)
- `TimeSlotValidationProvider`: Passes (within time slot, `ActualMiningTimes` empty returns true)
- `ContinuousBlocksValidationProvider`: Passes (not producing continuous blocks)

**Economic Rationality:**
- **Cost**: Zero additional cost (just use different method)
- **Benefit**: Full block rewards without consensus work
- **Detection Risk**: Low - miner appears to be mining normally, only round termination reveals fake values
- **Punishment**: None - miner is not marked as evil since they produced blocks [9](#0-8) 

Evil miner detection only checks `MissedTimeSlots`, which doesn't increment for miners actively producing blocks via TinyBlock.

**Probability:** HIGH - The exploit is straightforward, undetectable during validation, and economically profitable with no penalties.

### Recommendation

**Add TinyBlock Behavior Validation:**

Add a new validator `TinyBlockBehaviourValidationProvider` to enforce that TinyBlock is only valid when:
1. The miner has already published `OutValue` in the current round, OR
2. The miner is the `ExtraBlockProducerOfPreviousRound` and current time is before round start time

Update the validation logic:

```csharp
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.TinyBlock:
        validationProviders.Add(new TinyBlockBehaviourValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        break;
}
```

**Implement TinyBlockBehaviourValidationProvider:**

```csharp
public class TinyBlockBehaviourValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var baseRound = validationContext.BaseRound;
        var pubkey = validationContext.SenderPubkey;
        var minerInRound = baseRound.RealTimeMinersInformation[pubkey];
        
        // TinyBlock is valid if OutValue is not null (already mined this round)
        if (minerInRound.OutValue != null)
            return new ValidationResult { Success = true };
        
        // OR if miner is extra block producer before round start
        if (baseRound.ExtraBlockProducerOfPreviousRound == pubkey &&
            validationContext.ExtraData.Round.RoundNumber == baseRound.RoundNumber)
            return new ValidationResult { Success = true };
        
        return new ValidationResult 
        { 
            Message = "TinyBlock behavior requires OutValue already published or extra block producer status." 
        };
    }
}
```

**Test Cases:**
1. Verify miner with `OutValue == null` (not extra block producer) cannot use TinyBlock
2. Verify miner with `OutValue != null` can use TinyBlock
3. Verify extra block producer before round start can use TinyBlock with `OutValue == null`
4. Verify proper error messages returned for invalid TinyBlock usage

### Proof of Concept

**Initial State:**
- Blockchain is running with multiple miners
- Current round number: N
- Attacker is a valid miner with pubkey "MaliciousMiner"
- Attacker's time slot in round N has arrived
- Attacker's `OutValue` is null (first block in round N)

**Attack Steps:**

1. **Normal Expected Behavior:**
   Attacker should call `UpdateValue(UpdateValueInput)` containing:
   - `OutValue` (hash of their in-value)
   - `Signature` (cryptographic signature)
   - `PreviousInValue` (from previous round)
   - `ImpliedIrreversibleBlockHeight`

2. **Malicious Actual Behavior:**
   Instead, attacker calls `UpdateTinyBlockInformation(TinyBlockInput)` containing:
   - `RoundId`: Current round ID
   - `ProducedBlocks`: 1
   - `ActualMiningTime`: Current timestamp
   - `RandomNumber`: Valid VRF proof

3. **Validation Result:**
   - `MiningPermissionValidationProvider`: PASS (attacker is valid miner)
   - `TimeSlotValidationProvider`: PASS (within time slot, `ActualMiningTimes.Count` is 0)
   - `ContinuousBlocksValidationProvider`: PASS (not continuous)
   - **UpdateValueValidationProvider**: NOT RUN (TinyBlock behavior)
   - **LibInformationValidationProvider**: NOT RUN (TinyBlock behavior)
   - **Result**: Validation succeeds

4. **Processing Result:**
   - `ProcessTinyBlock` executes
   - `ActualMiningTimes` updated: [current timestamp]
   - `ProducedBlocks` incremented: 0 → 1
   - `ProducedTinyBlocks` incremented: 0 → 1
   - `OutValue` remains: null
   - `Signature` remains: null
   - Round information saved to state

5. **Expected vs Actual Outcome:**
   - **Expected**: Attacker publishes cryptographic consensus values, contributes to LIB calculation, earns block reward
   - **Actual**: Attacker earns block reward, contributes nothing to consensus, `OutValue`/`Signature` remain null, no LIB update

6. **Round Termination:**
   When `NextRound` is called, `SupplyCurrentRoundInformation` detects `OutValue == null` and fills fake values, allowing consensus to continue but with compromised security.

**Success Condition:**
The attack succeeds if the attacker mines a block, receives rewards, but their `OutValue` remains null in the round state after their block is accepted and processed.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L39-114)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-33)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L108-112)
```csharp
    public override Empty UpdateTinyBlockInformation(TinyBlockInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```
