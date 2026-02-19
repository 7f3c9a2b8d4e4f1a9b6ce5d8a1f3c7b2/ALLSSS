# Audit Report

## Title
Missing Validation Allows Miners to Spoof TinyBlock Behavior and Bypass Consensus Value Submission

## Summary
The AEDPoS consensus contract fails to validate that a miner's claimed consensus behavior matches their actual state requirements. This allows malicious miners to claim `TinyBlock` behavior when they should use `UpdateValue` behavior, bypassing mandatory OutValue and Signature submission, thereby degrading consensus randomness and LIB calculation mechanisms.

## Finding Description

The vulnerability exists in the consensus validation flow where miners can specify their desired behavior without verification that this choice is appropriate for their current state.

When producing a block, miners provide trigger information that includes a `Behaviour` field. The contract processes this based on the claimed behavior [1](#0-0) , but never validates whether this claimed behavior matches what `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` would determine based on the miner's state [2](#0-1) .

The validation in `ValidateBeforeExecution` applies behavior-specific validators only for `UpdateValue`, `NextRound`, and `NextTerm` behaviors, but has **no case for TinyBlock** [3](#0-2) . This means TinyBlock claims only undergo basic validation (mining permission, time slot, continuous blocks) without verifying whether the miner's state actually permits TinyBlock usage.

When a miner uses TinyBlock, `ProcessTinyBlock` only updates `ActualMiningTimes` and block counts without requiring or validating OutValue and Signature [4](#0-3) . In contrast, `ProcessUpdateValue` requires OutValue, Signature, performs secret sharing, and triggers LIB calculation [5](#0-4) .

Post-execution validation cannot detect this misbehavior because `GetCheckableRound` explicitly excludes `ActualMiningTimes` from the round hash [6](#0-5) , meaning differences in this field won't trigger validation failures [7](#0-6) .

The system tolerates missing OutValues by auto-supplying fake values in `SupplyCurrentRoundInformation` [8](#0-7) , but this is intended as a fallback for failures, not for intentional malicious behavior.

## Impact Explanation

This vulnerability degrades critical consensus security properties:

1. **Consensus Randomness Degradation**: AEDPoS relies on miners' OutValue and Signature for randomness generation. When miners bypass this requirement, randomness quality degrades and becomes dependent on fewer honest participants. Multiple miners exploiting this significantly compromises the randomness beacon.

2. **LIB Calculation Bypass**: UpdateValue behavior triggers Last Irreversible Block height calculation. By using TinyBlock instead, miners prevent LIB updates during their blocks, potentially delaying chain finality.

3. **Reward Without Contribution**: Miners receive block production rewards and credit without fulfilling their cryptographic consensus obligations (OutValue/Signature computation).

4. **Secret Sharing Bypass**: UpdateValue performs secret sharing for consensus security. TinyBlock skips this entirely.

The severity is **Medium** because while it doesn't directly steal funds, it compromises fundamental consensus invariants. Multiple colluding miners could severely degrade consensus security.

## Likelihood Explanation

**Attack Feasibility**: High - The attack requires only:
- Being an active miner in the consensus set
- Providing `TinyBlock` in trigger information instead of following `GetConsensusCommand` guidance
- No complex timing or state manipulation needed

**Preconditions**: Requires miner-level access, which is realistic in a DPoS threat model where miner compromise or malicious behavior is a known concern.

**Detection Difficulty**: The attack is hard to detect because:
- All validation checks pass (no TinyBlock-specific validator exists)
- Round hash validation succeeds (ActualMiningTimes excluded from hash)
- System auto-supplies missing values, so rounds complete normally
- Only post-analysis of consensus data quality would reveal the issue

**Economic Motivation**: Rational miners might exploit this to reduce computational overhead while maintaining rewards, or to degrade consensus quality for strategic advantage in elections or randomness-dependent operations.

The likelihood is assessed as **Medium** - requires miner access but is trivially executable once that access exists.

## Recommendation

Add a TinyBlock-specific validation provider that verifies the claimed TinyBlock behavior is appropriate for the miner's current state:

```csharp
// Add to ValidateBeforeExecution switch statement
case AElfConsensusBehaviour.TinyBlock:
    validationProviders.Add(new TinyBlockValidationProvider());
    break;
```

Create `TinyBlockValidationProvider` that checks:
1. Miner's `OutValue` is already set in current round (TinyBlock requires prior UpdateValue)
2. Miner hasn't exceeded maximum blocks for their slot
3. Current time is within the miner's designated time slot

Alternatively, implement a behavior verification provider that runs for ALL behaviors to ensure the claimed behavior matches what `GetConsensusBehaviour()` would return based on current state.

## Proof of Concept

A malicious miner can execute this attack by:

1. When their mining slot arrives, call `GetConsensusCommand` (returns UpdateValue suggestion for first block)
2. Ignore this and prepare trigger information with `Behaviour = AElfConsensusBehaviour.TinyBlock`
3. Call `GenerateConsensusTransactions` with this modified trigger information
4. Produce block with TinyBlock behavior
5. Validation passes (no TinyBlock validator checks state appropriateness)
6. `ProcessTinyBlock` executes without OutValue/Signature requirement
7. Miner receives block credit without consensus contribution
8. Later, `SupplyCurrentRoundInformation` fills fake OutValue/Signature values

This can be verified by examining that:
- No validation in lines 77-92 of `AEDPoSContract_Validation.cs` has a TinyBlock case
- `ProcessTinyBlock` (lines 299-309 of `AEDPoSContract_ProcessConsensusInformation.cs`) doesn't require OutValue/Signature
- `GetConsensusBlockExtraData` (line 26 of `AEDPoSContract_GetConsensusBlockExtraData.cs`) switches on miner-provided behavior without verification

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L26-48)
```csharp
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextRound:
                information = GetConsensusExtraDataForNextRound(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextTerm:
                information = GetConsensusExtraDataForNextTerm(pubkey, triggerInformation);
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-197)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
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
