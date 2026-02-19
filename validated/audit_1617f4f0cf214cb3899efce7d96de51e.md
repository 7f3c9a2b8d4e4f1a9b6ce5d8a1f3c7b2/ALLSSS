# Audit Report

## Title
Broken After-Execution Validation Enables Consensus State Poisoning via Same-Object Hash Comparison

## Summary
The `ValidateConsensusAfterExecution` method contains a critical bug where hash comparison always passes because both sides reference the same object after recovery. The `RecoverFromUpdateValue` method modifies `currentRound` in-place and returns `this`, which is then assigned to `headerInformation.Round`, causing the subsequent hash comparison to compare an object's hash with itself. This broken validation allows malicious miners to commit corrupted consensus data to StateDb, poisoning future block validations.

## Finding Description

The vulnerability exists in the after-execution validation logic where consensus state should be verified against block header declarations.

**Root Cause:** [1](#0-0) 

The critical flaw is that `RecoverFromUpdateValue` modifies the caller object in-place and returns `this`: [2](#0-1) 

After the assignment at lines 90-92, both `headerInformation.Round` and `currentRound` reference the **same object**. The original header data is lost.

**Validation Flow:**
1. Load `currentRound` from StateDb (post-execution state)
2. Call `currentRound.RecoverFromUpdateValue(headerInformation.Round, pubkey)` which modifies `currentRound` in-place and returns it
3. Assign return value to `headerInformation.Round` - now both variables point to same object
4. Compare hashes at [3](#0-2)  - always succeeds (same object)

**Inconsistent Usage:** The before-execution validation correctly uses recovery for side effects only: [4](#0-3) 

It does NOT assign the return value, preserving the original header data for validation.

**State Update Path:** During execution, consensus fields are modified: [5](#0-4) 

Fields like `ProducedBlocks` are calculated (not from input), while others like `Signature`, `OutValue`, `ImpliedIrreversibleBlockHeight` are taken from input. The after-execution validation should verify final state matches header declarations.

**Fields in Simplified Round:** The header includes these fields via `GetUpdateValueRound`: [6](#0-5) 

All these fields can be manipulated in the header without detection due to the broken validation.

## Impact Explanation

**Consensus Integrity Compromise:**
Malicious miners can write consensus data to StateDb that differs from block header declarations. This corrupted state becomes the `BaseRound` for validating future blocks.

**Cascading Failures:**
Future blocks load corrupted state for validation: [7](#0-6) 

Validation providers depend on this data:
- **Mining permission checks**: [8](#0-7) 

- **Time slot validation**: [9](#0-8) 

Corrupted base round data causes:
- **Denial of Service**: Legitimate blocks rejected due to invalid state
- **Consensus Manipulation**: Malicious blocks accepted with corrupted validation baseline
- **Chain Instability**: Invalid round transitions from corrupted state

**Severity: CRITICAL** - Breaks fundamental consensus integrity invariant.

## Likelihood Explanation

**Attacker Prerequisites:**
Must be active miner in current or previous round, verified by `PreCheck`: [10](#0-9) 

**Attack Complexity: LOW**
1. Miner generates block with manipulated consensus header data
2. Execution updates state (correctly or incorrectly depending on field)
3. After-execution validation passes due to same-object bug
4. Corrupted state committed to blockchain

**Feasibility: HIGH**
- No additional permissions beyond being a miner
- Bug is deterministic and always present
- Single block attack vector
- Validation is mandatory: [11](#0-10) 

**Detection: DIFFICULT**
Validation passes silently. Corruption detected only when future blocks fail unexpectedly or via off-chain monitoring.

**Probability: HIGH**
Any malicious miner can exploit during their mining slot. With regular miner rotation, attack surface is continuously available.

## Recommendation

**Fix the recovery assignment logic** in `ValidateConsensusAfterExecution`:

```csharp
public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
{
    var headerInformation = new AElfConsensusHeaderInformation();
    headerInformation.MergeFrom(input.Value);
    if (TryToGetCurrentRoundInformation(out var currentRound))
    {
        // Store original header round for comparison
        var originalHeaderRound = headerInformation.Round.Clone();
        
        // Apply recovery for side effects only, don't overwrite header
        if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
            currentRound.RecoverFromUpdateValue(originalHeaderRound, 
                headerInformation.SenderPubkey.ToHex());

        if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
            currentRound.RecoverFromTinyBlock(originalHeaderRound,
                headerInformation.SenderPubkey.ToHex());

        // Now compare original header against recovered current state
        var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
        if (originalHeaderRound.GetHash(isContainPreviousInValue) !=
            currentRound.GetHash(isContainPreviousInValue))
        {
            // ... existing miner replacement check logic ...
        }
    }
    return new ValidationResult { Success = true };
}
```

**Key changes:**
1. Clone `headerInformation.Round` before recovery to preserve original
2. Apply recovery to `currentRound` only (for side effects)
3. Compare **original header** hash against **recovered current state** hash

This ensures the validation compares two distinct objects: the header declaration versus the actual post-execution state.

## Proof of Concept

The vulnerability can be demonstrated by creating a test that:

1. Sets up a miner with valid state
2. Creates a block with intentionally incorrect consensus values in the header (e.g., wrong `ProducedBlocks` count)
3. Executes the consensus transaction (which updates state correctly)
4. Calls `ValidateConsensusAfterExecution` with the incorrect header
5. Observes validation passes despite mismatch between header and state

The test would show that after line 92 in `ValidateConsensusAfterExecution`, both `headerInformation.Round` and `currentRound` point to the same object reference, making the hash comparison at lines 100-101 meaningless.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L18-20)
```csharp
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-21)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L80-99)
```csharp
    public async Task<bool> ValidateBlockAfterExecuteAsync(IBlock block)
    {
        if (block.Header.Height == AElfConstants.GenesisBlockHeight)
            return true;

        var consensusExtraData = _consensusExtraDataExtractor.ExtractConsensusExtraData(block.Header);
        if (consensusExtraData == null || consensusExtraData.IsEmpty)
        {
            Logger.LogDebug($"Invalid consensus extra data {block}");
            return false;
        }

        var isValid = await _consensusService.ValidateConsensusAfterExecutionAsync(new ChainContext
        {
            BlockHash = block.GetHash(),
            BlockHeight = block.Header.Height
        }, consensusExtraData.ToByteArray());

        return isValid;
    }
```
