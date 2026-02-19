### Title
Consensus After-Execution Validation Bypassed for UpdateValue and TinyBlock Behaviors Due to Object Aliasing

### Summary
The `ValidateConsensusAfterExecution` method in the AEDPoS consensus contract fails to properly validate consensus state for `UpdateValue` and `TinyBlock` behaviors. The recover methods modify `currentRound` in place and return it, causing both `currentRound` and `headerInformation.Round` to reference the same object. The subsequent hash comparison at line 100-101 compares the object to itself, always succeeding and bypassing validation entirely.

### Finding Description

The vulnerability exists in the validation flow: [1](#0-0) 

At lines 89-97, the code calls recover methods for `UpdateValue` and `TinyBlock` behaviors: [2](#0-1) 

The `RecoverFromUpdateValue` method modifies `this` (the `currentRound` object) in place and returns `this`: [3](#0-2) 

Similarly, `RecoverFromTinyBlock` exhibits the same behavior: [4](#0-3) 

After the assignment on line 90 or 96, both `headerInformation.Round` and `currentRound` reference the **same modified object**. The hash comparison at lines 100-101 then compares this object to itself, which always returns equal hashes, causing the validation to always pass.

Additionally, if `TryToGetCurrentRoundInformation` returns false at line 87 (when consensus state is missing or corrupted), the entire validation block is skipped and success is returned at line 127 without any checks. [5](#0-4) 

### Impact Explanation

**Consensus Integrity Violation**: The after-execution validation is the final safety check to ensure that the consensus state written during block execution matches the expected state from the block header. By bypassing this validation for `UpdateValue` and `TinyBlock` behaviors, the system loses this critical invariant check.

**Concrete Harms**:
1. **Silent State Corruption**: If bugs exist in `ProcessUpdateValue` or `ProcessTinyBlock` that cause incorrect state updates, they would go undetected. [6](#0-5) 

2. **Invalid Round Information Acceptance**: Malformed consensus data could be accepted if it passes the weaker `ValidateBeforeExecution` but causes unexpected state during execution.

3. **LIB Calculation Errors**: Since `ImpliedIrreversibleBlockHeight` is part of the consensus state, incorrect values could corrupt Last Irreversible Block calculations.

4. **Miner Order Manipulation**: Fields like `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` could be manipulated without detection, affecting future round generation.

The validation is called in the critical block acceptance path: [7](#0-6) 

Blocks with invalid consensus state would be accepted into the chain, potentially causing consensus forks or incorrect miner scheduling in subsequent rounds.

### Likelihood Explanation

**Attack Complexity**: The vulnerability is always present for `UpdateValue` and `TinyBlock` behaviors. No special conditions are required - the validation simply doesn't work due to the object aliasing bug.

**Mitigating Factors**:
- `ValidateBeforeExecution` provides initial validation before the block is executed
- The execution is deterministic based on the input

**Exploitation Scenarios**:
1. **Execution Bugs**: If `ProcessUpdateValue` or `ProcessTinyBlock` have implementation bugs that can be triggered with specific inputs, these would not be caught by after-execution validation.

2. **State Inconsistencies**: Edge cases where the actual state diverges from expected state (due to re-entrancy, race conditions, or contract logic errors) would not be detected.

3. **Missing Round Information**: When `TryToGetCurrentRoundInformation` returns false (corrupted state), blocks are silently accepted without validation.

**Detection**: The lack of test coverage for `ValidateConsensusAfterExecution` with `UpdateValue` and `TinyBlock` behaviors confirms this bug has gone undetected:

Test coverage shows no validation tests for these behaviors, only for `NextRound`.

### Recommendation

**1. Fix Object Aliasing in Recover Methods**:

Modify `RecoverFromUpdateValue` and `RecoverFromTinyBlock` to clone the round object before modification:

```csharp
public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
{
    var recoveredRound = this.Clone(); // Create a copy
    // Perform modifications on recoveredRound instead of this
    return recoveredRound;
}
```

Or alternatively, do not modify `currentRound` - instead, directly modify `headerInformation.Round` by merging data from `currentRound`.

**2. Reject Blocks When Round Information Missing**:

At line 87, return failure instead of continuing:
```csharp
if (!TryToGetCurrentRoundInformation(out var currentRound))
    return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

This matches the behavior in `ValidateBeforeExecution`: [8](#0-7) 

**3. Add Comprehensive Test Coverage**:

Create tests that:
- Generate consensus extra data for `UpdateValue` and `TinyBlock` behaviors
- Execute the block transactions
- Call `ValidateConsensusAfterExecution` with modified consensus data
- Verify the validation correctly rejects invalid state

### Proof of Concept

**Initial State**: Consensus contract initialized with a current round at height N.

**Attack Steps**:

1. **Craft Malicious UpdateValue Block**:
   - Create a block with `UpdateValue` behavior
   - Include consensus extra data that passes `ValidateBeforeExecution`
   - The header includes incorrect values for `ImpliedIrreversibleBlockHeight` or miner ordering

2. **Block Execution**:
   - `GenerateConsensusTransactions` generates `UpdateValue` transaction
   - `ProcessUpdateValue` executes and updates state
   - State now contains the executed values (which may differ from header if bugs exist)

3. **Validation Bypass**:
   - `ValidateConsensusAfterExecution` is called
   - Line 90: `headerInformation.Round = currentRound.RecoverFromUpdateValue(...)`
   - Both variables now point to the same object (the state's `currentRound`)
   - Line 100-101: Hash comparison succeeds because it's comparing the object to itself
   - Validation returns success

4. **Expected Result**: Validation should detect if the actual state doesn't match the header.

5. **Actual Result**: Validation always succeeds for `UpdateValue` and `TinyBlock`, allowing potentially invalid consensus state to be accepted.

**Success Condition**: Any discrepancy between header consensus data and actual post-execution state goes undetected for these behaviors, violating the consensus integrity invariant.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
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

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```
