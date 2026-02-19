### Title
Missing Validation Allows ConfirmedIrreversibleBlockHeight to Exceed Current Blockchain Height During Term Transitions

### Summary
The `NextTermInput.Create()` function accepts and propagates a Round's `ConfirmedIrreversibleBlockHeight` without validating it against the current blockchain height. Malicious miners can set arbitrarily high `ImpliedIrreversibleBlockHeight` values during block production, which lack upper-bound validation, leading to invalid LIB calculations that violate the fundamental invariant that LIB height must never exceed the current blockchain height.

### Finding Description

**Root Cause - Missing Validation Chain:**

1. **No validation in `NextTermInput.Create()`**: The function blindly copies `ConfirmedIrreversibleBlockHeight` from the provided Round without any validation. [1](#0-0) 

2. **Source of invalid LIB in `GenerateFirstRoundOfNextTerm()`**: The Round passed to `Create()` gets its `ConfirmedIrreversibleBlockHeight` copied directly from `currentRound` without validation. [2](#0-1) 

3. **No upper-bound validation in `UpdateValueValidationProvider`**: When miners submit `UpdateValue` transactions, their `ImpliedIrreversibleBlockHeight` is never validated to ensure it doesn't exceed the current block height. [3](#0-2) 

4. **`LibInformationValidationProvider` only checks backwards movement**: The validation only ensures LIB doesn't decrease, not that it doesn't exceed current blockchain height. [4](#0-3) 

5. **`ProcessUpdateValue` accepts invalid LIB calculations**: The calculated `libHeight` is accepted if it's higher than the current `ConfirmedIrreversibleBlockHeight`, with no check against `Context.CurrentHeight`. [5](#0-4) 

6. **No LIB validation for NextTerm behavior**: The validation pipeline for `NextTerm` only includes `RoundTerminateValidationProvider`, omitting `LibInformationValidationProvider` entirely. [6](#0-5) 

### Impact Explanation

**Consensus Integrity Violation:**
- Violates the critical invariant that Last Irreversible Block (LIB) height must always be ≤ current blockchain height
- Creates state inconsistency between the consensus contract's `ConfirmedIrreversibleBlockHeight` and the actual blockchain state
- Cross-chain operations relying on LIB for finality guarantees may accept invalid proofs or reject valid ones
- When the blockchain height eventually catches up to the inflated LIB value, blocks may be incorrectly marked as irreversible without proper consensus

**Operational Impact:**
- Breaks consensus finality guarantees that other contracts and off-chain systems depend on
- Cross-chain bridges using LIB for transaction finality could process transfers prematurely
- Election and reward distribution mechanisms that key off LIB may trigger incorrectly
- Once propagated through term transitions, the invalid LIB persists across multiple terms

### Likelihood Explanation

**Attacker Capabilities:**
- Requires attacker to be an active miner in the consensus set
- No special privileges beyond normal miner capabilities required
- Attack vector is a simple parameter manipulation in `UpdateValueInput`

**Attack Complexity:**
- Low complexity: Simply provide inflated `ImpliedIrreversibleBlockHeight` value in UpdateValue transaction
- No sophisticated timing or race conditions required
- Validation gaps are structural, not timing-dependent

**Feasibility:**
- Highly feasible: The miner generates consensus extra data locally where `ImpliedIrreversibleBlockHeight` is set to `Context.CurrentHeight`. [7](#0-6) 
- However, when the block is executed, the value comes from `UpdateValueInput` which the miner controls. [8](#0-7) 
- With enough colluding miners (or even a single miner in certain round configurations), the LIB calculation at index `(count-1)/3` of sorted implied heights can produce an invalid result. [9](#0-8) 

**Detection:**
- Difficult to detect in real-time as the invalid state exists within consensus contract storage
- The blockchain's `SetIrreversibleBlockAsync` would silently fail to update when the block hash doesn't exist yet, masking the issue. [10](#0-9) 

### Recommendation

**Immediate Mitigations:**

1. **Add validation in `ProcessUpdateValue`**: Reject any `ImpliedIrreversibleBlockHeight` that exceeds `Context.CurrentHeight`:
```csharp
// In ProcessUpdateValue, before line 248
Assert(updateValueInput.ImpliedIrreversibleBlockHeight <= Context.CurrentHeight, 
       "Implied irreversible block height cannot exceed current block height.");
```

2. **Add validation for calculated LIB**: In `ProcessUpdateValue`, verify the calculated `libHeight` doesn't exceed current height:
```csharp
// After line 270, before setting ConfirmedIrreversibleBlockHeight
if (libHeight > Context.CurrentHeight)
{
    Context.LogDebug(() => $"Calculated LIB {libHeight} exceeds current height {Context.CurrentHeight}");
    return; // or use last valid height
}
```

3. **Add LIB validation for NextTerm**: Include `LibInformationValidationProvider` in the validation pipeline for `NextTerm` behavior:
```csharp
// In ValidateBeforeExecution
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this
    break;
```

4. **Add explicit validation in `NextTermInput.Create()`**:
```csharp
// Add assertion after line 9
Assert(round.ConfirmedIrreversibleBlockHeight <= /* Context.CurrentHeight via parameter */,
       "Cannot create NextTermInput with LIB exceeding current height");
```

**Test Cases:**
- Verify UpdateValue transaction rejected when `ImpliedIrreversibleBlockHeight > Context.CurrentHeight`
- Verify NextTerm transition rejected when source Round has invalid `ConfirmedIrreversibleBlockHeight`
- Verify LIB calculation never produces value exceeding current blockchain height
- Verify term transitions maintain LIB invariant under adversarial miner behavior

### Proof of Concept

**Initial State:**
- Blockchain at height 100
- Current round has `ConfirmedIrreversibleBlockHeight = 95`
- Malicious miner is active in consensus set

**Attack Steps:**

1. Malicious miner produces block at height 101 with `UpdateValue` behavior
2. Instead of setting `ImpliedIrreversibleBlockHeight = 101`, miner sets it to `500` (future height)
3. Validation in `LibInformationValidationProvider` only checks it doesn't go backwards - passes
4. Value `500` is stored in round state via `ProcessUpdateValue`
5. In next round at height 102, `LastIrreversibleBlockHeightCalculator` executes
6. With enough miners having high implied heights, calculated `libHeight` could be `> 102`
7. `ProcessUpdateValue` accepts this and sets `currentRound.ConfirmedIrreversibleBlockHeight = 300` (example)
8. NextTerm is triggered at height 150
9. `GenerateFirstRoundOfNextTerm` copies invalid LIB value (300) from current round
10. `NextTermInput.Create()` accepts this without validation
11. New term begins with `ConfirmedIrreversibleBlockHeight = 300` while blockchain is only at height 150

**Expected Result:**
- Validation should reject `ImpliedIrreversibleBlockHeight = 500` at step 3
- LIB calculation should be capped at current height
- NextTerm should reject invalid LIB values

**Actual Result:**
- All validations pass
- Invalid LIB state persists in consensus contract
- Invariant `LIB ≤ current height` is violated

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-32)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L63-65)
```csharp
            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;
```
