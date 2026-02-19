### Title
LIB Monotonicity Violation via Unvalidated NextRound and TinyBlock Consensus Behaviors

### Summary
The `LibInformationValidationProvider` is only applied to `UpdateValue` behavior, but `NextRound` and `TinyBlock` behaviors also modify LIB-related values in consensus state. A malicious miner can exploit this validation gap to submit consensus data with regressed (lowered) LIB values, violating the fundamental invariant that Last Irreversible Block height must be monotonically increasing. This poisons the consensus state and enables cascading LIB regressions in subsequent rounds.

### Finding Description

**Root Cause:** Selective validation application creates an exploitable gap in LIB monotonicity enforcement.

The `LibInformationValidationProvider` validates that LIB values do not regress by checking:
- `ConfirmedIrreversibleBlockHeight` should not decrease
- `ConfirmedIrreversibleBlockRoundNumber` should not decrease  
- Per-miner `ImpliedIrreversibleBlockHeight` should not decrease [1](#0-0) 

However, this validator is **only** added for `UpdateValue` behavior: [2](#0-1) 

**Vulnerability in NextRound Behavior:**

When a miner produces a NextRound block, they provide a `NextRoundInput` that includes `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields: [3](#0-2) 

These fields are included when converting to a `Round` object: [4](#0-3) 

The legitimate code path copies these values forward from the current round: [5](#0-4) 

**However**, a malicious miner can modify the `NextRoundInput` to contain **lower** LIB values before submission. Without the `LibInformationValidationProvider`, there is no validation that `providedRound.ConfirmedIrreversibleBlockHeight >= baseRound.ConfirmedIrreversibleBlockHeight`. The malicious round gets directly stored to state: [6](#0-5) [7](#0-6) 

**Vulnerability in TinyBlock Behavior:**

TinyBlock behavior includes `ImpliedIrreversibleBlockHeight` in the simplified round data: [8](#0-7) 

During recovery, this value is applied to the miner's state: [9](#0-8) 

Without `LibInformationValidationProvider`, a miner can submit a TinyBlock with a **lower** `ImpliedIrreversibleBlockHeight` than previously reported, and this regressed value gets stored via `TryToUpdateRoundInformation(currentRound)`: [10](#0-9) 

**Why Existing Protections Fail:**

The validation context properly distinguishes between `BaseRound` (current state) and `ProvidedRound` (miner-submitted data): [11](#0-10) 

But the validation service only runs the providers that were added to the list: [12](#0-11) 

Since `LibInformationValidationProvider` is not added for NextRound or TinyBlock behaviors, the LIB regression check never executes.

### Impact Explanation

**Consensus Integrity Violation (High):**
- LIB height is a **critical consensus invariant** that must be monotonically increasing
- Regressing LIB values in consensus state violates this fundamental safety property
- Future `UpdateValue` operations use the poisoned state as their baseline, enabling cascading regressions

**Cross-Chain Security Implications (High):**
- LIB determines which blocks are considered finalized for cross-chain operations
- While `IrreversibleBlockFoundLogEventProcessor` has guards against system-level LIB regression: [13](#0-12) 

- The consensus contract's Round state would contain **inconsistent** LIB values diverging from the chain's actual LIB
- This inconsistency could confuse cross-chain indexing operations that query consensus state

**State Poisoning (High):**
- Once a malicious round with lowered LIB is stored, all subsequent rounds built on it inherit the corrupted baseline
- Future LIB calculations use `currentRound` and `previousRound` from state: [14](#0-13) 

- If these rounds have poisoned LIB values, the calculation starts from a false baseline

### Likelihood Explanation

**High Likelihood - Practical Exploitation:**

**Reachable Entry Point:** 
- Public consensus methods `NextRound` and `TinyBlock` are callable by any authorized miner during their time slot
- No special privileges beyond normal miner status required

**Feasible Preconditions:**
- Attacker must be in the active miner set (realistic for a compromised/malicious validator)
- Attacker must wait for their assigned time slot to produce NextRound or TinyBlock
- No additional trust assumptions violated

**Execution Practicality:**
- Attacker modifies `NextRoundInput.ConfirmedIrreversibleBlockHeight` to a lower value before submission
- Or modifies `ImpliedIrreversibleBlockHeight` in TinyBlock data
- Transaction passes all validations except the missing LIB check
- State gets corrupted immediately upon successful block execution

**Economic Rationality:**
- Attack cost: Standard block production cost (negligible)
- No token stakes or bonds at risk for this specific attack
- Attack is detectable in logs but not preventable by existing validation

**Detection Constraints:**
- Regression would be visible in consensus events and state queries
- However, once stored, the corrupted state affects all dependent operations
- No automatic recovery mechanism exists

### Recommendation

**Immediate Fix:** Add `LibInformationValidationProvider` to all consensus behaviors that modify LIB-related fields:

```csharp
// In AEDPoSContract_Validation.cs, modify the switch statement:
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.TinyBlock:
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
}
```

**Additional Invariant Checks:**
1. Add assertion in `AddRoundInformation` to verify LIB never regresses:
```csharp
private void AddRoundInformation(Round round)
{
    var currentRound = State.Rounds[State.CurrentRoundNumber.Value];
    Assert(
        currentRound == null || 
        round.ConfirmedIrreversibleBlockHeight >= currentRound.ConfirmedIrreversibleBlockHeight,
        "LIB height cannot regress");
    
    State.Rounds.Set(round.RoundNumber, round);
    // ... rest of method
}
```

2. Add per-miner ImpliedIrreversibleBlockHeight monotonicity check in `TryToUpdateRoundInformation`

**Test Cases:**
1. Test NextRound with lowered `ConfirmedIrreversibleBlockHeight` - should fail validation
2. Test TinyBlock with lowered `ImpliedIrreversibleBlockHeight` - should fail validation
3. Test that legitimate NextRound/TinyBlock with proper LIB values still pass
4. Test cascading round generation after attempted LIB regression is blocked

### Proof of Concept

**Initial State:**
- Current round has `ConfirmedIrreversibleBlockHeight = 1000`
- Current round has `ConfirmedIrreversibleBlockRoundNumber = 10`
- Attacker is an authorized miner in position to produce NextRound block

**Attack Steps:**

1. **Attacker produces malicious NextRound:**
   - Legitimate code would generate nextRound with `ConfirmedIrreversibleBlockHeight = 1000` (copied from current)
   - Attacker modifies `NextRoundInput` to set `ConfirmedIrreversibleBlockHeight = 500` (regression!)
   - Submits transaction calling `NextRound(maliciousInput)`

2. **Validation executes:**
   - `MiningPermissionValidationProvider` passes (attacker is authorized miner)
   - `TimeSlotValidationProvider` passes (correct time slot)
   - `ContinuousBlocksValidationProvider` passes (normal block production)
   - `NextRoundMiningOrderValidationProvider` passes (correct miner order)
   - `RoundTerminateValidationProvider` passes (round can terminate)
   - **`LibInformationValidationProvider` NOT executed** ❌ (missing from provider list)

3. **State corruption occurs:**
   - `ProcessNextRound` executes successfully
   - `AddRoundInformation(nextRound)` stores the malicious round
   - `State.Rounds[newRoundNumber]` now contains `ConfirmedIrreversibleBlockHeight = 500`

4. **Verification of corruption:**
   - Query `GetCurrentRoundInformation()` returns round with LIB = 500
   - Previous round had LIB = 1000
   - **LIB regression confirmed** - monotonicity invariant violated

**Expected Result:** Transaction should fail with "Incorrect lib information" error

**Actual Result:** Transaction succeeds, LIB values regress from 1000 to 500, consensus state is corrupted

**Success Condition:** The regressed LIB value (500) is stored in `State.Rounds[newRoundNumber].ConfirmedIrreversibleBlockHeight`, violating the monotonicity invariant that LIB must never decrease.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-30)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L16-17)
```csharp
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L58-76)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L19-27)
```csharp
    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L16-26)
```csharp
    public ValidationResult ValidateInformation(ConsensusValidationContext validationContext)
    {
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
        }

        return new ValidationResult { Success = true };
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L60-61)
```csharp
            if (chain.LastIrreversibleBlockHeight > irreversibleBlockFound.IrreversibleBlockHeight)
                return;
```
