### Title
Missing Validation Allows Negative LIB Height Injection via NextTerm Transaction

### Summary
A malicious miner can inject a negative `ConfirmedIrreversibleBlockHeight` value into consensus state by crafting a malicious `NextTermInput` during term transitions. The `RoundTerminateValidationProvider` used for NextTerm behavior validates only round and term numbers but not the LIB height fields, allowing corrupted values to persist in state and propagate to all subsequent rounds, completely breaking blockchain finality tracking.

### Finding Description

**Root Cause:** Missing validation of `ConfirmedIrreversibleBlockHeight` in NextTerm transaction processing.

The vulnerability exists in the term transition flow:

1. In `GenerateFirstRoundOfNewTerm()`, the function unconditionally copies `ConfirmedIrreversibleBlockHeight` from the provided `currentRound` parameter to the new round: [1](#0-0) 

2. When a miner calls `NextTerm()`, it processes the input through `ProcessConsensusInformation()`: [2](#0-1) 

3. The input is validated via `ValidateBeforeExecution()`, which for NextTerm behavior only adds `RoundTerminateValidationProvider`: [3](#0-2) 

4. `RoundTerminateValidationProvider` validates ONLY round number and term number, not the LIB height fields: [4](#0-3) 

5. The `LibInformationValidationProvider`, which DOES validate LIB height cannot decrease, is only added for UpdateValue behavior, NOT for NextTerm: [5](#0-4) [6](#0-5) 

6. The unvalidated input is converted to a Round via `ToRound()` which preserves the attacker-controlled `ConfirmedIrreversibleBlockHeight`: [7](#0-6) 

7. This Round is then stored directly in State via `AddRoundInformation()`: [8](#0-7) 

8. Subsequent round generation copies this corrupted value forward: [9](#0-8) 

**Why Normal LIB Calculation Cannot Prevent This:** While normal UpdateValue transactions calculate LIB height correctly and filter out non-positive ImpliedIrreversibleBlockHeights: [10](#0-9) 

This protection is bypassed because the malicious miner injects the negative value directly via NextTermInput, which does not go through the LIB calculation logic.

### Impact Explanation

**Critical Consensus Corruption:**
- **Broken Finality Tracking:** A negative `ConfirmedIrreversibleBlockHeight` value (e.g., -1, -1000000) corrupts the fundamental invariant that LIB height represents irreversible blocks. Cross-chain indexing, block validation, and reorganization protection all depend on accurate LIB tracking.
- **Persistent State Corruption:** The negative value persists indefinitely in `State.Rounds` and propagates to every subsequent round and term through the copy operations, requiring chain rollback or hard fork to fix.
- **Cross-Chain Bridge Failures:** Cross-chain contracts rely on `ConfirmedIrreversibleBlockHeight` for security. Negative values could cause underflows, validation bypasses, or complete bridge halts.
- **Block Production Issues:** Future rounds inherit the corrupted value, potentially causing arithmetic errors or logic failures in time slot validation and miner scheduling.

**Who is Affected:**
- All network participants (validators, users, cross-chain bridges)
- Entire blockchain finality and consensus integrity

**Severity Justification:** CRITICAL - Allows a single malicious miner to permanently corrupt core consensus state during their authorized time slot, breaking fundamental blockchain invariants without requiring additional privileges beyond being an active miner.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner with a valid time slot during a term transition
- Must run modified node software to craft malicious `NextTermInput` with arbitrary `ConfirmedIrreversibleBlockHeight` value
- No special privileges beyond normal miner status required

**Attack Complexity:** LOW
- Single transaction during attacker's legitimate mining slot
- No race conditions or timing dependencies
- No need to compromise other miners or governance
- Direct state manipulation via public entry point

**Feasibility Conditions:**
- Attacker waits for their turn to produce the NextTerm block
- Constructs `NextTermInput` with `ConfirmedIrreversibleBlockHeight = -1` (or any negative value)
- Submits NextTerm transaction
- Validation passes (only checks round/term numbers)
- Corrupted state is stored permanently

**Detection/Operational Constraints:**
- Attack is immediately visible in consensus state once executed
- However, damage is already done as corrupted value is stored
- Network would need emergency hard fork to recover

**Probability:** HIGH - Any of the ~20+ active miners could execute this attack during any term transition (approximately every few days). The attack is deterministic, requires no external coordination, and has guaranteed success if the attacker reaches their NextTerm time slot.

### Recommendation

**Immediate Fix:** Add `LibInformationValidationProvider` to NextTerm validation to enforce LIB height monotonicity:

In `contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs`, modify the NextTerm case to include LIB validation:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
    break;
```

**Additional Checks:** Add explicit validation in `ProcessNextTerm()`:
```csharp
// After line 163 in AEDPoSContract_ProcessConsensusInformation.cs
Assert(nextRound.ConfirmedIrreversibleBlockHeight >= 0, 
    "ConfirmedIrreversibleBlockHeight cannot be negative.");
Assert(nextRound.ConfirmedIrreversibleBlockHeight >= currentRound.ConfirmedIrreversibleBlockHeight,
    "ConfirmedIrreversibleBlockHeight cannot decrease.");
```

**Test Cases:**
1. Attempt NextTerm with negative `ConfirmedIrreversibleBlockHeight` - should fail
2. Attempt NextTerm with `ConfirmedIrreversibleBlockHeight` less than current - should fail
3. Verify legitimate NextTerm with proper LIB height succeeds
4. Test edge cases: zero, Int64.MinValue, Int64.MaxValue

### Proof of Concept

**Required Initial State:**
- Blockchain running with multiple miners
- Attacker is one of the active miners
- Current term is about to end (NextTerm transition imminent)

**Attack Steps:**
1. Attacker's node monitors for their NextTerm time slot
2. Instead of calling contract's `GetConsensusExtraData()` to generate proper consensus data, attacker constructs malicious `NextTermInput`:
   ```
   NextTermInput {
     RoundNumber: currentRound.RoundNumber + 1,
     TermNumber: currentRound.TermNumber + 1,
     ConfirmedIrreversibleBlockHeight: -999999,  // MALICIOUS
     ConfirmedIrreversibleBlockRoundNumber: currentRound.ConfirmedIrreversibleBlockRoundNumber,
     // ... other fields properly populated
   }
   ```
3. Attacker submits NextTerm transaction during their valid time slot
4. Validation runs:
   - `MiningPermissionValidationProvider`: PASS (attacker is valid miner)
   - `TimeSlotValidationProvider`: PASS (within attacker's time slot)
   - `RoundTerminateValidationProvider`: PASS (round/term numbers correct)
   - **LibInformationValidationProvider: NOT EXECUTED** ← vulnerability
5. `ProcessNextTerm()` executes, stores Round with `ConfirmedIrreversibleBlockHeight = -999999`

**Expected Result:** Transaction should be rejected due to invalid LIB height

**Actual Result:** Transaction succeeds, `State.Rounds[newRoundNumber]` contains negative `ConfirmedIrreversibleBlockHeight`, value propagates to all future rounds

**Success Condition:** Query `GetCurrentRoundInformation()` and observe `ConfirmedIrreversibleBlockHeight < 0`, confirming permanent consensus state corruption.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L47-54)
```csharp
    internal Round GenerateFirstRoundOfNewTerm(int miningInterval, Timestamp currentBlockTime, Round currentRound)
    {
        var round = GenerateFirstRoundOfNewTerm(miningInterval, currentBlockTime, currentRound.RoundNumber,
            currentRound.TermNumber);
        round.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        round.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        return round;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-19)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
    }
```
