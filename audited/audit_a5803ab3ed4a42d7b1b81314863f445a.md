### Title
ImpliedIrreversibleBlockHeight Validation Bypass via RecoverFromUpdateValue State Mutation

### Summary
The `LibInformationValidationProvider` validation for `ImpliedIrreversibleBlockHeight` is completely bypassed because `RecoverFromUpdateValue` modifies `BaseRound` in-place before validation occurs. This allows malicious miners to report arbitrarily low implied LIB heights (including backwards values), which should be rejected but are accepted, enabling manipulation of consensus finality.

### Finding Description

**Root Cause:**

In `ValidateBeforeExecution`, when processing `UpdateValue` behavior, the code calls `RecoverFromUpdateValue` on `baseRound` (fetched from state) before running validation providers: [1](#0-0) 

The `RecoverFromUpdateValue` method modifies `baseRound` in-place by copying the `ImpliedIrreversibleBlockHeight` from the provided round: [2](#0-1) 

Specifically at line 19, it overwrites: `minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight`.

Subsequently, the modified `baseRound` is passed to the validation context: [3](#0-2) 

When `LibInformationValidationProvider` runs, it checks whether the base value is greater than the provided value: [4](#0-3) 

**Why Protection Fails:**

After `RecoverFromUpdateValue` executes, `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` equals `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight`. The validation check at lines 25-26 becomes:

`providedValue > providedValue` → always **false** → validation **passes**

This renders the monotonicity check completely ineffective. The validation was designed to reject blocks where a miner reports a lower `ImpliedIrreversibleBlockHeight` than previously recorded in state, but the premature state mutation destroys the original value before comparison.

**Execution Path:**

1. Miner produces block with `UpdateValue` behavior
2. `ValidateBeforeExecution` called
3. `baseRound` fetched from state (contains previous `ImpliedIrreversibleBlockHeight` = 1000)
4. `RecoverFromUpdateValue` called → overwrites to provided value (e.g., 100)
5. `LibInformationValidationProvider` checks 100 > 100 → false → passes
6. Block accepted
7. `ProcessUpdateValue` writes the low value to state: [5](#0-4) 

### Impact Explanation

**Consensus Finality Manipulation:**

The `ImpliedIrreversibleBlockHeight` values from miners are used to calculate the Last Irreversible Block (LIB) height: [6](#0-5) 

The calculator takes the value at position `(count-1)/3` from sorted implied heights, requiring 2/3+ miner consensus.

**Concrete Harm:**

1. **LIB Freeze Attack**: If 1/3+ colluding miners report artificially low `ImpliedIrreversibleBlockHeight` values, the LIB calculation will use these low values, preventing the LIB from advancing properly.

2. **Finality Denial**: Applications and cross-chain bridges relying on LIB for transaction finality would be affected. Transactions would remain in a pending/unconfirmed state indefinitely.

3. **Cross-Chain Security**: Cross-chain operations depend on LIB for irreversibility guarantees. A frozen or manipulated LIB undermines cross-chain security assumptions.

4. **Economic Impact**: Trading, settlement, and time-sensitive operations requiring finality guarantees would be disrupted.

**Affected Parties:** All network participants, cross-chain operations, dApps relying on finality.

**Severity:** HIGH - This directly violates the critical invariant "LIB height rules" under Consensus & Cross-Chain integrity.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner in the current round (elected position)
- Can construct consensus extra data with arbitrary `ImpliedIrreversibleBlockHeight` values
- No special privileges beyond being a miner required

**Attack Complexity:** LOW
- Single malicious miner can report invalid values
- No complex transaction sequences needed
- Direct exploitation through normal block production

**Feasibility Conditions:**
- Miner produces blocks during their time slot
- Provides `UpdateValue` with low/zero `ImpliedIrreversibleBlockHeight`
- Validation automatically passes due to the bypass

**Economic Rationality:**
- Attack cost: None beyond normal block production cost
- Benefit: Disrupting competitor protocols or preventing unfavorable transactions from finalizing
- For coordinated attacks (1/3+ miners), impact scales significantly

**Detection:** 
Difficult to detect as blocks appear valid and pass all validation checks. Only observable through monitoring LIB progression anomalies.

### Recommendation

**Code-Level Mitigation:**

1. **Preserve Original State for Validation:**
   
   In `ValidateBeforeExecution`, create a copy of the original `baseRound` before calling `RecoverFromUpdateValue`:
   
   ```csharp
   var originalBaseRound = baseRound.Clone(); // Add before line 47
   
   if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
       baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
   
   var validationContext = new ConsensusValidationContext
   {
       BaseRound = baseRound,
       OriginalBaseRound = originalBaseRound, // Add new field
       ...
   };
   ```

2. **Update LibInformationValidationProvider:**

   Use `OriginalBaseRound` for comparison:
   
   ```csharp
   if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
       providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
       validationContext.OriginalBaseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
       providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
   ```

**Invariant Checks:**
- Add assertion: `ImpliedIrreversibleBlockHeight` for each miner must be monotonically increasing
- Add test: Verify validation rejects blocks with decreased `ImpliedIrreversibleBlockHeight`

**Test Cases:**
1. Test that a miner cannot report lower `ImpliedIrreversibleBlockHeight` than previous value
2. Test that a miner reporting zero when previously non-zero is rejected (unless first block)
3. Test that validation uses original state, not recovered state, for comparison

### Proof of Concept

**Initial State:**
- Miner "MinerA" has previously reported `ImpliedIrreversibleBlockHeight = 1000` (stored in state)
- Current round stored in state with this value
- Current LIB is at height 950

**Attack Transaction:**
1. MinerA produces block during their time slot
2. In consensus extra data (`UpdateValueInput`):
   - Set `ImpliedIrreversibleBlockHeight = 100` (backwards!)
   - Fill valid `OutValue`, `Signature`, `ActualMiningTime`
3. Block enters validation

**Expected Result (if validation worked correctly):**
- `LibInformationValidationProvider` should check: 1000 > 100? YES → **REJECT** with "Incorrect implied lib height"

**Actual Result (vulnerability present):**
- `ValidateBeforeExecution` line 47: `baseRound.RecoverFromUpdateValue(...)` overwrites: `baseRound.ImpliedIrreversibleBlockHeight = 100`
- `LibInformationValidationProvider` checks: 100 > 100? NO → **PASS**
- Block accepted
- State updated with value 100
- Future LIB calculations use this corrupted low value

**Success Condition:**
Block with backwards `ImpliedIrreversibleBlockHeight` is accepted when it should be rejected, confirming the validation bypass.

### Notes

The vulnerability exists because the design separates state recovery (necessary for hash validation) from state comparison validation, but performs them in the wrong order. The `RecoverFromUpdateValue` method is needed for `ValidateConsensusAfterExecution` hash comparison, but should not corrupt the state copy used for monotonicity validation in `ValidateBeforeExecution`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L9-34)
```csharp
    private class LastIrreversibleBlockHeightCalculator
    {
        private readonly Round _currentRound;
        private readonly Round _previousRound;

        public LastIrreversibleBlockHeightCalculator(Round currentRound, Round previousRound)
        {
            _currentRound = currentRound;
            _previousRound = previousRound;
        }

        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
    }
```
