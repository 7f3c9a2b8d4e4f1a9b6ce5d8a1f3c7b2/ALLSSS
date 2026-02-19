### Title
LIB Height Manipulation via Ineffective Validation of ImpliedIrreversibleBlockHeight in UpdateValue

### Summary
The `LibInformationValidationProvider` validation executes after `RecoverFromUpdateValue` has already overwritten the base round's `ImpliedIrreversibleBlockHeight` with the provided value, making the validation check ineffective. This allows malicious miners to submit arbitrary implied irreversible block heights without detection. When approximately ≥1/3 of miners collude to provide artificially low values, they can manipulate the LIB calculation to slow down or halt finality progression, impacting cross-chain operations and block irreversibility.

### Finding Description

**Root Cause:**

The validation order in `ValidateBeforeExecution` is flawed. The method fetches the current round from state, then calls `RecoverFromUpdateValue` to merge the provided consensus data into the base round BEFORE running validation providers. [1](#0-0) [2](#0-1) 

The `RecoverFromUpdateValue` method unconditionally overwrites the base round's `ImpliedIrreversibleBlockHeight` with the value from the provided round: [3](#0-2) 

After this modification, the validation context is created with the already-modified base round: [4](#0-3) 

When `LibInformationValidationProvider` executes, it compares `baseRound.ImpliedIrreversibleBlockHeight` against `providedRound.ImpliedIrreversibleBlockHeight`, but both now contain the same (potentially malicious) value: [5](#0-4) 

The check `baseRound value > providedRound value` becomes `newValue > newValue`, which always evaluates to false and passes validation regardless of the actual value submitted.

**Exploitation Path:**

1. A malicious miner produces a block with `UpdateValue` behavior
2. In the consensus contract's honest implementation, `ImpliedIrreversibleBlockHeight` is set to `Context.CurrentHeight`: [6](#0-5) 

3. However, a malicious miner can bypass honest mining software and create their own `UpdateValueInput` with an artificially low `ImpliedIrreversibleBlockHeight` (e.g., 0 or a very low value): [7](#0-6) 

4. The validation fails to detect this due to the validation order bug described above
5. `ProcessUpdateValue` stores the fake value in the current round state: [8](#0-7) 

6. In the next round, the LIB calculator retrieves implied heights from the previous round and uses them to calculate the new LIB: [9](#0-8) 

7. The algorithm selects the value at position `floor((count-1)/3)` from sorted heights. If ≥ `floor((count-1)/3) + 1` miners (approximately ≥1/3) collude to provide fake low values, they can manipulate the selected LIB height.

### Impact Explanation

**Consensus Integrity Violation:**
- The LIB (Last Irreversible Block) height can be manipulated to slow down or halt its advancement
- While the forward-only check prevents reversing the LIB, attackers can freeze finality progression: [10](#0-9) 

**Operational Impact:**
- **Finality DoS**: Blocks cannot become irreversible, preventing transaction finality
- **Cross-chain operations stalled**: Cross-chain indexing and verification depend on LIB heights for security, so halted LIB advancement blocks cross-chain transfers
- **System-wide degradation**: Applications relying on finality guarantees cannot confirm transactions

**Byzantine Fault Tolerance Compromise:**
- For n=7 miners, `floor((7-1)/3) = 2`, so 3+ colluding miners (≥43%) can manipulate LIB
- For n=21 miners, `floor((21-1)/3) = 6`, so 7+ colluding miners (≥33%) can manipulate LIB
- This is at the edge of or slightly worse than standard BFT 1/3 tolerance

**Affected Parties:**
- All network participants depending on finality
- Cross-chain bridge users
- Smart contracts relying on irreversibility guarantees

### Likelihood Explanation

**Attacker Capabilities:**
- Requires control of ≥1/3 of active miners (those who have mined in the current round)
- Miners must coordinate to submit artificially low `ImpliedIrreversibleBlockHeight` values
- Each colluding miner must modify their mining software to bypass honest consensus transaction generation

**Feasibility:**
- Miners are elected and economically incentivized through staking, creating barriers to collusion
- However, 1/3 threshold is achievable in scenarios like:
  - Compromised mining pools controlling multiple validators
  - Nation-state level attacks
  - Economic incentives to disrupt cross-chain operations
- The attack is reachable through the public `UpdateValue` transaction path

**Detection:**
- Observable: LIB height stops advancing while block production continues normally
- Monitoring can detect the discrepancy between current block height and LIB height
- Forensic analysis can identify which miners submitted abnormally low implied heights

**Economic Rationality:**
- Direct financial gain may be limited (no immediate fund theft)
- Motivations could include:
  - Disrupting competitor chains in cross-chain ecosystems
  - Market manipulation (shorting tokens dependent on chain operations)
  - Censorship (preventing finality of specific transactions)
  - Extortion (demanding payment to restore normal operations)

**Execution Complexity:** Medium - requires miner collusion but no sophisticated cryptographic exploits

### Recommendation

**Immediate Fix:**

1. **Preserve original values for validation**: Modify `ValidateBeforeExecution` to store the original `ImpliedIrreversibleBlockHeight` before calling `RecoverFromUpdateValue`, then validate against the original value:

```csharp
// In ValidateBeforeExecution, before line 46:
var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(extraData.SenderPubkey.ToHex()) 
    ? baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight 
    : 0;

// Then modify LibInformationValidationProvider to use this stored original value
```

2. **Add explicit lower bound validation**: In `LibInformationValidationProvider`, check that the new `ImpliedIrreversibleBlockHeight` is not lower than the miner's previous value and is within reasonable bounds of current blockchain height:

```csharp
if (providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight < originalImpliedHeight)
{
    return new ValidationResult { Message = "ImpliedIrreversibleBlockHeight cannot decrease" };
}

if (providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > currentBlockHeight)
{
    return new ValidationResult { Message = "ImpliedIrreversibleBlockHeight cannot exceed current height" };
}
```

3. **Add upper bound validation**: Ensure `ImpliedIrreversibleBlockHeight` cannot be unreasonably high (e.g., greater than `Context.CurrentHeight`): [11](#0-10) 

**Additional Safeguards:**

4. **Strengthen Byzantine tolerance**: Consider using a higher percentile selection (e.g., median or 2/3 percentile) in the LIB calculator to increase resistance to manipulation: [12](#0-11) 

5. **Add monitoring alerts**: Implement off-chain monitoring to detect when LIB advancement significantly lags behind block production

**Test Cases:**

- Test that validation rejects `ImpliedIrreversibleBlockHeight` values lower than miner's previous value
- Test that validation rejects values exceeding current block height  
- Test that colluding miners providing low values are detected during validation
- Test recovery scenarios after validation fixes are applied

### Proof of Concept

**Initial State:**
- 7 active miners in current round
- Current blockchain height: 10000
- Current confirmed LIB height: 9000
- All miners have previously mined with correct implied heights around 9500

**Attack Sequence:**

1. **Setup**: 3 colluding malicious miners modify their mining software
2. **Round N execution**: 
   - 4 honest miners submit `UpdateValue` with `ImpliedIrreversibleBlockHeight = 10000` (current height)
   - 3 malicious miners submit `UpdateValue` with `ImpliedIrreversibleBlockHeight = 100` (fake low value)
   - All transactions pass validation due to the validation order bug
3. **Round N+1 LIB calculation**:
   - LIB calculator collects 7 implied heights from round N: `[100, 100, 100, 10000, 10000, 10000, 10000]`
   - Sorts them: `[100, 100, 100, 10000, 10000, 10000, 10000]`
   - Selects position `floor((7-1)/3) = 2` (0-indexed): value `100`
   - New LIB height: `max(9000, 100) = 9000` (unchanged due to forward-only check)

**Expected Result:** LIB should advance to ~9900-10000 range based on honest miners

**Actual Result:** LIB remains at 9000 and stops advancing as long as the attack continues

**Success Condition:** LIB height fails to advance for multiple rounds despite normal block production, causing finality DoS

**Notes**

This vulnerability represents a critical breakdown in the consensus finality mechanism. The validation order bug in `ValidateBeforeExecution` creates a blind spot where miners can submit arbitrary `ImpliedIrreversibleBlockHeight` values without detection. While the forward-only check at line 272 prevents reversing finality (which would be catastrophic), the ability to halt LIB advancement still constitutes a severe DoS attack on chain finality and cross-chain operations.

The approximate 1/3 Byzantine tolerance threshold for this attack aligns with but does not exceed standard BFT assumptions, making the attack theoretically feasible though requiring significant coordination. The impact extends beyond the consensus layer to affect any system depending on block irreversibility, including cross-chain bridges and applications requiring transaction finality guarantees.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L48-48)
```csharp
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-284)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
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
```
