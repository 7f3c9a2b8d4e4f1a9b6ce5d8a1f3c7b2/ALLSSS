### Title
ImpliedIrreversibleBlockHeight Validation Bypass via RecoverFromUpdateValue Timing Issue

### Summary
The `LibInformationValidationProvider` validation is completely bypassed for `ImpliedIrreversibleBlockHeight` during UpdateValue consensus behavior. The root cause is that `RecoverFromUpdateValue` modifies the `BaseRound` object before validation occurs, causing the validator to compare the malicious value against itself. This allows any miner to inject fraudulently low implied LIB heights into consensus state, which will affect Last Irreversible Block (LIB) calculations in subsequent rounds and compromise blockchain finality guarantees.

### Finding Description

The vulnerability exists in the validation flow for UpdateValue consensus behavior. The execution sequence is:

**Location 1 - Premature State Recovery:** [1](#0-0) 

When the behavior is UpdateValue, `RecoverFromUpdateValue` is called on `baseRound`, modifying it before any validation occurs.

**Location 2 - Recovery Implementation:** [2](#0-1) 

The recovery copies `ImpliedIrreversibleBlockHeight` (along with other values) from `providedRound` into `baseRound` for the sender.

**Location 3 - Ineffective Validation:** [3](#0-2) 

The validator checks if `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight`. However, after `RecoverFromUpdateValue`, these values are identical, making the check always pass.

**Location 4 - Unvalidated State Persistence:** [4](#0-3) 

The malicious `ImpliedIrreversibleBlockHeight` from input is directly written to state without any effective validation preventing regression.

**Root Cause:** The design flaw is that state recovery (`RecoverFromUpdateValue`) happens before validation, corrupting the reference point (`BaseRound`) that validators use to detect malicious decreases. The validation becomes a tautology: comparing a value to itself.

### Impact Explanation

**Consensus Integrity Impact:**
The `ImpliedIrreversibleBlockHeight` is critical for LIB calculation: [5](#0-4) 

The LIB calculation collects implied irreversible heights from miners, sorts them, and takes the value at position `(count-1)/3` to ensure 2/3 consensus. A malicious miner can:

1. **Inject Fraudulent Low Values**: Set `ImpliedIrreversibleBlockHeight` to an arbitrarily low value (e.g., 100 when current height is 1000)
2. **Manipulate LIB Calculation**: In the next round, this fraudulent low value enters the sorted list used for LIB calculation
3. **Compromise Finality**: While one miner's impact is limited, repeated attacks or collusion among multiple miners can significantly lower the calculated LIB, affecting blockchain finality guarantees

**Concrete Example:**
- Setup: 7 miners, current height ~1000
- Normal: All miners report heights [995, 996, 997, 998, 999, 1000, 1001], LIB = 997
- Attack: Attacker injects 100, list becomes [100, 996, 997, 998, 999, 1000, 1001], LIB = 997 (still bounded by others)
- Repeated Attack: Over multiple rounds, attacker can prevent LIB from advancing properly

**Affected Parties:**
- All network participants relying on LIB for finality
- Applications depending on irreversible block confirmations
- Cross-chain operations using LIB heights

**Severity Justification:** HIGH - This bypasses a critical consensus validation designed to prevent regression of finality markers, directly impacting blockchain security guarantees.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a valid miner in the current round (realistic for any elected miner)
- No special privileges beyond normal mining rights required
- Can execute attack during their normal time slot

**Attack Complexity:**
- LOW - Simply requires setting a lower-than-legitimate `ImpliedIrreversibleBlockHeight` value when calling `GetConsensusExtraData`
- The validation bypass is automatic due to the code flow
- No race conditions or timing windows to exploit

**Feasibility Conditions:**
- Attacker is an elected miner (common in PoS/DPoS systems)
- During UpdateValue behavior (occurs every block production)
- No additional preconditions required

**Detection/Operational Constraints:**
- The malicious value appears legitimate to the validation logic
- No automatic detection mechanism exists in the current code
- Would only be noticed through manual state inspection or abnormal LIB progression

**Probability:** HIGH - Any miner can execute this attack at any time during their block production without detection by the current validation system.

### Recommendation

**Fix 1 - Preserve Original State for Validation:**
Modify `ValidateBeforeExecution` to preserve the original `baseRound` before recovery:

```csharp
// In AEDPoSContract_Validation.cs, around line 46-60
Round originalBaseRound = baseRound.Clone(); // Preserve original for validation

if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

var validationContext = new ConsensusValidationContext
{
    BaseRound = originalBaseRound, // Use original for validation
    ProvidedRound = extraData.Round,
    // ... other fields
};
```

**Fix 2 - Validate Before Recovery:**
Move the validation check to occur before `RecoverFromUpdateValue`:

```csharp
// In LibInformationValidationProvider.cs
// Add direct comparison without relying on recovered state
if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    var originalMiner = validationContext.BaseRound.RealTimeMinersInformation[pubkey];
    var providedMiner = providedRound.RealTimeMinersInformation[pubkey];
    
    if (providedMiner.ImpliedIrreversibleBlockHeight != 0 &&
        originalMiner.ImpliedIrreversibleBlockHeight > providedMiner.ImpliedIrreversibleBlockHeight)
    {
        return new ValidationResult { 
            Success = false, 
            Message = "ImpliedIrreversibleBlockHeight cannot decrease." 
        };
    }
}
```

**Invariant Checks to Add:**
1. `ImpliedIrreversibleBlockHeight` must be monotonically increasing for each miner
2. `ImpliedIrreversibleBlockHeight` should be close to current block height (within reasonable bounds)
3. Add explicit validation in `ProcessUpdateValue` as defense-in-depth

**Test Cases:**
1. Test that UpdateValue with decreased `ImpliedIrreversibleBlockHeight` is rejected
2. Test that UpdateValue with increased `ImpliedIrreversibleBlockHeight` is accepted
3. Test edge case where miner produces first block (no previous value to compare)
4. Verify LIB calculation integrity after fix

### Proof of Concept

**Required Initial State:**
- Blockchain at height 1000
- Miner A has previously produced a block with `ImpliedIrreversibleBlockHeight = 1000` stored in state
- Miner A is in the current round's miner list

**Attack Steps:**
1. Miner A's turn to produce block at height 1010
2. Miner A calls `GetConsensusCommand` and receives consensus command
3. Miner A crafts malicious `UpdateValueInput` with `ImpliedIrreversibleBlockHeight = 500` (fraudulently low)
4. Block validation occurs via `ValidateConsensusBeforeExecution`:
   - `baseRound` fetched: Miner A's `ImpliedIrreversibleBlockHeight = 1000`
   - `RecoverFromUpdateValue` called: copies 500 into `baseRound`
   - `LibInformationValidationProvider` checks: `baseRound[MinerA].ImpliedIrreversibleBlockHeight (500) > providedRound[MinerA].ImpliedIrreversibleBlockHeight (500)`? **FALSE** → Validation passes
5. `UpdateValue` executes, setting state: `currentRound[MinerA].ImpliedIrreversibleBlockHeight = 500`
6. State corrupted with malicious low value

**Expected vs Actual Result:**
- **Expected:** Validation should reject the block with message "Incorrect implied lib height"
- **Actual:** Validation passes, malicious value written to state

**Success Condition:** 
State inspection after block execution shows `State.Rounds[currentRound][MinerA].ImpliedIrreversibleBlockHeight = 500` despite current height being 1010, proving the validation bypass.

### Notes

The vulnerability also affects the `RecoverFromTinyBlock` flow similarly, though with less severe impact since TinyBlock behavior doesn't include the same LIB validation requirements. The core issue is architectural: performing state recovery before validation fundamentally breaks the validation logic that depends on comparing provided values against stored state.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L14-20)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-248)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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
