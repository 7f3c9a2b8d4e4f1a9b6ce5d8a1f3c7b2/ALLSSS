### Title
ImpliedIrreversibleBlockHeight Validation Bypass Allows LIB Manipulation

### Summary
The `LibInformationValidationProvider.ValidateHeaderInformation()` performs validation after `baseRound.RecoverFromUpdateValue()` has already modified the base round with provided values, causing the validation to compare identical values and always pass. Additionally, the `!= 0` condition on line 24 allows miners to completely bypass validation by setting `ImpliedIrreversibleBlockHeight` to 0, enabling manipulation of Last Irreversible Block (LIB) calculation and potentially stalling blockchain finality.

### Finding Description

The vulnerability exists in the validation flow for `ImpliedIrreversibleBlockHeight` in the consensus mechanism:

**Root Cause - Validation After Recovery:**

In the validation pipeline, `baseRound.RecoverFromUpdateValue()` is called BEFORE the validators run: [1](#0-0) 

The `RecoverFromUpdateValue` method modifies `baseRound` in place, copying values from the provided round: [2](#0-1) 

After this recovery, the validation context uses the MODIFIED baseRound: [3](#0-2) 

**Ineffective Validation Check:**

The `LibInformationValidationProvider` then compares `baseRound` (already modified with new value) against `providedRound` (source of the new value): [4](#0-3) 

Since both sides now contain identical values after recovery, the condition on line 25-26 (`baseRound > providedRound`) will always be false, making the validation ineffective.

**Bypass via Zero Value:**

The `!= 0` condition on line 24 allows miners to completely skip validation by providing `ImpliedIrreversibleBlockHeight = 0`. While 0 is the default value for miners who haven't produced blocks yet, in normal operation miners set this to `Context.CurrentHeight` when producing blocks: [5](#0-4) 

A miner who previously set a valid height (e.g., 1000) can later provide 0 to bypass validation entirely.

**Impact on LIB Calculation:**

The LIB calculation filters out miners with `ImpliedIrreversibleBlockHeight <= 0`: [6](#0-5) 

This exclusion affects the Byzantine fault-tolerant consensus calculation: [7](#0-6) 

### Impact Explanation

**Consensus Integrity Compromise:**
- Malicious miners can set `ImpliedIrreversibleBlockHeight` to 0 or artificially low values, corrupting the LIB calculation
- LIB height determines blockchain finality - blocks below LIB are considered irreversible

**Denial of Service Potential:**
- If ≥1/3 of miners set their height to 0, the count drops below `MinersCountOfConsent` (2/3 + 1 threshold), causing LIB calculation to return 0 and halting finality advancement
- Even a single malicious miner excluding themselves shifts the 1/3 position in the sorted heights downward, delaying finality

**Cross-Chain Operation Impact:**
- Cross-chain indexing and verification rely on accurate LIB heights for security
- Manipulated LIB values compromise cross-chain bridge integrity

**Severity: HIGH** - Core consensus invariant violated, enabling finality manipulation and potential DoS of the entire blockchain's irreversibility mechanism.

### Likelihood Explanation

**Reachable Entry Point:**
The `UpdateValue` method is a standard consensus operation callable by any miner during their assigned time slot.

**Attacker Requirements:**
- Must be an active miner in the current miner list
- This is a realistic assumption in consensus security models (Byzantine fault tolerance assumes some miners may be malicious)

**Attack Complexity: LOW**
- Simply provide `ImpliedIrreversibleBlockHeight = 0` in the `UpdateValueInput` message
- No special timing or complex state manipulation required
- No transaction cost beyond normal block production

**Detection Difficulty:**
- The manipulation is visible in block data but may not trigger immediate alerts
- Requires monitoring of individual miner `ImpliedIrreversibleBlockHeight` values across rounds
- Impact becomes visible when LIB stops advancing or advances slower than expected

**Probability: HIGH** - Given the ease of execution and significant impact, a rational malicious miner could exploit this to disrupt finality or gain advantages in cross-chain operations.

### Recommendation

**1. Fix Validation Timing:**

Preserve the original `baseRound` values before recovery for comparison:

```csharp
// In AEDPoSContract_Validation.cs, before line 47
var originalBaseRound = baseRound.Clone(); // Need to implement deep clone

if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound,
    OriginalBaseRound = originalBaseRound, // Add this field
    ...
};
```

**2. Fix Validation Logic:**

Update `LibInformationValidationProvider` to compare original vs provided values:

```csharp
// Use OriginalBaseRound instead of BaseRound for the comparison
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    var originalHeight = validationContext.OriginalBaseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    var providedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Once set to non-zero, it should never decrease
    if (originalHeight > 0 && providedHeight < originalHeight)
    {
        validationResult.Message = "Incorrect implied lib height - cannot decrease.";
        return validationResult;
    }
    
    // Should be set to current height or higher, never 0 after first block
    if (originalHeight > 0 && providedHeight == 0)
    {
        validationResult.Message = "Incorrect implied lib height - cannot be reset to 0.";
        return validationResult;
    }
}
```

**3. Add Invariant Check:**

In `ProcessUpdateValue`, verify the implied height is reasonable:

```csharp
// After line 248 in ProcessConsensusInformation.cs
Assert(
    minerInRound.ImpliedIrreversibleBlockHeight > 0 || currentRound.RoundNumber == 1,
    "ImpliedIrreversibleBlockHeight must be positive after first round."
);
```

**4. Add Test Cases:**

- Test that miner cannot decrease `ImpliedIrreversibleBlockHeight` once set
- Test that miner cannot set `ImpliedIrreversibleBlockHeight` to 0 after producing first block
- Test LIB calculation behavior when multiple miners attempt this manipulation

### Proof of Concept

**Initial State:**
- Blockchain at height 1000
- Miner A has previously produced blocks, `ImpliedIrreversibleBlockHeight = 1000` in state
- Current round has 7 miners total (MinersCountOfConsent = 5)

**Attack Sequence:**

1. **Miner A produces block at height 1005:**
   - Creates `UpdateValueInput` with `ImpliedIrreversibleBlockHeight = 0`
   - Submits `UpdateValue` transaction

2. **Validation Phase:**
   - `baseRound` fetched from state: `baseRound.RealTimeMinersInformation["MinerA"].ImpliedIrreversibleBlockHeight = 1000`
   - `RecoverFromUpdateValue` called: overwrites to 0
   - `LibInformationValidationProvider` checks:
     - Line 24: `providedRound.ImpliedIrreversibleBlockHeight != 0` → FALSE (it's 0)
     - Entire validation block skipped
   - Validation returns `Success = true`

3. **State Update:**
   - `ProcessUpdateValue` line 248: `minerInRound.ImpliedIrreversibleBlockHeight = 0`
   - State now has MinerA's height as 0

4. **LIB Calculation in Next Round:**
   - `GetSortedImpliedIrreversibleBlockHeights` filters miners with height > 0
   - MinerA (height = 0) is excluded from calculation
   - Only 6 miners counted instead of 7
   - If MinerA + two other miners do this, count drops to 4 < 5 (MinersCountOfConsent)
   - LIB calculation returns 0, finality stalls

**Expected Result:** Validation should reject the 0 value and maintain height at 1000

**Actual Result:** Validation passes, height updated to 0, LIB calculation compromised

**Success Condition:** Transaction succeeds with exit code 0, state shows `ImpliedIrreversibleBlockHeight = 0` for MinerA, subsequent LIB calculations exclude MinerA

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-19)
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
