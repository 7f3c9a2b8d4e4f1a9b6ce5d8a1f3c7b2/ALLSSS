### Title
ImpliedIrreversibleBlockHeight Monotonicity Violation Due to Pre-Validation Mutation

### Summary
The `RecoverFromUpdateValue()` function overwrites `ImpliedIrreversibleBlockHeight` before validation occurs, causing the `LibInformationValidationProvider` to compare the provided value against itself rather than against the original state value. This allows malicious miners to decrease the `ImpliedIrreversibleBlockHeight`, potentially causing the Last Irreversible Block (LIB) height to move backwards and violating blockchain finality guarantees.

### Finding Description

**Root Cause:**

The vulnerability exists in the validation flow where `RecoverFromUpdateValue` is called before the `LibInformationValidationProvider` validation executes.

In `ValidateBeforeExecution`, the code retrieves the current round from state and then immediately modifies it with the provided information: [1](#0-0) [2](#0-1) 

The `RecoverFromUpdateValue` method directly overwrites the `ImpliedIrreversibleBlockHeight` without any validation: [3](#0-2) 

**Why Validation Fails:**

After the mutation, the validation context is created with the already-modified `baseRound`: [4](#0-3) 

The `LibInformationValidationProvider` is then added to check for LIB decreases: [5](#0-4) 

However, this validator compares the modified `baseRound` (which now contains the provided value) against the `providedRound` (which also contains the same provided value): [6](#0-5) 

Since both sides of the comparison now contain the same value (the provided value), the check `baseRound > providedRound` will always be false, never detecting a decrease.

**State Update Path:**

If validation passes, the malicious value is persisted to state in `ProcessUpdateValue`: [7](#0-6) 

### Impact Explanation

**Direct Consensus Integrity Impact:**

The `ImpliedIrreversibleBlockHeight` is used to calculate the Last Irreversible Block (LIB) height, which is fundamental to blockchain finality. The LIB calculation collects these values from all miners and derives a consensus value: [8](#0-7) 

By allowing a miner to provide a lower `ImpliedIrreversibleBlockHeight`, the calculated LIB can move backwards, violating the monotonicity invariant that finalized blocks should never be reversed.

**Affected Parties:**
- All network participants relying on block finality
- Cross-chain bridges and sidechains that depend on parent chain LIB heights
- Applications and users who consider transactions final based on LIB status

**Severity:** CRITICAL - Violates fundamental blockchain finality guarantees, enabling potential double-spend attacks and breaking cross-chain security assumptions.

### Likelihood Explanation

**Attacker Capabilities:**

Any active miner in the consensus miner list can exploit this vulnerability. Access control is enforced via `PreCheck()`: [9](#0-8) 

However, this only verifies that the sender is a miner, not that their provided values are valid.

**Attack Complexity:** LOW
- Attacker only needs to be an active miner (or previous miner during term transitions)
- No complex setup or state manipulation required
- Simply provide a lower `ImpliedIrreversibleBlockHeight` in the `UpdateValueInput`
- The broken validation will not detect the decrease

**Feasibility:** HIGH
- The vulnerability is reachable through normal consensus operations
- No special conditions or timing requirements needed
- Can be executed in any round during normal block production

**Economic Rationality:** 
A malicious miner could exploit this to:
1. Cause chain reorganizations affecting finalized blocks
2. Undermine cross-chain security by manipulating reported LIB heights
3. Enable sophisticated double-spend attacks by reversing "finalized" transactions

### Recommendation

**Immediate Fix:**

Preserve the original state value before calling `RecoverFromUpdateValue` and use it for validation. Modify the validation flow in `AEDPoSContract_Validation.cs`:

```csharp
// Store original value before mutation
var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(extraData.SenderPubkey.ToHex())
    ? baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight
    : 0;

if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound,
    OriginalImpliedIrreversibleBlockHeight = originalImpliedHeight, // Add this field
    // ... rest of context
};
```

**Alternative Fix:**

Move the validation check BEFORE the `RecoverFromUpdateValue` call, or perform the validation directly in `RecoverFromUpdateValue` before overwriting the value.

**Invariant Check:**

Add explicit monotonicity enforcement:
```csharp
if (providedInformation.ImpliedIrreversibleBlockHeight != 0 &&
    minerInRound.ImpliedIrreversibleBlockHeight > providedInformation.ImpliedIrreversibleBlockHeight)
{
    throw new AssertionException("ImpliedIrreversibleBlockHeight cannot decrease");
}
```

**Test Cases:**

1. Test that UpdateValue with lower `ImpliedIrreversibleBlockHeight` is rejected
2. Test that UpdateValue with equal or higher value succeeds
3. Test that the fix doesn't break legitimate consensus operations
4. Add regression test for LIB monotonicity across multiple rounds

### Proof of Concept

**Initial State:**
- Current round N with miner M
- `State.Rounds[N].RealTimeMinersInformation[M].ImpliedIrreversibleBlockHeight = 1000`

**Attack Sequence:**

1. Miner M produces a block with `UpdateValue` behavior
2. In the consensus extra data, M provides: `UpdateValueInput.ImpliedIrreversibleBlockHeight = 500` (lower than current 1000)
3. During `ValidateBeforeExecution`:
   - `baseRound` retrieved with value 1000
   - `RecoverFromUpdateValue` called, overwrites to 500
   - `LibInformationValidationProvider` checks: `500 > 500` → FALSE → Validation passes
4. `ProcessUpdateValue` executes and persists value 500 to state
5. State now has: `State.Rounds[N].RealTimeMinersInformation[M].ImpliedIrreversibleBlockHeight = 500`

**Expected Result:** Transaction should be rejected due to decreasing LIB height

**Actual Result:** Transaction succeeds, `ImpliedIrreversibleBlockHeight` decreased from 1000 to 500

**Success Condition:** Query state after transaction shows `ImpliedIrreversibleBlockHeight = 500`, violating monotonicity invariant

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L81-82)
```csharp
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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
