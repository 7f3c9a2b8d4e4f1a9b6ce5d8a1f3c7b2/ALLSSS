### Title
Ineffective ImpliedIrreversibleBlockHeight Validation Enables Last Irreversible Block Stalling Attack

### Summary
The validation logic for `ImpliedIrreversibleBlockHeight` in `LibInformationValidationProvider` is rendered ineffective because the base round is modified with provided values before validation occurs, allowing malicious miners to set arbitrarily low values. While this cannot directly decrease the confirmed LIB due to an existing safeguard, attackers controlling approximately 1/3 of miners can cause the LIB calculation to yield values lower than the current confirmed LIB, permanently stalling LIB advancement and blocking finality.

### Finding Description

The vulnerability exists in the validation flow orchestrated in `ValidateBeforeExecution`: [1](#0-0) 

The critical issue is the order of operations. Before validation, `RecoverFromUpdateValue` is called which overwrites the base round's `ImpliedIrreversibleBlockHeight`: [2](#0-1) 

Subsequently, the validation compares the modified base round against the provided round: [3](#0-2) 

Since both `baseRound` and `providedRound` now contain identical `ImpliedIrreversibleBlockHeight` values after recovery, the check `baseRound[pubkey].ImpliedIrreversibleBlockHeight > providedRound[pubkey].ImpliedIrreversibleBlockHeight` always evaluates to false, allowing any value to pass validation.

Honest miners set this value to the current block height: [4](#0-3) 

However, malicious miners can provide artificially low values which bypass validation. The LIB calculation uses these values: [5](#0-4) 

The calculation takes the value at position `(count-1)/3` from sorted implied heights, meaning approximately 1/3 of miners reporting low values can manipulate this calculation downward.

While there is a safeguard preventing `ConfirmedIrreversibleBlockHeight` from decreasing: [6](#0-5) 

This same check prevents LIB from advancing when the calculated `libHeight` is lower than the current confirmed value, causing permanent LIB stalling.

### Impact Explanation

**Operational Impact - DoS on Finality Mechanism:**
- When ~1/3 Byzantine miners report artificially low `ImpliedIrreversibleBlockHeight` values, the LIB calculation (using position `(count-1)/3` in sorted heights) produces results below the current confirmed LIB
- The safeguard at line 272 prevents updates when `currentRound.ConfirmedIrreversibleBlockHeight >= libHeight`, causing the LIB to permanently stop advancing
- No new blocks become irreversible, breaking the finality guarantee fundamental to blockchain security

**Cross-Chain Operations Blocked:**
- Cross-chain operations rely on LIB for security verification
- Stalled LIB prevents cross-chain transfers, merkle proof verification, and parent/side-chain synchronization
- All cross-chain functionality becomes inoperable

**Economic and Trust Damage:**
- Users cannot obtain finality guarantees for high-value transactions
- Exchanges and DeFi protocols requiring settlement assurance are affected
- Long-term stalling damages protocol trust and adoption

The severity is **CRITICAL** because it breaks a fundamental consensus invariant (LIB advancement) with systemic impact across all protocol layers requiring finality.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires control of approximately 1/3 of active miners (f nodes in a 3f+1 BFT system)
- This is within the standard Byzantine fault tolerance threat model that the system claims to handle

**Attack Complexity:**
- **Simple to Execute**: Attacker only needs to modify their miner node to set `ImpliedIrreversibleBlockHeight` to a low constant value instead of `Context.CurrentHeight`
- **No Special Permissions Required**: Uses normal `UpdateValue` consensus behavior accessible to all miners
- **Persistent Effect**: Once enough malicious miners participate in a round, LIB stops advancing indefinitely until manual intervention

**Feasibility Conditions:**
- No economic disincentives exist for reporting false implied heights
- No detection mechanism identifies miners reporting anomalous values
- The validation that should prevent this is broken by design

**Detection and Operational Constraints:**
- Attack is difficult to detect initially as blocks continue to be produced normally
- Only becomes apparent when finality-dependent operations (cross-chain, settlement) start failing
- No automatic recovery mechanism exists

**Probability Assessment:** HIGH - The attack requires only 1/3 miner collusion (standard BFT threshold) and is trivial to implement, making it highly feasible for motivated adversaries or compromised validator sets.

### Recommendation

**Fix the Validation Order:**

In `AEDPoSContract_Validation.cs`, create the validation context BEFORE calling recovery methods. Store the original base round for validation:

```csharp
// Store original for validation
var originalBaseRound = baseRound.Clone(); // Need to implement Clone() or use protobuf clone

var validationContext = new ConsensusValidationContext
{
    BaseRound = originalBaseRound, // Use unmodified base for validation
    ProvidedRound = extraData.Round,
    // ... other fields
};

// Validate FIRST with original values
var validationResult = service.ValidateInformation(validationContext);
if (!validationResult.Success) return validationResult;

// Only AFTER validation passes, apply recovery for later processing
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**Add Invariant Checks:**

Add explicit bounds checking for `ImpliedIrreversibleBlockHeight`:
```csharp
// In LibInformationValidationProvider
var providedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
var baseHeight = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;

// Must not decrease
if (providedHeight < baseHeight && baseHeight != 0)
{
    validationResult.Message = "ImpliedIrreversibleBlockHeight cannot decrease";
    return validationResult;
}

// Should be reasonably close to current height (e.g., within last 1000 blocks)
if (Context.CurrentHeight - providedHeight > 1000)
{
    validationResult.Message = "ImpliedIrreversibleBlockHeight too far behind current height";
    return validationResult;
}
```

**Add Test Cases:**
1. Test that validation rejects decreased `ImpliedIrreversibleBlockHeight`
2. Test that malicious miner reporting old heights gets validation failure
3. Test LIB advancement with mixed honest/malicious miners
4. Test that validation occurs before state modification

### Proof of Concept

**Initial State:**
- Current round N with 7 miners, each with `ImpliedIrreversibleBlockHeight = 10000`
- Current `ConfirmedIrreversibleBlockHeight = 9500`
- Current block height = 10100

**Attack Steps:**

1. **Attacker Setup:** Compromise 3 out of 7 miners (43%, exceeds 1/3 threshold)

2. **Round N+1 - Attackers Report Low Values:**
   - Honest miners (4): Set `ImpliedIrreversibleBlockHeight = 10100` (current height)
   - Malicious miners (3): Set `ImpliedIrreversibleBlockHeight = 100` (artificially low)
   - All values pass validation due to broken check at line 23-30 (compares modified base against provided)

3. **Round N+2 - LIB Calculation Uses Round N+1 Values:**
   - `LastIrreversibleBlockHeightCalculator` called with previous round (N+1) heights
   - Sorted heights: `[100, 100, 100, 10100, 10100, 10100, 10100]`
   - Position = `(7-1)/3 = 2` (0-indexed)
   - Calculated `libHeight = 100`

4. **LIB Update Check Fails:**
   - Check at line 272: `if (9500 < 100)` evaluates to FALSE
   - `ConfirmedIrreversibleBlockHeight` not updated, remains 9500
   - No `IrreversibleBlockFound` event fired

5. **Subsequent Rounds:**
   - Malicious miners continue reporting `ImpliedIrreversibleBlockHeight = 100`
   - Calculated LIB remains 100 (or similar low value)
   - Check `9500 < 100` continues to fail
   - **LIB permanently stuck at 9500**

**Expected Result (Without Vulnerability):**
- Validation should reject miners reporting `ImpliedIrreversibleBlockHeight < 10000`
- LIB should advance normally to ~10090 by round N+2

**Actual Result (With Vulnerability):**
- All malicious values accepted
- LIB advancement permanently stalled at 9500
- Cross-chain operations blocked
- No new finality achieved beyond block 9500

**Success Condition:** 
LIB remains stuck indefinitely at 9500 while block production continues to 11000+, demonstrating successful DoS on finality mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-60)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L271-281)
```csharp
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
