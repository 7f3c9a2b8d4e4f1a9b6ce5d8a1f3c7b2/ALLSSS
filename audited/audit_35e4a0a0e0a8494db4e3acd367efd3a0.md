### Title
Validation Bypass via Data Contamination Enables Last Irreversible Block (LIB) Manipulation

### Summary
The consensus validation logic contaminates trusted state data (`baseRound`) with untrusted block header data (`extraData.Round`) before performing validation checks. This causes the `LibInformationValidationProvider` to compare `ImpliedIrreversibleBlockHeight` against itself, always passing validation regardless of the submitted value. Malicious miners can exploit this to manipulate LIB calculations, potentially causing finality regression or denial of service.

### Finding Description

**Root Cause:** The validation flow in `ValidateBeforeExecution` modifies the trusted `baseRound` object with untrusted data from `extraData.Round` before creating the validation context. [1](#0-0) 

The `RecoverFromUpdateValue` method directly overwrites `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` with the value from the untrusted `providedRound`: [2](#0-1) 

Similarly for `RecoverFromTinyBlock`: [3](#0-2) 

After this contamination, the validation context is created with the modified `baseRound`: [4](#0-3) 

**Why Protection Fails:** The `LibInformationValidationProvider` then attempts to validate that `ImpliedIrreversibleBlockHeight` hasn't regressed by checking if `baseRound` value is greater than `providedRound` value: [5](#0-4) 

However, since `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` was just set equal to `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight`, this check becomes `X > X`, which always evaluates to false, causing validation to always pass.

**Execution Path:** After validation passes, the malicious value is persisted to state: [6](#0-5) 

This value is then used in LIB calculation: [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
- **Finality Regression**: Malicious miners can set `ImpliedIrreversibleBlockHeight` to zero or values below current LIB. With control of ⅓+ of miners (needed for LIB consensus), attackers can force the LIB to regress to arbitrary heights, breaking irreversibility guarantees.
- **Finality DoS**: By consistently reporting low or zero values, attackers prevent LIB from advancing, indefinitely blocking transaction finality.
- **Consensus Disruption**: The LIB calculation selects the value at position `(count-1)/3` from sorted heights. Malicious miners controlling this threshold can arbitrarily manipulate which blocks are considered irreversible.

**Affected Parties:**
- All network participants relying on block finality
- Cross-chain bridges and external systems using LIB for confirmation
- Applications depending on irreversible transaction guarantees

**Severity:** Critical - breaks core consensus invariant that LIB heights must be monotonically increasing.

### Likelihood Explanation

**Attacker Capabilities:** Any authorized miner in the current miner list can exploit this vulnerability.

**Attack Complexity:** Low
1. Miner produces block with `UpdateValue` or `TinyBlock` behavior
2. Sets `ImpliedIrreversibleBlockHeight` to malicious value (e.g., 0 or below current LIB) in the consensus extra data
3. Block validation passes due to contaminated comparison
4. Malicious value persists to state and influences LIB calculation

**Feasibility:** High
- Entry point is the standard block production flow
- No special privileges beyond being an active miner required
- No additional preconditions or complex state setup needed
- Exploit is deterministic and repeatable

**Detection Constraints:** The bypassed validation means no error or event is raised, making detection difficult without external monitoring of LIB progression anomalies.

**Probability:** High - exploit requires only miner status (by design) and simple parameter manipulation in consensus data.

### Recommendation

**Code-Level Mitigation:**

1. **Do not contaminate baseRound before validation**. Create validation context with pristine `baseRound` from state, then validate against untrusted `providedRound`:

```
// In AEDPoSContract_Validation.cs, remove lines 46-50
// DO NOT call RecoverFromUpdateValue/RecoverFromTinyBlock before validation

var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound,  // Use unmodified state data
    CurrentTermNumber = State.CurrentTermNumber.Value,
    CurrentRoundNumber = State.CurrentRoundNumber.Value,
    PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
    LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
    ExtraData = extraData
};
```

2. **Add explicit validation in LibInformationValidationProvider** that reads the actual previous state value:

```
// Add check that uses original baseRound (not contaminated)
if (providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0)
{
    var currentStateValue = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    var providedValue = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    if (currentStateValue > providedValue)
    {
        validationResult.Message = "ImpliedIrreversibleBlockHeight cannot regress";
        return validationResult;
    }
}
```

3. **Add monotonicity check** comparing against confirmed LIB:

```
if (providedValue < currentRound.ConfirmedIrreversibleBlockHeight)
{
    validationResult.Message = "ImpliedIrreversibleBlockHeight cannot be below confirmed LIB";
    return validationResult;
}
```

**Test Cases:**
- Test that miners cannot submit `ImpliedIrreversibleBlockHeight` below current value
- Test that miners cannot submit values below `ConfirmedIrreversibleBlockHeight`
- Test that validation rejects regressing values with appropriate error messages
- Test LIB calculation remains monotonic under adversarial inputs

### Proof of Concept

**Initial State:**
- Current round has `ConfirmedIrreversibleBlockHeight = 1000`
- Miner M1 has `ImpliedIrreversibleBlockHeight = 1000` in current state
- Miner M1 is authorized and in active miner list

**Attack Steps:**
1. Miner M1 produces a block with `UpdateValue` behavior
2. M1 sets `UpdateValueInput.ImpliedIrreversibleBlockHeight = 0` (or any value < 1000)
3. Block header includes this malicious value in `extraData.Round`

**Validation Flow (bypassed):**
1. `ValidateBeforeExecution` fetches `baseRound` from state where M1's value is 1000
2. `RecoverFromUpdateValue` executes, setting `baseRound.RealTimeMinersInformation[M1].ImpliedIrreversibleBlockHeight = 0`
3. `LibInformationValidationProvider` checks: `if (0 > 0)` → false, validation passes
4. `ProcessUpdateValue` persists the malicious value 0 to state

**Expected vs Actual:**
- **Expected:** Validation should reject the block with "Incorrect implied lib height" error because provided value (0) is less than current state value (1000)
- **Actual:** Validation passes, malicious value 0 is stored in state

**Success Condition:** 
After M1's block, `State.Rounds[currentRound].RealTimeMinersInformation[M1].ImpliedIrreversibleBlockHeight == 0`, allowing this malicious value to influence subsequent LIB calculations and potentially cause LIB regression if sufficient miners collude.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-20)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L43-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
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
