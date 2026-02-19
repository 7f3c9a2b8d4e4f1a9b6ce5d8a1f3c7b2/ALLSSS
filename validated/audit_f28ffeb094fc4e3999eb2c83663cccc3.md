# Audit Report

## Title
Broken ImpliedIrreversibleBlockHeight Validation Allows LIB Manipulation

## Summary
The `LibInformationValidationProvider.ValidateHeaderInformation()` contains a broken validation check that always passes due to premature state modification by `RecoverFromUpdateValue()`. This allows miners to set arbitrary `ImpliedIrreversibleBlockHeight` values without proper validation, enabling Last Irreversible Block (LIB) manipulation when sufficient miners collude.

## Finding Description

**Root Cause:**

The validation logic attempts to prevent `ImpliedIrreversibleBlockHeight` from decreasing, but this check is completely ineffective due to an ordering flaw in the validation flow. [1](#0-0) 

**Why the Check Fails:**

Before validation occurs, `RecoverFromUpdateValue()` is called in the validation flow, which modifies `baseRound` by copying the `providedRound`'s `ImpliedIrreversibleBlockHeight` value: [2](#0-1) [3](#0-2) 

After this line executes, `baseRound[pubkey].ImpliedIrreversibleBlockHeight` equals `providedRound[pubkey].ImpliedIrreversibleBlockHeight`. The subsequent validation check compares this value to itself, making the condition always evaluate to false (validation passes).

The validation context structure confirms that `BaseRound` is the modified round object while `ProvidedRound` returns the original from `ExtraData.Round`: [4](#0-3) 

**Missing Validations:**

1. No validation that `ImpliedIrreversibleBlockHeight` is monotonically increasing per miner (the existing check is broken)
2. No bounds checking that `ImpliedIrreversibleBlockHeight <= Context.CurrentHeight`
3. No consistency check between implied and confirmed LIB values
4. No verification that the value is reasonable relative to the miner's previous reports

**Expected vs Actual Behavior:**

During normal UpdateValue behavior, miners should set `ImpliedIrreversibleBlockHeight` to the current block height: [5](#0-4) 

However, a malicious miner can modify this value to any arbitrary number in their block header, and the broken validation will accept it. This value is then directly stored in the round state: [6](#0-5) 

## Impact Explanation

**Consensus Integrity Violation:**

These manipulated `ImpliedIrreversibleBlockHeight` values are directly used in LIB calculation in subsequent rounds: [7](#0-6) [8](#0-7) 

The LIB calculator uses a 2/3+1 consensus rule, taking the value at position `(count-1)/3` from the sorted implied heights. This means approximately 1/3 of miners can influence which value is selected.

**Attack Scenarios:**

1. **LIB Stalling (DoS):** If >1/3 of miners collude and report artificially low `ImpliedIrreversibleBlockHeight` values (e.g., 0 or far behind actual height), the LIB calculation will select these low values at position `(count-1)/3`, preventing LIB from advancing. This stalls:
   - Cross-chain operations dependent on LIB
   - Block pruning and chain finalization
   - User transaction finality guarantees

2. **Premature LIB Advancement (Critical):** If >1/3 of miners report artificially high `ImpliedIrreversibleBlockHeight` values (exceeding actual irreversible height), the LIB could advance beyond truly irreversible blocks, causing:
   - False finality signals to users and applications
   - Cross-chain bridges accepting non-final state
   - Potential for chain reorganization after "finality"
   - Violation of Byzantine fault tolerance guarantees

**Affected Parties:**
- All chain participants relying on LIB for finality
- Cross-chain bridges and side-chain operations
- Applications requiring transaction finality guarantees

## Likelihood Explanation

**Attacker Capabilities:**
- Any active miner can exploit this by modifying their block header data
- No special permissions required beyond being in the current miner list
- Single miner can influence LIB calculation (limited by the 2/3+1 consensus rule)
- >1/3 colluding miners can fully control LIB progression

**Attack Complexity:**
- Low: Simply set `ImpliedIrreversibleBlockHeight` to arbitrary values in block headers during block production
- The validation is broken and will always pass
- No cryptographic or computational barriers
- No on-chain transaction required, just modify consensus extra data

**Feasibility Conditions:**
- Miner must be in active rotation (normal consensus operation)
- For significant impact, requires >1/3 miner collusion
- Detection: Malicious values would be visible on-chain but may not trigger alarms without specific monitoring

**Economic Rationality:**
- Attack cost: Minimal (just modify block data during production)
- Potential gain: DoS attack on chain finality, or advance LIB to enable double-spend attacks
- Risk: On-chain evidence of misbehavior, but validation doesn't prevent or punish it

**Overall Likelihood:** Medium to High
- Single miner: Can set arbitrary values, limited impact but possible
- Colluding miners (>1/3): High impact, lower probability in honest majority scenarios but realistic in adversarial conditions or during transition periods when miner set changes

## Recommendation

**Fix the validation order:**

Move the validation BEFORE the state recovery, or validate against the original state before modification:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // Create validation context with UNMODIFIED baseRound
    var validationContext = new ConsensusValidationContext
    {
        BaseRound = baseRound,  // Original state for validation
        CurrentTermNumber = State.CurrentTermNumber.Value,
        CurrentRoundNumber = State.CurrentRoundNumber.Value,
        PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
        LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
        ExtraData = extraData
    };

    // Validate FIRST with original state
    var validationProviders = CreateValidationProviders(extraData.Behaviour);
    var service = new HeaderInformationValidationService(validationProviders);
    var validationResult = service.ValidateInformation(validationContext);
    
    if (!validationResult.Success)
        return validationResult;

    // THEN recover state for processing
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

    if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
        baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

    return new ValidationResult { Success = true };
}
```

**Add additional validations:**

1. Bounds check: `ImpliedIrreversibleBlockHeight <= Context.CurrentHeight`
2. Monotonicity check: Value must not decrease from previous reports
3. Reasonableness check: Value should be within a reasonable range of current LIB

## Proof of Concept

The vulnerability can be demonstrated by tracing the execution flow:

1. Miner produces block with `UpdateValue` behavior
2. Sets `ImpliedIrreversibleBlockHeight` to arbitrary value (e.g., 0 or 999999999) in block header
3. `ValidateBeforeExecution()` is called
4. Line 47: `baseRound.RecoverFromUpdateValue()` copies arbitrary value to baseRound
5. Line 82: `LibInformationValidationProvider` is added to validators
6. Validation runs: Checks if `baseRound[pubkey].ImpliedIrreversibleBlockHeight > providedRound[pubkey].ImpliedIrreversibleBlockHeight`
7. Both values are now equal (due to step 4), so condition is false → validation passes
8. Block executes, line 248 of `ProcessUpdateValue()` stores arbitrary value to state
9. In next round, LIB calculation uses these manipulated values

With >1/3 miners setting low/high values, the sorted list at position `(count-1)/3` will contain the manipulated value, affecting the calculated LIB height.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L22-27)
```csharp
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-33)
```csharp
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
