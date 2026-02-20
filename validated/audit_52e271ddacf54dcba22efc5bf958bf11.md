# Audit Report

## Title
LibInformationValidationProvider Bypass Through Pre-Validation State Modification

## Summary
The `LibInformationValidationProvider` monotonicity check is completely bypassed because `RecoverFromUpdateValue` modifies the `baseRound` object before validation occurs. This allows malicious consensus miners to report artificially low `ImpliedIrreversibleBlockHeight` values, potentially delaying Last Irreversible Block (LIB) advancement and affecting consensus finality guarantees.

## Finding Description

The vulnerability exists in the validation flow for consensus `UpdateValue` transactions. The root cause is an ordering issue where state modification occurs before validation.

**Vulnerable Flow:**

1. `ValidateBeforeExecution` fetches `baseRound` from state [1](#0-0) 

2. For `UpdateValue` behavior, it calls `baseRound.RecoverFromUpdateValue()` which modifies the object in-place [2](#0-1) 

3. Inside `RecoverFromUpdateValue`, the method directly overwrites `ImpliedIrreversibleBlockHeight` with the provided value [3](#0-2) 

4. A validation context is created using the already-modified `baseRound` [4](#0-3) 

5. `LibInformationValidationProvider` is added to validators for `UpdateValue` behavior [5](#0-4) 

6. The validator attempts to check monotonicity by comparing `baseRound` and `providedRound` values [6](#0-5) 

However, since `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` was already set equal to `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` in step 3, the check becomes `X > X`, which always evaluates to false. The validation never rejects decreasing values. The validation service executes all providers sequentially [7](#0-6) , but by this point the damage is done—the validator is comparing the modified baseRound against the provided values that were just copied into it.

The low value then gets persisted to state during `ProcessUpdateValue` [8](#0-7) 

## Impact Explanation

**Consensus Finality Degradation:**

The `ImpliedIrreversibleBlockHeight` values are critical for calculating the Last Irreversible Block (LIB). The LIB calculator retrieves implied heights from the previous round for miners who mined in the current round [9](#0-8) , sorts them, and selects the value at position `(count-1)/3` as the LIB height [10](#0-9) 

**Specific Harms:**

1. **Delayed Finality**: If one or more miners report artificially low values, they drag down the median calculation at the `(count-1)/3` position, preventing proper LIB advancement. This delays block finalization across the network.

2. **Cross-Chain Impact**: LIB height is used for cross-chain transaction verification and finality guarantees. Delayed LIB affects cross-chain operations that depend on irreversibility confirmations.

3. **Consensus Integrity Violation**: The vulnerability completely disables the monotonicity invariant that `ImpliedIrreversibleBlockHeight` should never decrease. This is a fundamental consensus safety property.

4. **No Direct Fund Loss**: While this doesn't directly steal funds, it affects the core security property of consensus finality, which underpins all blockchain operations.

**Severity**: Medium-High - Consensus finality is a critical security property. The complete bypass of a monotonicity check represents a significant consensus integrity issue.

## Likelihood Explanation

**Attacker Capabilities:**
- Must be a consensus miner (privileged role but explicitly within AElf's threat model)
- No additional permissions required beyond normal mining operations
- Can execute during normal block production via `UpdateValue` consensus transactions

**Attack Complexity:**
- Trivial execution: Simply provide a lower `ImpliedIrreversibleBlockHeight` value when producing blocks
- No race conditions or timing requirements
- Deterministic bypass due to the design flaw
- Low economic cost (normal mining operations)

**Feasibility:**
- Directly reachable through the normal `UpdateValue` consensus transaction flow
- No complex preconditions
- Validation bypass is automatic and guaranteed

**Detection Challenges:**
- Requires monitoring historical `ImpliedIrreversibleBlockHeight` values per miner across rounds
- Not immediately detectable without cross-round comparison
- Could appear as network latency or "slow" miner behavior rather than malicious activity

**Probability**: High likelihood if a miner becomes malicious, as the attack is trivial to execute and provides strategic advantages in controlling finality timing.

## Recommendation

Fix the ordering issue by performing validation BEFORE modifying the baseRound object. The corrected flow should be:

1. Fetch `baseRound` from state (unchanged)
2. Create validation context with the UNMODIFIED `baseRound`
3. Run all validation providers (including `LibInformationValidationProvider`)
4. Only if validation passes, then call `RecoverFromUpdateValue` to update the state
5. Proceed with `ProcessUpdateValue`

Alternatively, the `LibInformationValidationProvider` should retrieve the original value directly from state rather than from the validation context's `baseRound`, or the validation context should maintain separate references to both the original and modified rounds.

## Proof of Concept

The vulnerability is demonstrated by the code flow itself:

1. A miner with `ImpliedIrreversibleBlockHeight = 1000` in the current round
2. Submits an `UpdateValue` with `ImpliedIrreversibleBlockHeight = 500` (maliciously low)
3. `ValidateBeforeExecution` fetches baseRound (contains 1000)
4. `RecoverFromUpdateValue` overwrites baseRound's value to 500
5. `LibInformationValidationProvider` checks: `500 > 500` → false (validation passes incorrectly)
6. Value 500 is persisted to state
7. Future LIB calculations use 500 instead of enforcing monotonic increase

The monotonicity check that should reject this (baseRound value > provided value) becomes meaningless because both sides of the comparison now contain the same value due to the premature modification.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L82-82)
```csharp
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-26)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L18-23)
```csharp
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```
