# Audit Report

## Title
ImpliedIrreversibleBlockHeight Validation Bypass via RecoverFromUpdateValue State Mutation

## Summary
The `LibInformationValidationProvider` validation for `ImpliedIrreversibleBlockHeight` is completely bypassed because `RecoverFromUpdateValue` modifies the base round in-place before validation occurs. This allows malicious miners to report arbitrarily low implied LIB heights, enabling manipulation of consensus finality.

## Finding Description

The validation mechanism designed to prevent miners from reporting decreasing `ImpliedIrreversibleBlockHeight` values is defeated by a critical order-of-operations flaw in the validation pipeline.

**Vulnerable Execution Flow:**

When processing `UpdateValue` behavior during block validation, the system first fetches the current round information from state into `baseRound`. [1](#0-0) 

Before any validation occurs, the code calls `RecoverFromUpdateValue` on this `baseRound` object, passing the provided round data from the block header. [2](#0-1) 

The `RecoverFromUpdateValue` method modifies `baseRound` **in-place** by directly overwriting the miner's `ImpliedIrreversibleBlockHeight` field with the attacker-provided value. [3](#0-2) 

This modified `baseRound` (now containing the malicious value) is then passed into the validation context. [4](#0-3) 

The `LibInformationValidationProvider` is added to validate the implied LIB height. [5](#0-4) 

When `LibInformationValidationProvider` executes its validation check, it compares `baseRound[pubkey].ImpliedIrreversibleBlockHeight` against `providedRound[pubkey].ImpliedIrreversibleBlockHeight`. [6](#0-5) 

However, since `RecoverFromUpdateValue` already overwrote `baseRound[pubkey].ImpliedIrreversibleBlockHeight` with the provided value, this check becomes `providedValue > providedValue`, which is always false, causing the validation to always pass regardless of whether the value actually decreased.

The malicious low value then gets permanently written to state during execution. [7](#0-6) 

## Impact Explanation

**Consensus Finality Manipulation:**

The corrupted `ImpliedIrreversibleBlockHeight` values directly feed into the Last Irreversible Block (LIB) calculation mechanism. [8](#0-7) 

The LIB calculator sorts all miners' implied heights and selects the value at position `(count-1)/3`, effectively implementing a 2/3+ consensus threshold. If 1/3 or more colluding miners inject artificially low `ImpliedIrreversibleBlockHeight` values, they can poison the sorted array at critical positions, causing:

1. **LIB Freeze/Regression**: The calculated LIB will stall or move backwards, violating the fundamental consensus invariant that finality must monotonically advance
2. **Cross-Chain Security Breakdown**: Cross-chain bridges and sidechains rely on LIB for irreversibility guarantees - a manipulated LIB breaks these security assumptions
3. **Application Disruption**: DApps depending on transaction finality cannot confirm settlements reliably
4. **Economic Impact**: Time-sensitive operations, token locks, and financial instruments requiring finality guarantees become unreliable

**Severity: HIGH** - This directly compromises the consensus finality mechanism, which is a critical security invariant of the blockchain protocol.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an elected miner in the current round (achievable through normal staking/election process)
- Can construct consensus extra data with arbitrary `ImpliedIrreversibleBlockHeight` values (standard block production capability)

**Attack Complexity: LOW**
- Single malicious miner can exploit the validation bypass immediately
- No complex transaction sequences or timing requirements
- Direct exploitation through normal block production flow
- Validation is automatically bypassed due to the structural flaw

**Feasibility: HIGH**
- No special privileges beyond standard miner status required
- Attack cost equals normal block production cost
- Detection is difficult as blocks appear structurally valid
- No on-chain evidence of manipulation (looks like legitimate consensus data)

For coordinated attacks with 1/3+ colluding miners, the impact scales dramatically to completely freeze consensus finality advancement, which could halt the entire blockchain's ability to achieve irreversibility.

## Recommendation

The validation must occur **before** state mutation. The fix requires changing the order of operations in `ValidateBeforeExecution`:

**Current (vulnerable) flow:**
1. Fetch `baseRound` from state
2. Call `RecoverFromUpdateValue` (mutates `baseRound`)
3. Create validation context with mutated `baseRound`
4. Run validation (compares mutated value against itself)

**Fixed flow:**
1. Fetch `baseRound` from state (preserve original)
2. Create validation context with **original unmutated** `baseRound`
3. Run validation (compares original against provided value)
4. Only if validation passes, then apply `RecoverFromUpdateValue`

Alternatively, create a deep copy of `baseRound` before calling `RecoverFromUpdateValue`, ensuring the validation context receives the original state values for comparison.

The key principle: **validation must compare original state against proposed changes, not modified state against itself**.

## Proof of Concept

A malicious miner can exploit this vulnerability through the following attack flow:

1. Miner produces a block with `UpdateValue` behavior
2. In the consensus extra data, miner sets `ImpliedIrreversibleBlockHeight` to an arbitrarily low value (e.g., value much lower than current legitimate value)
3. During `ValidateBeforeExecution`:
   - `baseRound` is fetched with legitimate high value
   - `RecoverFromUpdateValue` overwrites it with low malicious value
   - `LibInformationValidationProvider` validation check becomes: `lowValue > lowValue` = false (passes)
4. Block is accepted and malicious low value is written to state
5. In subsequent LIB calculations, this low value poisons the sorted array at position `(count-1)/3`
6. With 1/3+ colluding miners doing this, the LIB calculation uses these low values, freezing or regressing the LIB

To verify this vulnerability, examine the execution flow in `AEDPoSContract_Validation.cs` where `RecoverFromUpdateValue` is called at line 47 before the validation context is created at lines 52-60, then trace how `LibInformationValidationProvider` at lines 23-26 compares the already-mutated `baseRound` against the `providedRound`.

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
