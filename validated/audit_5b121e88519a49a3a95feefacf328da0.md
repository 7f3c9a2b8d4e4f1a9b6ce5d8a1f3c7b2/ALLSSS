# Audit Report

## Title
Broken ImpliedIrreversibleBlockHeight Validation Allows Malicious LIB Manipulation

## Summary
A critical logic error in the AEDPoS consensus validation flow allows malicious miners to artificially lower their reported `ImpliedIrreversibleBlockHeight` value, bypassing validation checks designed to prevent this. The `RecoverFromUpdateValue` method modifies baseline round data before validation occurs, causing validation to compare a value against itself rather than against stored state. This enables attackers to delay chain finality by manipulating Last Irreversible Block (LIB) calculations.

## Finding Description

The vulnerability exists in the ordering of operations during consensus block validation. When a block with `UpdateValue` behavior is validated, the current round information is first fetched from state as `baseRound`. [1](#0-0) 

For `UpdateValue` behavior, `RecoverFromUpdateValue` is immediately called on `baseRound`, modifying it in-place by copying values from the provided round: [2](#0-1) 

The recovery operation explicitly overwrites the miner's `ImpliedIrreversibleBlockHeight` in `baseRound` with the attacker-provided value: [3](#0-2) 

The validation context is then created using this **already-modified** `baseRound`: [4](#0-3) 

`LibInformationValidationProvider` is added to the validation pipeline: [5](#0-4) 

The validation check compares `baseRound[pubkey].ImpliedIrreversibleBlockHeight` (now equal to the attacker's value) with `providedRound[pubkey].ImpliedIrreversibleBlockHeight`: [6](#0-5) 

**Root Cause**: Since `RecoverFromUpdateValue` executes before validation, the security check effectively becomes `attackerValue > attackerValue`, which is always false, allowing validation to pass regardless of whether the value decreased.

The malicious value is then persisted to state during consensus information processing: [7](#0-6) 

The LIB calculator retrieves implied heights from the previous round for miners who mined in the current round: [8](#0-7) 

And sorts them, taking the value at index `(count-1)/3` (the 1/3 quantile): [9](#0-8) 

Additionally, the same logic error affects `ValidateConsensusAfterExecution`, where the recovery method is called and its result assigned back to the header information before hash comparison: [10](#0-9) 

This causes both objects to reference the same modified data, making the subsequent hash validation ineffective: [11](#0-10) 

## Impact Explanation

**Severity: HIGH**

This vulnerability directly violates consensus finality guarantees, which are fundamental to blockchain security:

1. **Consensus Integrity Violation**: The Last Irreversible Block (LIB) height is calculated using the 1/3 quantile of sorted implied heights from active miners. A maliciously low value in the bottom third of sorted heights directly lowers the calculated LIB.

2. **Delayed Finality**: Lower LIB means blocks take longer to become irreversible, extending the window during which blocks remain reversible.

3. **Cross-Chain Impact**: Cross-chain operations and indexing depend on LIB for determining which blocks are finalized. Manipulated LIB heights create potential for cross-chain inconsistencies.

4. **Double-Spend Window**: Extended reversibility windows enable potential double-spend attack vectors by keeping transactions in a non-final state longer than protocol-intended.

5. **No Cryptographic Protection**: The hash validation that should detect tampering suffers from the same logic error, providing no defense against this attack.

While this doesn't directly result in fund theft, it fundamentally undermines the security model of the blockchain by breaking finality guarantees.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Prerequisites**:
- Must be an active block producer (miner) in the consensus round
- This is a non-trivial but feasible requirement (requires staking and election)

**Attack Complexity: LOW**
- Miners generate consensus extra data where `ImpliedIrreversibleBlockHeight` is normally set to the current block height: [12](#0-11) 

- The miner simply modifies this value in the `UpdateValueInput` message: [13](#0-12) 

- Submit the block with modified consensus data
- The broken validation guarantees success

**Execution Feasibility**:
- No cryptographic barriers prevent modification
- Attack is repeatable across multiple rounds
- Success is guaranteed due to the validation logic error
- No alerting mechanism exists to detect abnormally low values

**Detection Difficulty**: LOW - While the malicious values are stored in state, there's no built-in monitoring for values that are unexpectedly low relative to block heights.

The combination of guaranteed success once prerequisites are met and the significant consensus compromise makes this MEDIUM-HIGH likelihood despite requiring miner access.

## Recommendation

Fix the validation logic by storing the original `baseRound` state before calling `RecoverFromUpdateValue`, then use the original state for validation:

```csharp
// Store original value before recovery
var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(extraData.SenderPubkey.ToHex()) 
    ? baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight 
    : 0;

if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound,
    OriginalImpliedHeight = originalImpliedHeight, // Add this field
    // ... rest of context
};
```

Then modify `LibInformationValidationProvider` to use the original stored value for comparison instead of the modified `baseRound` value.

Similarly, fix `ValidateConsensusAfterExecution` by avoiding the assignment that causes both objects to reference the same data:

```csharp
// Create a copy before recovery to preserve original for hash comparison
var headerRoundCopy = headerInformation.Round.Clone();
currentRound.RecoverFromUpdateValue(headerRoundCopy, headerInformation.SenderPubkey.ToHex());
// Now compare currentRound with headerInformation.Round (original)
```

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a consensus round with an active miner who has previously reported `ImpliedIrreversibleBlockHeight = 1000`
2. Have the miner submit an `UpdateValue` transaction with `ImpliedIrreversibleBlockHeight = 500` (lowered value)
3. Verify that `ValidateConsensusBeforeExecution` returns `Success = true` (validation passes)
4. Verify that the malicious value `500` is persisted to state
5. Verify that subsequent LIB calculations use the lowered value, resulting in a lower calculated LIB than if the proper value had been enforced

The test would confirm that the validation check fails to detect the decreased value due to comparing the value against itself.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-25)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L48-48)
```csharp
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
```
