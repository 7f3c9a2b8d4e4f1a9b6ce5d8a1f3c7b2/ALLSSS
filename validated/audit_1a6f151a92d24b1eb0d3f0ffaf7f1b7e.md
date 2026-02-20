# Audit Report

## Title
ImpliedIrreversibleBlockHeight Validation Bypass Due to Premature State Recovery

## Summary
The `LibInformationValidationProvider` validation logic in the AEDPoS consensus contract is fundamentally broken because `RecoverFromUpdateValue` modifies the `baseRound` state before validation occurs. This causes the validation check to compare identical values instead of comparing StateDb values against newly provided values, allowing malicious miners to report artificially low `ImpliedIrreversibleBlockHeight` values without detection. If 1/3+ miners collude, they can stall Last Irreversible Block (LIB) advancement indefinitely.

## Finding Description

The vulnerability exists in the validation flow for UpdateValue consensus behavior. The validation sequence executes as follows:

**1. State Retrieval**: The validation process begins by fetching the current round from StateDb [1](#0-0) 

**2. Premature Recovery**: Before any validation providers are invoked, `RecoverFromUpdateValue` is called on `baseRound` for UpdateValue behavior [2](#0-1) 

**3. State Corruption**: The `RecoverFromUpdateValue` method copies values from `providedRound` into `baseRound`, including the miner's `ImpliedIrreversibleBlockHeight` [3](#0-2) 

**4. Validation Context Creation**: A validation context is created using the now-modified `baseRound` [4](#0-3) 

**5. Broken Validation**: The `LibInformationValidationProvider` is added to validators [5](#0-4)  and attempts to validate that the miner's `ImpliedIrreversibleBlockHeight` hasn't decreased [6](#0-5) 

**Root Cause**: Since `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` was already overwritten with `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` during the recovery phase, the comparison always evaluates identical values. The validation check can never detect a decrease because both sides reference the same value after mutation.

The intended behavior is to compare the original StateDb value (representing the miner's previously reported height) against the new value being provided, rejecting any regression. However, the premature recovery destroys the StateDb baseline before comparison occurs.

## Impact Explanation

**Operational Impact - High Severity**:

**1. LIB Finalization Prevention**: Malicious miners can report artificially low `ImpliedIrreversibleBlockHeight` values without detection. During LIB calculation, these values are sorted and the value at position `(count-1)/3` is selected as the new LIB height [7](#0-6) . If 1/3+ miners collude to provide artificially low values, the calculated LIB will be suppressed indefinitely.

**2. Cross-Chain Operations Disruption**: LIB height is critical for cross-chain verification and merkle proof validation. Stalled LIB prevents parent/side-chain synchronization and cross-chain message processing, breaking the cross-chain ecosystem.

**3. State Management Issues**: LIB determines which blocks can be safely pruned from the state database. Preventing LIB advancement causes unbounded state growth and eventual resource exhaustion on all nodes.

**4. Transaction Finality Delay**: Users cannot achieve finality guarantees on their transactions when LIB is stalled, fundamentally affecting economic activity and user confidence in the blockchain.

While this is a liveness attack rather than a safety violation (LIB cannot decrease due to the check at line 272 of ProcessUpdateValue [8](#0-7) ), the operational impact is severe enough to warrant HIGH severity classification as it can halt the blockchain's ability to finalize transactions.

## Likelihood Explanation

**Medium Likelihood**:

**Attacker Capabilities**: 
- Must be an elected miner in the consensus round (achievable through the election mechanism)
- Can modify consensus extra data before block production. The `ImpliedIrreversibleBlockHeight` is set by the contract [9](#0-8)  and the miner receives this data which they can tamper with before signing and producing the block

**Attack Complexity**: 
- Low complexity for an individual miner to provide false data
- Medium complexity to coordinate 1/3+ miners for significant LIB impact
- No cryptographic protection prevents miners from modifying their own consensus extra data

**Feasibility Conditions**:
- Block validation is sequential, eliminating race conditions
- Post-execution validation also fails to detect tampering since StateDb is already updated with fake values [10](#0-9) 
- No upper-bound validation exists, only the broken lower-bound check

**Detection/Operational Constraints**:
- Attack is detectable through explicit monitoring of individual miner `ImpliedIrreversibleBlockHeight` reports
- Miners have reputation and economic stake at risk through the election mechanism
- However, subtle variations in reported heights may go unnoticed without dedicated monitoring infrastructure

The attack requires malicious intent from elected miners but is technically straightforward to execute once mining permissions are obtained through the election process.

## Recommendation

The fix is to perform validation BEFORE calling `RecoverFromUpdateValue`. The recovery operation should only happen after all validation checks pass. The corrected flow should be:

1. Fetch `baseRound` from StateDb (unchanged)
2. Create validation context with unmodified `baseRound` and `providedRound` from `extraData.Round`
3. Run all validation providers including `LibInformationValidationProvider`
4. Only after validation succeeds, call `RecoverFromUpdateValue` to merge the changes

Alternatively, preserve the original `ImpliedIrreversibleBlockHeight` value before recovery:

```csharp
// In ValidateBeforeExecution method, before line 46:
var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(extraData.SenderPubkey.ToHex())
    ? baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight
    : 0;

// Then pass this value to validation context for comparison
```

The validation provider should then compare `originalImpliedHeight` against `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight`.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus round with multiple miners where one miner has previously reported `ImpliedIrreversibleBlockHeight = 1000`
2. That same miner attempts to produce a block with `ImpliedIrreversibleBlockHeight = 500` (artificially low)
3. Due to the bug, validation passes when it should fail with "Incorrect implied lib height"
4. The artificially low value is stored to state
5. If 1/3+ miners repeat this, LIB calculation stalls at the low reported values

A test would need to mock the consensus round state, simulate a miner providing a decreased `ImpliedIrreversibleBlockHeight`, and verify that the validation incorrectly passes when it should reject the block.

**Notes**

This is a critical consensus integrity issue that breaks an important safety invariant: miners' reported `ImpliedIrreversibleBlockHeight` values should be monotonically non-decreasing. The bug exists because the validation architecture was designed to compare `baseRound` (from StateDb) against `providedRound` (from block header), but the premature recovery operation mutates `baseRound` before validation occurs, causing the comparison to be meaningless. This represents a fundamental flaw in the validation pipeline ordering.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-272)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```
