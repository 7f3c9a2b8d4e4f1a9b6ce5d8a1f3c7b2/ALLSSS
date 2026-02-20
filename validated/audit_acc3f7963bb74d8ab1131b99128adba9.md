# Audit Report

## Title
Missing OutValue Uniqueness Check Allows Miners to Manipulate Mining Order Through Duplicate UpdateValue Submissions

## Summary
The AEDPoS consensus contract fails to enforce that each miner submits their OutValue commitment exactly once per round. The validation flow calls `RecoverFromUpdateValue` before duplicate checking, which overwrites the original OutValue in BaseRound state, making detection impossible. This allows malicious miners to adaptively change their committed OutValue mid-round after observing other miners' submissions, breaking the consensus randomness guarantee and enabling mining order manipulation.

## Finding Description

The vulnerability exists in the validation pipeline for `UpdateValue` transactions, where the contract does not verify whether a miner has already submitted an OutValue in the current round.

**Root Cause:**

The validation flow in `ValidateBeforeExecution` calls `RecoverFromUpdateValue` on the baseRound **before** any validation occurs: [1](#0-0) 

This method unconditionally overwrites the miner's OutValue in the baseRound: [2](#0-1) 

The validation context is then created using this already-modified baseRound: [3](#0-2) 

The `UpdateValueValidationProvider` checks only that the ProvidedRound contains a non-null OutValue, but cannot detect if the baseRound originally had an OutValue because it was already overwritten: [4](#0-3) 

The only duplicate protection is `EnsureTransactionOnlyExecutedOnceInOneBlock`, which prevents multiple executions in the same **block** but not in the same **round** across different blocks: [5](#0-4) 

During execution, `ProcessUpdateValue` unconditionally overwrites the OutValue in state: [6](#0-5) 

**Expected vs Actual Behavior:**

The client-side consensus behavior provider expects miners to use TinyBlock after their first UpdateValue (when OutValue is already set): [7](#0-6) 

However, this is client-side guidance only and not enforced by contract-side validation. A malicious miner can modify their node to submit multiple UpdateValue transactions in different blocks within the same round.

**Attack Scenario:**

1. Miner A is elected and has their time slot in Round N
2. At block height H, Miner A calls UpdateValue with OutValue_1 (derived from InValue_1)
3. Miner A observes other miners' OutValue submissions in subsequent blocks
4. At block height H+k (still in Round N, within the same time slot), Miner A calls UpdateValue again with OutValue_2 (derived from InValue_2)
5. The second UpdateValue passes all validations because:
   - Different block heights (H vs H+k) so `EnsureTransactionOnlyExecutedOnceInOneBlock` passes
   - `RecoverFromUpdateValue` overwrites BaseRound.OutValue_1 with OutValue_2 before validation
   - `NewConsensusInformationFilled` only checks that OutValue_2 is non-null, not that OutValue_1 already existed
6. Miner A's state now has OutValue_2, allowing them to choose the value that positions them optimally in the next round

## Impact Explanation

**Consensus Integrity Violation - HIGH**

This vulnerability directly undermines a core security property of the AEDPoS consensus mechanism: miners must commit to their randomness contribution (OutValue) before observing others' commitments.

The mining order for the next round is calculated based on the signature value modulo the miner count: [8](#0-7) 

By allowing miners to change their OutValue mid-round, the attacker can:

1. **Manipulate Mining Order**: Generate multiple InValue/OutValue pairs and select the one that positions them favorably in the next round's mining schedule
2. **Break Randomness Guarantees**: The commitment scheme ensures unpredictable ordering. Adaptive commitment breaks this property
3. **Gain Unfair Advantage**: Honest miners commit once and are bound to their choice, while the attacker can optimize based on observed values

This compromises the fairness and security of the consensus mechanism, as mining order determines block production privileges and associated rewards.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood**

**Attack Complexity**: Low
- Attacker needs to be an elected miner (achievable through normal staking and voting)
- Attack requires modifying node software to submit UpdateValue instead of TinyBlock after the first block
- No complex state manipulation or cryptographic breaks required

**Preconditions**: Minimal
- Attacker must be an elected miner (achievable through legitimate election process)
- Must be within their time slot to produce multiple blocks
- No additional privileges required

**Detection**: Difficult
- Duplicate UpdateValue transactions appear valid to on-chain validators
- No event logs or state markers distinguish this from normal operation
- The original OutValue is lost, making forensic analysis difficult

**Economic Rationality**: High
- Attack cost: Minimal (only transaction fees)
- Attack benefit: Favorable mining position in next round, potentially higher block rewards
- Risk: Low (appears as normal consensus operation)

## Recommendation

Add a check in `UpdateValueValidationProvider` to verify that the miner has not already submitted an OutValue in the current round **before** calling `RecoverFromUpdateValue`:

```csharp
// In ValidateBeforeExecution, check BEFORE recovery
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    var minerInRound = baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()];
    if (minerInRound.OutValue != null && minerInRound.OutValue.Value.Any())
    {
        return new ValidationResult 
        { 
            Success = false, 
            Message = "Miner has already submitted OutValue in this round." 
        };
    }
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}
```

Alternatively, add this check within `UpdateValueValidationProvider` by accessing the original baseRound state before recovery.

## Proof of Concept

A PoC would involve:
1. Setting up a test environment with multiple miners
2. Having one miner submit UpdateValue transaction at block H with OutValue_1
3. Having the same miner submit another UpdateValue transaction at block H+1 (same round) with OutValue_2
4. Verifying that both transactions are accepted and the second OutValue overwrites the first
5. Demonstrating that the miner's position in the next round changes based on the final OutValue

The test would verify that no validation failure occurs during the second UpdateValue submission, confirming the missing uniqueness check.

---

**Notes:**

This vulnerability is valid because:
- It affects production consensus contract code in scope
- The execution path is clearly traceable and exploitable
- It breaks a fundamental consensus invariant (binding commitment)
- The attacker role (elected miner) is achievable through normal protocol operation
- The impact directly affects consensus fairness and integrity

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-16)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L245-245)
```csharp
        minerInRound.OutValue = updateValueInput.OutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-62)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
