# Audit Report

## Title
Missing Duplicate UpdateValue Check Allows Consensus Data Overwrite Within Same Round

## Summary
The AEDPoS consensus contract lacks validation to prevent a miner from calling `UpdateValue` multiple times within the same round. The validation logic calls `RecoverFromUpdateValue` before checking if `OutValue` is already set in state, allowing a malicious miner to overwrite their previously submitted consensus data and manipulate consensus randomness and next-round ordering.

## Finding Description

The vulnerability exists in the consensus validation flow where miners can submit multiple `UpdateValue` transactions for the same pubkey within a single round, with each subsequent submission overwriting previous values.

**Root Cause:**

During validation, when the behavior is `UpdateValue`, the system calls `RecoverFromUpdateValue` on the `baseRound` (current state) BEFORE any duplicate-check validation occurs. [1](#0-0) 

This method unconditionally overwrites the `OutValue` and `Signature` fields in the baseRound with values from the provided round. [2](#0-1) 

The modified baseRound is then used to construct the validation context. [3](#0-2) 

The `UpdateValueValidationProvider` only checks that the provided values are non-null, not whether values were already set in the original state. [4](#0-3) 

When the transaction executes, `ProcessUpdateValue` unconditionally overwrites the stored values. [5](#0-4) 

**Why Existing Protections Fail:**

1. `EnsureTransactionOnlyExecutedOnceInOneBlock` only checks if the current height differs from the latest executed height, preventing multiple consensus transactions in the SAME block but not across different blocks in the same round. [6](#0-5) 

2. The consensus behavior provider checks `if (_minerInRound.OutValue == null)` to prevent generating additional UpdateValue commands after OutValue is set, but this only affects automatic command generation via `GetConsensusCommand` and cannot prevent manually crafted transactions submitted directly to the `UpdateValue` RPC method. [7](#0-6) 

3. Time slot validation only checks if the miner is within their time slot by comparing the latest actual mining time against the end of the expected time slot, not if they've already updated their OutValue. [8](#0-7) 

4. Permission validation only checks if the sender's public key is in the miner list. [9](#0-8) 

## Impact Explanation

**Consensus Randomness Manipulation:**
The `Signature` field is directly used by the consensus mechanism. During consensus information processing, the system verifies the random number using ECVrfVerify and generates a random hash that's stored in state. [10](#0-9) 

A malicious miner can submit multiple UpdateValue transactions with different `InValue` inputs to generate different signatures, effectively "re-rolling" the random output until they obtain a favorable result for validator selection, reward distribution, or any protocol mechanism relying on this randomness.

**Next Round Order Manipulation:**
The signature is used to calculate the miner's order in subsequent rounds. The system calculates `SupposedOrderOfNextRound` by taking the signature's int64 value modulo the miners count. [11](#0-10) 

By manipulating their signature, a malicious miner can control their position in the next round, potentially gaining first-mover advantages or avoiding unfavorable positions.

**Secret Sharing Integrity Breach:**
If secret sharing is enabled, the system performs secret sharing operations including adding encrypted pieces and decrypted pieces to the round information. [12](#0-11) 

An attacker can manipulate revealed in-values and encrypted pieces, which could break the cryptographic guarantees of the secret sharing mechanism and compromise consensus integrity.

**Severity: HIGH** - Breaks fundamental consensus invariants including randomness integrity and fair miner ordering.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a legitimate miner with an allocated time slot in the current round
- Can sign transactions with their miner key
- Can submit transactions directly to the network

**Attack Complexity: LOW**

The attack path is straightforward:
1. Miner produces their first block at time T with `UpdateValue` containing `OutValue_1 = Hash(InValue_1)`. The `UpdateValue` method is a public entry point. [13](#0-12) 

2. Within the same time slot (before T + mining_interval), miner produces another block at T+Δ with `UpdateValue` containing `OutValue_2 = Hash(InValue_2)` where `InValue_2 ≠ InValue_1`

3. The second transaction passes all validations because:
   - It's in a different block (different height), so `EnsureTransactionOnlyExecutedOnceInOneBlock` passes
   - The time slot validation passes as the miner is still within their allocated time
   - No validator checks if OutValue was already set in the original state
   - The validation context contains the already-modified baseRound after `RecoverFromUpdateValue` is called

4. The second transaction overwrites the first submission

**Feasibility Conditions:**
- Mining interval provides sufficient time for multiple blocks (typically 4-8 seconds)
- No additional infrastructure required beyond standard miner capabilities
- Attack leaves clear on-chain evidence but no automatic detection/prevention exists

**Probability: HIGH** - Any malicious miner can execute this attack without special circumstances or race conditions.

## Recommendation

Add a duplicate check in the validation flow before calling `RecoverFromUpdateValue`. The validation should check if `OutValue` is already set in the original state before allowing the update.

**Recommended Fix:**

In `AEDPoSContract_Validation.cs`, before line 47, add a check:

```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    // Check if OutValue is already set in the original state
    var minerInRound = baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()];
    if (minerInRound.OutValue != null && minerInRound.OutValue.Value.Any())
    {
        return new ValidationResult 
        { 
            Success = false, 
            Message = "OutValue has already been set for this miner in the current round." 
        };
    }
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}
```

This ensures the validation fails if a miner attempts to submit UpdateValue multiple times within the same round, preserving the integrity of consensus randomness and next-round ordering.

## Proof of Concept

A complete test demonstrating this vulnerability would require:

1. Setup a test environment with multiple miners in a round
2. Have a miner call `UpdateValue` with `InValue_1` and `OutValue_1 = Hash(InValue_1)`
3. Verify the values are stored in state
4. In a subsequent block (but same round and within time slot), have the same miner call `UpdateValue` again with `InValue_2` and `OutValue_2 = Hash(InValue_2)` where `InValue_2 ≠ InValue_1`
5. Verify the second transaction succeeds (does not revert)
6. Verify the stored `OutValue` and `Signature` have been overwritten with the second submission's values
7. Demonstrate that the `SupposedOrderOfNextRound` changes based on the new signature
8. Demonstrate that the `RandomHash` stored in state is affected by the new signature

The test would confirm that no validation prevents the overwrite and that critical consensus data can be manipulated within the same round.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-17)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L29-32)
```csharp
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-248)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-50)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
