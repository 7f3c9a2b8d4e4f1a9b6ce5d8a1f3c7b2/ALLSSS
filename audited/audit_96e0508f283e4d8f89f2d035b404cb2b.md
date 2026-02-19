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

1. `EnsureTransactionOnlyExecutedOnceInOneBlock` only checks if `State.LatestExecutedHeight.Value != Context.CurrentHeight`, preventing multiple consensus transactions in the SAME block but not across different blocks in the same round. [6](#0-5) 

2. The consensus behavior provider checks `if (_minerInRound.OutValue == null)` to prevent generating additional UpdateValue commands after OutValue is set, but this only affects automatic command generation and cannot prevent manually crafted transactions. [7](#0-6) 

3. Time slot validation only checks if the miner is within their time slot by comparing the latest actual mining time against the end of the expected time slot, not if they've already updated their OutValue. [8](#0-7) 

4. Permission validation only checks if the sender's public key is in the miner list. [9](#0-8) 

## Impact Explanation

**Consensus Randomness Manipulation:**
The `Signature` field is directly used by the consensus mechanism. During consensus information processing, the system verifies the random number and generates a random hash that's stored in state. [10](#0-9) 

A malicious miner can submit multiple UpdateValue transactions with different `InValue` inputs to generate different signatures, effectively "re-rolling" the random output until they obtain a favorable result for validator selection, reward distribution, or any protocol mechanism relying on this randomness.

**Next Round Order Manipulation:**
The signature and out value are used to calculate the miner's order in subsequent rounds. The system stores `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` based on the submitted consensus data. [11](#0-10) 

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

4. The second transaction overwrites the first submission

**Feasibility Conditions:**
- Mining interval provides sufficient time for multiple blocks (typically 4-8 seconds)
- No additional infrastructure required beyond standard miner capabilities
- Attack leaves clear on-chain evidence but no automatic detection/prevention exists

**Probability: HIGH** - Any malicious miner can execute this attack without special circumstances or race conditions.

## Recommendation

Add a duplicate-submission check in the `UpdateValueValidationProvider` that verifies whether `OutValue` is already set in the ORIGINAL state (before `RecoverFromUpdateValue` is called).

**Proposed Fix:**

1. Modify the validation flow to check the original state before calling `RecoverFromUpdateValue`:

```csharp
// In ValidateBeforeExecution method, before line 47:
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    // Check if OutValue is already set in the original state
    var originalMinerInRound = baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()];
    if (originalMinerInRound.OutValue != null)
    {
        return new ValidationResult 
        { 
            Success = false, 
            Message = "UpdateValue already submitted in this round." 
        };
    }
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}
```

2. Alternatively, modify `UpdateValueValidationProvider` to receive both the original and recovered rounds, and add validation:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    // Check if OutValue was already set in original state
    var originalMinerInRound = validationContext.BaseRoundBeforeRecover.RealTimeMinersInformation[validationContext.SenderPubkey];
    if (originalMinerInRound.OutValue != null)
    {
        return new ValidationResult { Message = "UpdateValue already submitted in this round." };
    }
    
    // Existing validation...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateUpdateValue_ShouldOverwriteConsensusData()
{
    // Arrange: Setup initial round with miner
    var miner = SampleAccount.Accounts.First();
    var minerKeyPair = SampleAccount.KeyPairs.First();
    
    await InitializeConsensusAsync();
    await StartFirstRoundAsync();
    
    // Get current round information
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInRound = currentRound.RealTimeMinersInformation[miner.PublicKey.ToHex()];
    
    // Act 1: Submit first UpdateValue
    var firstInValue = HashHelper.ComputeFrom("first_random_value");
    var firstOutValue = HashHelper.ComputeFrom(firstInValue);
    var firstSignature = HashHelper.ComputeFrom("first_signature");
    
    var firstUpdateInput = new UpdateValueInput
    {
        OutValue = firstOutValue,
        Signature = firstSignature,
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        ImpliedIrreversibleBlockHeight = 1,
        RandomNumber = ByteString.CopyFromUtf8("random1")
    };
    
    await ConsensusStub.UpdateValue.SendAsync(firstUpdateInput);
    
    // Verify first update was stored
    var roundAfterFirst = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerAfterFirst = roundAfterFirst.RealTimeMinersInformation[miner.PublicKey.ToHex()];
    Assert.Equal(firstOutValue, minerAfterFirst.OutValue);
    Assert.Equal(firstSignature, minerAfterFirst.Signature);
    
    // Act 2: Submit second UpdateValue in different block (still within time slot)
    var secondInValue = HashHelper.ComputeFrom("second_random_value");
    var secondOutValue = HashHelper.ComputeFrom(secondInValue);
    var secondSignature = HashHelper.ComputeFrom("second_signature");
    
    var secondUpdateInput = new UpdateValueInput
    {
        OutValue = secondOutValue,
        Signature = secondSignature,
        ActualMiningTime = TimestampHelper.GetUtcNow().AddSeconds(1),
        SupposedOrderOfNextRound = 2,
        ImpliedIrreversibleBlockHeight = 2,
        RandomNumber = ByteString.CopyFromUtf8("random2")
    };
    
    // This should fail but currently succeeds
    await ConsensusStub.UpdateValue.SendAsync(secondUpdateInput);
    
    // Assert: Second update overwrote the first
    var roundAfterSecond = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerAfterSecond = roundAfterSecond.RealTimeMinersInformation[miner.PublicKey.ToHex()];
    
    // VULNERABILITY: OutValue and Signature were overwritten
    Assert.Equal(secondOutValue, minerAfterSecond.OutValue); // Should still be firstOutValue
    Assert.Equal(secondSignature, minerAfterSecond.Signature); // Should still be firstSignature
    Assert.NotEqual(firstOutValue, minerAfterSecond.OutValue); // Proves overwrite occurred
}
```

## Notes

This vulnerability requires the attacker to be a legitimate miner, which means it's a byzantine fault scenario rather than an external attack. However, the consensus mechanism should be resistant to byzantine miners within the fault tolerance threshold. The ability to manipulate consensus randomness and round ordering violates fundamental consensus security properties and could enable various attacks on protocol fairness and security.

The fix should be implemented at the validation layer to maintain defense-in-depth and prevent any possibility of duplicate submissions regardless of how the transaction is constructed or submitted.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-260)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-24)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
