# Audit Report

## Title
Round Mismatch Causes Miner DoS Due to Missing UpdateValueInput.RoundId Validation

## Summary
The `UpdateValueInput.RoundId` field, explicitly documented to ensure updates apply to the correct round, is never validated against the current round during transaction processing. This causes legitimate miners to lose block production opportunities and mining rewards when round transitions occur between transaction generation and validation.

## Finding Description

The AEDPoS consensus contract contains a critical validation gap in the `UpdateValue` transaction flow. When miners generate consensus transactions, the `UpdateValueInput` includes a `RoundId` field that captures the round number at generation time. [1](#0-0) 

The protobuf specification explicitly documents this field's purpose: [2](#0-1) 

However, this validation is completely absent from the implementation. The `UpdateValueValidationProvider` only validates `OutValue` and `Signature` fields: [3](#0-2) 

Additionally, the `ProcessUpdateValue` method never references the `RoundId` field from the input, as confirmed by code inspection: [4](#0-3) 

**Attack Scenario:**

1. Miner A generates an `UpdateValue` transaction for round N via `GenerateConsensusTransactions`: [5](#0-4) 

2. Before Miner A's transaction is included, another miner produces a `NextRound` or `NextTerm` transaction, advancing the consensus to round N+1

3. Miner A's transaction enters validation, where `ValidateBeforeExecution` fetches the **current** round (now N+1) as `baseRound`: [6](#0-5) 

4. The validation calls `RecoverFromUpdateValue`, which returns early without modifications if the miner's pubkey is not in the current round: [7](#0-6) 

5. The `MiningPermissionValidationProvider` then checks if the sender exists in `baseRound` and fails: [8](#0-7) 

6. Transaction is rejected with "Sender is not a miner", despite being validly generated for round N

## Impact Explanation

This vulnerability causes direct operational and financial harm to legitimate miners:

**Immediate Impact:**
- **Lost Block Production:** The miner loses their assigned time slot and cannot produce a block
- **Reward Forfeiture:** No block production means zero mining rewards for that slot
- **Wasted Resources:** Transaction fees and computational effort spent generating the transaction are lost

**Cascading Impact:**
- **Reputation Damage:** Missed time slots increment the miner's `MissedTimeSlots` counter
- **Evil Miner Risk:** If missed slots exceed `TolerableMissedTimeSlotsCount` (4320 slots = 3 days), the miner is marked as evil and removed from the candidate list: [9](#0-8) [10](#0-9) 

**Affected Miners:**
- Miners during any round transition
- Miners with higher network latency
- All miners during term transitions when miner lists are reconfigured

The severity is **Medium** because while it doesn't cause fund theft, it creates operational DoS with direct financial consequences and potential long-term reputation penalties.

## Likelihood Explanation

This issue has **Medium to High** likelihood because it occurs through natural protocol operations without requiring any attacker:

**Natural Triggers:**
- Round transitions occur regularly based on configured block production intervals
- Term transitions happen periodically and change miner lists
- Network latency naturally causes transaction propagation delays

**High-Risk Windows:**
- During the last time slots of any round when `NextRound` is imminent
- During term changes when miner lists are reconfigured, creating the highest risk for miners not in the new list
- During network congestion when transaction inclusion is delayed

**No Attack Required:**
This is a pure race condition inherent to the system design - the time window between `GenerateConsensusTransactions` (which reads round N) and `ValidateBeforeExecution` (which may read round N+1) creates the vulnerability naturally.

The probability increases proportionally to:
- Network latency between miners
- Frequency of round/term transitions
- Number of miners not retained in subsequent rounds

## Recommendation

Add explicit validation of `UpdateValueInput.RoundId` in the validation flow to implement the documented security guarantee. The fix should be added to `UpdateValueValidationProvider` or as a new dedicated provider:

```csharp
public class UpdateValueValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // NEW: Validate RoundId matches current round
        if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        {
            var updateValueInput = // Extract from transaction
            if (updateValueInput.RoundId != validationContext.BaseRound.RoundIdForValidation)
                return new ValidationResult { 
                    Message = $"UpdateValue RoundId mismatch: expected {validationContext.BaseRound.RoundIdForValidation}, got {updateValueInput.RoundId}" 
                };
        }

        // Existing validations...
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
}
```

Alternatively, implement early rejection with a clearer error message that distinguishes between "miner not authorized" and "transaction for stale round", allowing miners to regenerate transactions for the current round instead of being penalized.

## Proof of Concept

The vulnerability can be demonstrated by creating a test that:

1. Sets up a consensus round with multiple miners
2. Has Miner A call `GenerateConsensusTransactions` to create an `UpdateValue` transaction for round N
3. Has Miner B produce a `NextRound` transaction before Miner A's transaction is processed
4. Attempts to validate Miner A's transaction against the new round N+1
5. Observes the validation failure despite the transaction being legitimately generated

```csharp
[Fact]
public async Task UpdateValue_ShouldFail_WhenRoundAdvancesBeforeValidation()
{
    // Setup: Initialize consensus with Miner A in round 1
    var minerA = InitialMiners[0];
    var currentRound = await GetCurrentRound();
    
    // Step 1: Miner A generates UpdateValue for round 1
    var updateValueInput = currentRound.ExtractInformationToUpdateConsensus(
        minerA.PublicKey.ToHex(), GenerateRandomNumber());
    Assert.Equal(currentRound.RoundIdForValidation, updateValueInput.RoundId);
    
    // Step 2: Another miner advances to round 2 (removing Miner A)
    await ProduceNextRound(excludeMiner: minerA);
    
    // Step 3: Attempt to process Miner A's stale UpdateValue transaction
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(updateValueInput);
    
    // Verify: Transaction fails despite valid generation
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Sender is not a miner");
}
```

The test demonstrates that the `RoundId` field in `UpdateValueInput` is never validated, causing legitimate transactions to fail when round transitions occur.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L40-40)
```csharp
            RoundId = RoundIdForValidation,
```

**File:** protobuf/aedpos_contract.proto (L199-200)
```text
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-146)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-20)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-182)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
```
