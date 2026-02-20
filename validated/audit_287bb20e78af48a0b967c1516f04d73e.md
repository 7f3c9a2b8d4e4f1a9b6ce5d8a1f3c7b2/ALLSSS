# Audit Report

## Title
Missing Round ID Validation in UpdateValue Allows Consensus State Corruption via Stale Data Application

## Summary
The `UpdateValueInput.RoundId` field is never validated against the current round's ID, despite protobuf documentation explicitly stating it should "ensure the values to update will be apply to correct round by comparing round id." This allows a malicious miner to craft blocks with headers from the current round but transaction payloads from stale rounds, corrupting consensus state by mixing cryptographic values, mining orders, and LIB calculations across round boundaries.

## Finding Description

**Root Cause:**

The `ExtractInformationToUpdateConsensus` method sets the `RoundId` field to `RoundIdForValidation`: [1](#0-0) 

The protobuf specification explicitly documents this field's validation purpose: [2](#0-1) 

However, the `ProcessUpdateValue` method directly applies `UpdateValueInput` fields to the current round without any round ID verification: [3](#0-2) 

**Why Existing Validations Fail:**

The `TimeSlotValidationProvider` only validates the `ProvidedRound` structure in the block header based on the header's round ID, not the transaction payload: [4](#0-3) 

The `UpdateValueValidationProvider` only checks that `OutValue` and `Signature` fields are filled, not their round origin: [5](#0-4) 

Most critically, `ValidateConsensusAfterExecution` has a fundamental flaw in its validation logic. It calls `RecoverFromUpdateValue` which modifies the current round in-place: [6](#0-5) [7](#0-6) 

Since `Round` is a reference type (class) [8](#0-7) , and `RecoverFromUpdateValue` modifies `this` (currentRound) and returns it, both `headerInformation.Round` and `currentRound` reference the same object after recovery. The comparison at lines 100-101 in ValidateConsensusAfterExecution compares the hash of the same object to itself, making the validation ineffective.

**Attack Path:**

A malicious miner can:
1. Save `UpdateValueInput` from round N during normal block production
2. Wait for round transition to N+1  
3. Generate a valid block header with `ProvidedRound` from round N+1 (passes `TimeSlotValidationProvider`)
4. Include the saved `UpdateValueInput` from round N in the transaction payload
5. The block passes validation because validators only check the header, not the transaction's `RoundId`
6. `ProcessUpdateValue` applies round N's stale cryptographic values and ordering data to round N+1's state

## Impact Explanation

**HIGH Severity** - Fundamental consensus integrity violation with chain-wide impact:

1. **Cryptographic Signature Chain Corruption**: The signature and out-value fields from a stale round break the cryptographic chain used for verifiable random number generation, compromising the fairness and unpredictability of future block production order.

2. **Mining Order Manipulation**: The `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` fields control miner scheduling for round N+2. Applying stale values allows the attacker to manipulate which miners produce blocks in future rounds.

3. **LIB Calculation Corruption**: The Last Irreversible Block height calculation depends on `ImpliedIrreversibleBlockHeight` values. Stale data corrupts finality guarantees, potentially allowing double-spend attacks or chain reorganizations.

4. **Consensus State Divergence**: Different nodes may process blocks differently if some detect the anomaly while others don't, leading to chain forks and network instability.

All validators and users are impacted by the corrupted consensus state, affecting the security guarantees of the entire blockchain network.

## Likelihood Explanation

**MEDIUM Likelihood** - Requires specific conditions but is technically feasible:

**Attacker Capabilities:**
- Must be an active miner in both rounds (verified by PreCheck, but this is a legitimate role in the threat model for consensus attacks)
- Must have technical capability to craft custom block headers and transaction payloads

**Attack Complexity:**  
- MODERATE: Attacker needs to intercept and save consensus data from a previous round, then craft a block with mismatched header/transaction
- The miner has full control over block production, making this technically feasible
- No cryptographic binding exists between `ProvidedRound` (header) and `UpdateValueInput.RoundId` (transaction)

**Detection Difficulty:**
- The corrupted data contains valid signatures and values, just from the wrong round
- The unused `RoundId` field indicates validation was intended but never implemented
- The flawed `ValidateConsensusAfterExecution` logic masks the corruption

## Recommendation

Add explicit round ID validation in `ProcessUpdateValue` before applying any updates:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // CRITICAL: Validate round ID matches current round
    Assert(updateValueInput.RoundId == currentRound.RoundId, 
        $"Round ID mismatch: expected {currentRound.RoundId}, got {updateValueInput.RoundId}");
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    // ... rest of the method
}
```

Additionally, fix `ValidateConsensusAfterExecution` to avoid the same-object comparison issue by creating a proper copy before recovery or validating fields directly without mutation.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Capturing an `UpdateValueInput` transaction from round N
2. Advancing the chain to round N+1
3. Crafting a block with:
   - Header containing round N+1 consensus information (passes header validation)
   - Transaction containing the captured round N `UpdateValueInput` (no validation performed)
4. Observing that `ProcessUpdateValue` applies the stale round N data to round N+1 state without any rejection

The key test would verify that `updateValueInput.RoundId` is never checked against `currentRound.RoundId` in the execution path, allowing cross-round data pollution.

## Notes

This vulnerability represents a critical gap in the consensus validation layer where the documented intent (validating round ID) was never implemented. The presence of the `RoundId` field in the protobuf definition with explicit documentation about its validation purpose, combined with the complete absence of such validation in the processing logic, indicates this is a security-critical oversight rather than an intentional design choice.

The broken `ValidateConsensusAfterExecution` method compounds the issue by providing a false sense of security - validators believe post-execution checks will catch anomalies, but the same-object comparison bug renders this protection ineffective for detecting header/transaction mismatches.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-284)
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

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L13-13)
```csharp
public partial class Round
```
