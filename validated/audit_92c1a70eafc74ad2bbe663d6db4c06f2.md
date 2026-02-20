# Audit Report

## Title
Missing Duplicate UpdateValue Check Allows Consensus Data Overwrite Within Same Round

## Summary
The AEDPoS consensus contract fails to prevent miners from calling `UpdateValue` multiple times within a single round, allowing malicious miners to overwrite their `OutValue` and `Signature` fields. This breaks consensus invariants by enabling manipulation of randomness generation and next-round miner ordering.

## Finding Description

The vulnerability exists in the consensus validation flow where the system fails to verify whether a miner has already submitted their consensus data before allowing an update.

**Root Cause:**

The validation flow calls `RecoverFromUpdateValue()` on the current state BEFORE any duplicate-submission checks occur. [1](#0-0) 

This recovery method unconditionally overwrites the `OutValue` and `Signature` fields regardless of whether these fields were already populated. [2](#0-1) 

The modified baseRound is then used to construct the validation context. [3](#0-2) 

The `UpdateValueValidationProvider` only checks that the provided values are non-null, not whether the ORIGINAL stored state already had these values set. [4](#0-3) 

During execution, `ProcessUpdateValue` again unconditionally overwrites the stored values. [5](#0-4) 

**Why Existing Protections Fail:**

1. `EnsureTransactionOnlyExecutedOnceInOneBlock` only prevents multiple consensus transactions at the SAME block height, not across different blocks within the same round. [6](#0-5) 

2. The consensus behavior provider checks `OutValue == null` to determine whether to generate UpdateValue commands, but this cannot prevent manually crafted transactions submitted directly to the public `UpdateValue` method. [7](#0-6) [8](#0-7) 

3. Time slot validation only verifies the miner is within their allocated time window, not whether they've already submitted UpdateValue. [9](#0-8) 

## Impact Explanation

**Consensus Randomness Manipulation:**
The `Signature` field is directly used in XOR operations to generate consensus randomness. [10](#0-9) 

A malicious miner can submit multiple `UpdateValue` transactions with different `InValue` inputs to generate different signatures, allowing them to "re-roll" the random output until obtaining a favorable result for mechanisms that depend on consensus randomness.

**Next Round Order Manipulation:**
The signature directly determines each miner's position in the next round through modulo arithmetic. [11](#0-10) 

By manipulating their signature value, a malicious miner can control their order in the subsequent round, potentially securing advantageous early positions.

**Secret Sharing Integrity Breach:**
If secret sharing is enabled, the attacker can manipulate encrypted pieces and decrypted pieces through repeated submissions. [12](#0-11) 

This breaks the cryptographic guarantees of the secret sharing mechanism, potentially compromising consensus integrity.

**Severity: HIGH** - Fundamentally breaks consensus invariants including fair randomness generation and deterministic miner ordering.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a legitimate miner with an allocated time slot in the current round
- Can sign transactions with their miner private key  
- Can submit transactions to the network

**Attack Execution:**
1. Miner produces block at height H with `UpdateValue` containing `OutValue_1 = Hash(InValue_1)`
2. Within the same round, miner produces another block at height H+1 with manually crafted `UpdateValue` containing `OutValue_2 = Hash(InValue_2)` where `InValue_2 ≠ InValue_1`
3. The second transaction passes all validations because `RecoverFromUpdateValue` has already modified the validation state
4. The execution unconditionally overwrites the first submission

**Feasibility:**
- Mining intervals typically provide sufficient time for multiple blocks within a time slot
- No special infrastructure required beyond standard miner node setup
- The `UpdateValue` method is publicly accessible

**Probability: HIGH** - Any malicious miner in the active set can execute this attack during their allocated time slot without special conditions or race requirements.

## Recommendation

Add a check in `UpdateValueValidationProvider` to verify that the miner has not already submitted consensus data in the current round:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // Check provided round has non-null values
    if (minerInRound.OutValue == null || minerInRound.Signature == null ||
        !minerInRound.OutValue.Value.Any() || !minerInRound.Signature.Value.Any())
        return false;
    
    // NEW: Check that the base round (from storage) doesn't already have these values set
    var baseRoundMiner = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    if (baseRoundMiner.OutValue != null && baseRoundMiner.OutValue.Value.Any())
        return false; // Already submitted UpdateValue in this round
        
    return true;
}
```

Additionally, consider adding round-based tracking in `EnsureTransactionOnlyExecutedOnceInOneBlock` to prevent multiple UpdateValue calls within the same round, not just the same block.

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateUpdateValueInSameRound_ShouldOverwriteConsensusData()
{
    // Setup: Initialize consensus with a miner in round 1
    var miner = SampleAccount.Accounts[0];
    var initialRound = GenerateRoundWithMiner(miner.PublicKey);
    await InitializeConsensus(initialRound);
    
    // Attack Step 1: Miner submits first UpdateValue at block height H
    var inValue1 = Hash.FromString("input_1");
    var outValue1 = Hash.FromMessage(inValue1);
    var signature1 = GenerateSignature(inValue1);
    
    await SubmitUpdateValue(miner, inValue1, outValue1, signature1);
    
    // Verify first submission stored
    var round1 = await GetCurrentRound();
    var minerInfo1 = round1.RealTimeMinersInformation[miner.PublicKey.ToHex()];
    minerInfo1.OutValue.ShouldBe(outValue1);
    minerInfo1.Signature.ShouldBe(signature1);
    
    // Attack Step 2: Same miner submits second UpdateValue at block height H+1 (same round)
    var inValue2 = Hash.FromString("input_2_malicious");
    var outValue2 = Hash.FromMessage(inValue2);
    var signature2 = GenerateSignature(inValue2);
    
    // This should fail but doesn't due to missing validation
    await SubmitUpdateValue(miner, inValue2, outValue2, signature2);
    
    // Verify second submission OVERWROTE the first (vulnerability demonstrated)
    var round2 = await GetCurrentRound();
    var minerInfo2 = round2.RealTimeMinersInformation[miner.PublicKey.ToHex()];
    minerInfo2.OutValue.ShouldBe(outValue2); // Values were overwritten!
    minerInfo2.Signature.ShouldBe(signature2);
    
    // Impact: Miner can manipulate their next round order
    var nextRoundOrder = (signature2.ToInt64() % round2.RealTimeMinersInformation.Count) + 1;
    // Attacker can choose favorable position by trying different InValue inputs
}
```

## Notes

This vulnerability is particularly severe because:

1. **No detection**: The overwrite happens silently with no failed validations or events
2. **Economic incentive**: Miners can optimize their position in subsequent rounds for higher rewards
3. **Randomness compromise**: Affects all protocol features that depend on consensus randomness
4. **Cryptographic violation**: Breaks secret sharing guarantees if enabled

The root cause is the architectural decision to call `RecoverFromUpdateValue` before validation, combined with the lack of duplicate-submission tracking at the round level (only at the block height level).

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-296)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
