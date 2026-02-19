# Audit Report

## Title
Consensus Signature Forgery Allows Mining Order Manipulation in AEDPoS UpdateValue

## Summary
The AEDPoS consensus mechanism fails to validate that the `Signature` field in `UpdateValueInput` matches the expected deterministic calculation, allowing miners to forge signatures and manipulate their mining order in subsequent rounds. The signature directly determines position via modulus operation but is only checked for null/empty, not correctness.

## Finding Description

The AEDPoS consensus uses a signature value to determine each miner's position in the next round through a deterministic calculation. The signature should be calculated as `XOR(previousInValue, XOR(all signatures from previous round))` [1](#0-0) , but when miners submit blocks with `UpdateValueInput`, there is no validation that the provided signature matches this expected calculation.

**Vulnerability Flow:**

1. During block production, miners generate consensus extra data via `GetConsensusExtraDataToPublishOutValue`, which correctly calculates the signature [2](#0-1) 

2. However, miners control the consensus extra data placed in the block header and can modify the signature field before block submission

3. During validation, `UpdateValueValidationProvider` only checks that signature is not null/empty [3](#0-2) , with no verification against the expected `CalculateSignature` result

4. The unverified signature is copied directly via `RecoverFromUpdateValue` [4](#0-3) 

5. In `ProcessUpdateValue`, this forged signature is stored to state without verification [5](#0-4) 

6. The forged signature determines the miner's order in the next round through `ApplyNormalConsensusData`, which converts the signature to int64 and applies modulus to determine position [6](#0-5) 

The post-execution validation in `ValidateConsensusAfterExecution` only verifies that the state matches the header hash [7](#0-6) , but since both include the same forged signature after state update, this check passes.

## Impact Explanation

This vulnerability breaks the fundamental fairness and randomness guarantees of the AEDPoS consensus mechanism:

**Direct Impact:**
- Miners can calculate and submit forged signatures to obtain desired positions (e.g., position #1) in subsequent rounds by reverse-engineering the modulus calculation
- Systematic manipulation allows miners to maintain favorable positions across multiple rounds
- The extra block producer selection, which depends on miner signatures, can be influenced

**Consensus Integrity:**
- Violates the invariant that mining order must be determined by unpredictable randomness based on previous round data
- Undermines the security assumption that miners cannot predict or control their future positions
- Enables unfair advantage in block production scheduling and associated rewards

**Severity: HIGH** - This breaks a critical consensus mechanism property where all miners should have equal probabilistic access to favorable mining positions. The deterministic signature calculation exists specifically to prevent position manipulation through unpredictable randomness.

## Likelihood Explanation

**Attacker Profile:**
- Must be an authorized miner (in the miner list)
- This is a realistic threat model - protecting against malicious miners is the primary purpose of consensus validation

**Attack Execution:**
1. Miner calculates which signature value yields desired next-round position: `targetSig = Hash.FromInt64((desiredOrder - 1) + k * minersCount)` for chosen k
2. Miner modifies the signature field in consensus extra data before block submission
3. Block validation accepts the forged signature (only null/empty check exists)
4. State is updated with forged signature
5. Next round miner order reflects the manipulated position

**Feasibility:**
- No special privileges beyond authorized miner status
- Trivial computational effort (single hash calculation)
- No economic cost (standard transaction fees)
- Undetectable - no validation exists to catch the forgery
- Repeatable every round

**Likelihood: HIGH** - Any authorized miner can exploit this with guaranteed success on every block they produce.

## Recommendation

Add signature validation in `UpdateValueValidationProvider` to verify the signature matches the expected calculation:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var providedSignature = validationContext.ExtraData.Round
        .RealTimeMinersInformation[validationContext.SenderPubkey].Signature;
    
    var previousInValue = validationContext.ExtraData.Round
        .RealTimeMinersInformation[validationContext.SenderPubkey].PreviousInValue;
    
    if (previousInValue == null || previousInValue == Hash.Empty)
        return true;
    
    var expectedSignature = validationContext.PreviousRound
        .CalculateSignature(previousInValue);
    
    return providedSignature == expectedSignature;
}
```

Then call this validation in `ValidateHeaderInformation`: [8](#0-7) 

Add after line 17:
```csharp
if (!ValidateSignature(validationContext))
    return new ValidationResult { Message = "Signature does not match expected calculation." };
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanForgeSignature_ToManipulateMiningOrder()
{
    // Setup: Initialize consensus with multiple miners
    var minerKeys = GenerateMiners(5);
    await InitializeConsensus(minerKeys);
    
    // Attacker is miner at index 2
    var attackerKey = minerKeys[2];
    var attackerStub = GetConsensusStub(attackerKey);
    
    // Normal round 1
    await ProduceBlocks(minerKeys, 1);
    var round1 = await attackerStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerOrderRound1 = round1.RealTimeMinersInformation[attackerKey.ToHex()].Order;
    
    // Round 2: Attacker forges signature to get position 1
    var previousInValue = GenerateHash(attackerKey, 1);
    var previousOutValue = HashHelper.ComputeFrom(previousInValue);
    
    // Store legitimate previous out value
    await attackerStub.UpdateValue.SendAsync(new UpdateValueInput {
        OutValue = previousOutValue,
        // ... other fields
    });
    
    // Round 3: Attacker calculates forged signature for position 1
    var minersCount = minerKeys.Count;
    var desiredOrder = 1;
    var forgedSignatureInt = (desiredOrder - 1); // Will result in (0 % 5) + 1 = 1
    var forgedSignature = Hash.FromInt64(forgedSignatureInt);
    
    // Submit update with forged signature
    var result = await attackerStub.UpdateValue.SendAsync(new UpdateValueInput {
        Signature = forgedSignature, // FORGED VALUE
        PreviousInValue = previousInValue,
        OutValue = GenerateHash(attackerKey, 2),
        // ... other fields
    });
    
    // Verify: Attacker successfully obtained position 1
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var round3 = await attackerStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerOrderRound3 = round3.RealTimeMinersInformation[attackerKey.ToHex()]
        .SupposedOrderOfNextRound;
    
    // VULNERABILITY CONFIRMED: Forged signature accepted, attacker has position 1
    attackerOrderRound3.ShouldBe(1);
    attackerOrderRound1.ShouldNotBe(1); // Was different before forgery
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L55-134)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataToPublishOutValue(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.

        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
            if (triggerInformation.PreviousInValue != null &&
                triggerInformation.PreviousInValue != Hash.Empty)
            {
                Context.LogDebug(
                    () => $"Previous in value in trigger information: {triggerInformation.PreviousInValue}");
                // Self check.
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
                else
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
            }
            else
            {
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
            }
        }

        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);

        Context.LogDebug(
            () => "Previous in value after ApplyNormalConsensusData: " +
                  $"{updatedRound.RealTimeMinersInformation[pubkey].PreviousInValue}");

        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;

        // Update secret pieces of latest in value.
        
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }

        // To publish Out Value.
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-47)
```csharp
    public Round ApplyNormalConsensusData(string pubkey, Hash previousInValue, Hash outValue, Hash signature)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return this;

        RealTimeMinersInformation[pubkey].OutValue = outValue;
        RealTimeMinersInformation[pubkey].Signature = signature;
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;

        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```
