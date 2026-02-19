### Title
Insufficient Consensus Signature Validation Allows Mining Order Manipulation

### Summary
The `UpdateValueValidationProvider.ValidateHeaderInformation()` validates `OutValue/Signature` presence and `PreviousInValue` consistency independently but fails to verify that `Signature` is correctly calculated using `CalculateSignature()` method. This allows miners to provide arbitrary signature values and manipulate their `SupposedOrderOfNextRound`, corrupting consensus round state and gaining unfair mining advantages.

### Finding Description

The validation logic has two independent checks: [1](#0-0) 

`NewConsensusInformationFilled()` only verifies that `OutValue` and `Signature` fields are non-empty: [2](#0-1) 

`ValidatePreviousInValue()` only validates that `PreviousInValue` hashes to `previousOutValue`: [3](#0-2) 

**Root Cause:** Neither check validates that `Signature` is correctly computed using the protocol-required `CalculateSignature()` method: [4](#0-3) 

The signature directly determines next round's mining order: [5](#0-4) 

During `ProcessUpdateValue`, the unchecked signature and miner-provided `SupposedOrderOfNextRound` are stored directly: [6](#0-5) 

The after-execution validation is ineffective because `RecoverFromUpdateValue` modifies `currentRound` in-place and returns it: [7](#0-6) 

Then compares it with itself: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Compromise:**
- Attackers manipulate `Signature` values to control `SupposedOrderOfNextRound` calculation
- Direct control over mining slot allocation in subsequent rounds
- Breaks consensus fairness and randomness guarantees
- Enables selfish mining strategies and censorship attacks

**Concrete Harms:**
1. Malicious miners consistently secure earlier/preferred time slots
2. Other miners pushed to disadvantageous positions
3. Randomness generation biased toward attacker
4. Block production becomes predictable and exploitable
5. Economic rewards unfairly concentrated

**Severity:** HIGH - Core consensus mechanism integrity violated, enabling sustained manipulation of miner selection and block production order.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner in current round (able to produce blocks)
- Can compute valid `PreviousInValue` from their own previous commitment
- Can submit `UpdateValue` transactions during their time slot

**Attack Complexity:** LOW
- Single-transaction exploit via `UpdateValue` method
- No special timing or race conditions required
- Validation logic has no signature verification

**Feasibility:** HIGH
- Entry point `UpdateValue` is standard consensus operation
- All preconditions (being a miner) are normal operational state
- No special privileges beyond normal miner capabilities required
- Economic cost is negligible (normal transaction fees)

**Detection Difficulty:** 
- Incorrect signatures appear valid to current validation
- No cryptographic signature verification performed
- Off-chain monitoring could detect order manipulation patterns but cannot prevent

### Recommendation

**Immediate Fix:** Add signature correctness validation in `UpdateValueValidationProvider`:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var providedSignature = validationContext.ProvidedRound
        .RealTimeMinersInformation[validationContext.SenderPubkey].Signature;
    
    var expectedSignature = validationContext.PreviousRound
        .CalculateSignature(validationContext.ProvidedRound
            .RealTimeMinersInformation[validationContext.SenderPubkey].PreviousInValue);
    
    return providedSignature == expectedSignature;
}
```

Add to `ValidateHeaderInformation()` before line 19.

**Additional Validations:**
1. Verify `SupposedOrderOfNextRound` matches calculation from `Signature`
2. Fix `ValidateConsensusAfterExecution` to compare independent round copies, not same object
3. Add cryptographic signature over consensus data to prevent tampering

**Test Cases:**
1. Reject `UpdateValue` with arbitrary signature values
2. Reject `SupposedOrderOfNextRound` inconsistent with signature
3. Verify after-execution validation catches state mismatches

### Proof of Concept

**Initial State:**
- Miner M is in current round with `previousOutValue = Hash("correct_invalue")`
- M's previous `InValue = "correct_invalue"`

**Attack Steps:**

1. **Miner M constructs malicious UpdateValue:**
   ```
   UpdateValueInput {
     previous_in_value: Hash("correct_invalue"),  // Valid, passes ValidatePreviousInValue
     out_value: Hash("new_random"),                // Valid (non-empty)
     signature: Hash("MANIPULATED_VALUE"),         // ARBITRARY - not CalculateSignature result
     supposed_order_of_next_round: 1               // Desired position (first slot)
   }
   ```

2. **Validation passes:**
   - `NewConsensusInformationFilled`: ✓ (fields non-empty)
   - `ValidatePreviousInValue`: ✓ (Hash(previous_in_value) == previousOutValue)
   - No signature correctness check exists

3. **State Updated:**
   - `ProcessUpdateValue` stores arbitrary signature
   - `SupposedOrderOfNextRound = 1` stored directly
   - `FinalOrderOfNextRound = 1` assigned

4. **After-Execution Validation:**
   - `RecoverFromUpdateValue` modifies `currentRound` with provided values
   - Comparison: `currentRound.GetHash() == currentRound.GetHash()` ✓ (same object)

**Result:**
- Miner M secures position 1 in next round with manipulated signature
- Expected: Position calculated from correct `CalculateSignature(previous_in_value)`
- Actual: Position 1 as attacker desired
- Consensus round state corrupted with incorrect signature value

### Notes

The vulnerability stems from treating signature as opaque data rather than a cryptographically verifiable commitment. The protocol design includes `CalculateSignature()` for deterministic signature generation, but validation never enforces this calculation. The independent validation of `PreviousInValue` consistency and signature presence creates a gap where mutual consistency between these fields is never verified.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L13-17)
```csharp
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-247)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
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
```
