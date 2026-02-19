### Title
Missing Signature Validation in UpdateValue Allows Mining Order Manipulation and Signature Chain Corruption

### Summary
The `RecoverFromUpdateValue()` function copies the miner's signature without validating it matches the expected cryptographic calculation. This allows any miner to submit an arbitrary signature value, manipulate their mining order in subsequent rounds, and corrupt the cryptographic signature chain used for consensus randomness and fairness.

### Finding Description

**Root Cause**: The signature field is copied without cryptographic verification at multiple points in the validation and execution flow.

In `RecoverFromUpdateValue()`, the signature is directly copied from provided input: [1](#0-0) 

This function is called during validation before execution: [2](#0-1) 

The validation provider only checks that signature is non-null and non-empty, not that it matches the expected calculation: [3](#0-2) 

During transaction execution, the signature is again directly assigned without validation: [4](#0-3) 

**Expected Calculation**: The signature should be computed as: [5](#0-4) 

This calculation XORs the previousInValue with all signatures from the previous round, creating a cryptographic chain. The correct calculation is shown here: [6](#0-5) 

**Why Protections Fail**: The validation only verifies that `hash(previousInValue) == previousOutValue`, but never verifies that the signature matches `previousRound.CalculateSignature(previousInValue)`: [7](#0-6) 

### Impact Explanation

**Mining Order Manipulation**: The unchecked signature value is converted to an integer and used to determine the miner's position in the next round: [8](#0-7) 

An attacker can choose a signature value that results in `order = 1`, guaranteeing they mine first in the next round. This grants unfair advantages including:
- First access to transaction fees
- Control over transaction ordering
- Ability to front-run other transactions
- Increased block production rewards

**Signature Chain Corruption**: Since `CalculateSignature` aggregates all miner signatures through XOR operations, a single corrupted signature pollutes all future calculations: [9](#0-8) 

This breaks the consensus randomness mechanism, as future miners' signatures will be calculated based on the corrupted chain, compromising the unpredictability and fairness of the entire consensus protocol.

**Severity**: Critical - Directly undermines consensus integrity, enables unfair mining advantages, and breaks cryptographic security guarantees.

### Likelihood Explanation

**Attacker Capabilities**: Any active miner in the consensus can exploit this vulnerability. No special privileges beyond being in the miner list are required.

**Attack Complexity**: Low. The attacker simply needs to:
1. Calculate what signature value (when converted to int64) will yield their desired mining order
2. Submit an UpdateValue transaction with that arbitrary signature value
3. The value passes all current validations

**Feasibility Conditions**: 
- Attacker must be an authorized miner (can produce blocks)
- No detection mechanisms exist since arbitrary signatures pass validation
- Attack is repeatable every round

**Execution Practicality**: The attack executes through the normal `UpdateValue` transaction flow. The signature field is a simple Hash type with no cryptographic verification: [10](#0-9) 

**Economic Rationality**: The attack cost is negligible (just transaction fees), while benefits include guaranteed first mining position, maximized rewards, and ability to front-run transactions.

**Probability**: High - The vulnerability is easily discoverable and exploitable by any miner with basic understanding of the codebase.

### Recommendation

Add signature validation in `UpdateValueValidationProvider.ValidateHeaderInformation()`:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;
    
    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true;
    
    var providedSignature = extraData.Round.RealTimeMinersInformation[publicKey].Signature;
    var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    
    if (previousInValue == null || previousInValue == Hash.Empty) 
        return true;
    
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
    return providedSignature == expectedSignature;
}
```

Call this validation method in `ValidateHeaderInformation()` after the existing checks: [11](#0-10) 

**Test Cases**:
1. Test that UpdateValue with incorrect signature is rejected
2. Test that UpdateValue with correct signature is accepted
3. Test that mining order cannot be manipulated through signature values
4. Test that signature chain remains consistent across multiple rounds

### Proof of Concept

**Initial State**:
- Blockchain has multiple miners in active consensus
- Attacker is miner with pubkey `ATTACKER_PUBKEY`
- Current round is N, previous round is N-1

**Attack Steps**:

1. **Calculate Target Signature**: Attacker wants order=1 in next round. They calculate: `targetSignature = Hash.FromInt64(minersCount * k + 1)` for some k

2. **Submit Malicious UpdateValue**: Attacker produces a block and submits UpdateValue with:
   - Correct `OutValue` = hash(InValue)  
   - Correct `PreviousInValue` 
   - **Malicious `Signature`** = targetSignature (instead of `previousRound.CalculateSignature(PreviousInValue)`)

3. **Validation Passes**: 
   - Check at line 31-32 passes (signature is not null/empty)
   - Check at line 48 passes (previousInValue hashes to previousOutValue)
   - **No check exists for signature correctness**

4. **Signature Stored**: At line 17 of Round_Recover.cs and line 244 of ProcessConsensusInformation, the malicious signature is stored

5. **Order Manipulated**: At line 19-21 of Round_ApplyNormalConsensusData, `supposedOrderOfNextRound = (targetSignature.ToInt64() % minersCount) + 1 = 1`, giving attacker first position

**Expected Result**: Signature validation should fail, transaction should be rejected

**Actual Result**: Transaction succeeds, attacker gains order=1, and corrupted signature propagates to future rounds through CalculateSignature's XOR aggregation, permanently compromising consensus fairness.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L17-17)
```csharp
        minerInRound.Signature = providedInformation.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L16-19)
```csharp
        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L48-48)
```csharp
        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-244)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** protobuf/aedpos_contract.proto (L197-198)
```text
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
```
