# Audit Report

## Title
Consensus Order Manipulation via Unvalidated SupposedOrderOfNextRound in UpdateValue

## Summary
The AEDPoS consensus contract accepts miner-provided `SupposedOrderOfNextRound` values without validation, allowing any miner to arbitrarily set their mining position in the next round. This breaks the fundamental fairness guarantee where mining order should be deterministically derived from cryptographic signatures.

## Finding Description

**Expected Behavior:**
The mining order for the next round should be calculated deterministically as `GetAbsModulus(signature.ToInt64(), minersCount) + 1` based on the miner's signature. [1](#0-0) 

**Actual Behavior:**
The `ProcessUpdateValue` function directly accepts the `SupposedOrderOfNextRound` value from `UpdateValueInput` without any validation or recalculation: [2](#0-1) 

This value is stored in state and subsequently used to determine the actual mining order in `GenerateNextRoundInformation`, which sorts miners by their `FinalOrderOfNextRound`: [3](#0-2) 

**Why Existing Validations Fail:**

1. The `UpdateValueValidationProvider` only validates `OutValue` and `Signature` fields, completely ignoring `SupposedOrderOfNextRound`: [4](#0-3) 

2. The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with valid orders matches the count who produced blocks, but does not validate the order values themselves: [5](#0-4) 

3. The `RecoverFromUpdateValue` function blindly overwrites order values from the provided round without validation: [6](#0-5) 

4. The `ValidateConsensusAfterExecution` contains a critical bug where it modifies `currentRound` via `RecoverFromUpdateValue` and then compares it to itself: [7](#0-6) [8](#0-7) 

**Attack Execution Path:**

1. A miner produces a block with UpdateValue behavior
2. The miner modifies the `supposed_order_of_next_round` field in the transaction input (this field is part of the protobuf message structure): [9](#0-8) 

3. The UpdateValue method is publicly accessible to any miner in the current or previous round: [10](#0-9) 

4. The PreCheck only verifies miner list membership, not order value correctness: [11](#0-10) 

5. The manipulated value persists in state and directly determines the next round's mining order

## Impact Explanation

This vulnerability fundamentally breaks the AEDPoS consensus fairness guarantee. A malicious miner can:

1. **Monopolize First Mining Slot**: Set `SupposedOrderOfNextRound = 1` in every round to consistently mine first, gaining MEV extraction advantages and the ability to censor transactions.

2. **Manipulate Block Production Timing**: Choose any mining position to maximize economic benefits or coordinate with other malicious actors.

3. **Create Order Collisions**: Multiple miners setting the same order disrupts the intended mining schedule and consensus flow.

4. **Undermine Consensus Security**: The unpredictability of mining order (derived from cryptographic randomness) is a core security property of AEDPoS. Breaking this allows strategic positioning that can facilitate selfish mining, transaction censorship, or other consensus attacks.

The impact is **CRITICAL** because:
- Any single miner can exploit this without requiring majority control
- The attack is undetectable in the current implementation
- It violates a fundamental consensus invariant
- Affects all network participants through degraded consensus security

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:

1. **Low Barrier to Entry**: The attacker only needs to be an active miner (part of the current or previous round's miner list), which is the normal operating condition for miners.

2. **Simple Execution**: The attack requires only modifying a single integer field in the transaction input before submission - no complex cryptographic operations or timing requirements.

3. **No Detection**: The flawed validation logic ensures the manipulation cannot be detected:
   - No validator checks if `SupposedOrderOfNextRound` matches the signature-derived value
   - The validation bug in `ValidateConsensusAfterExecution` causes the comparison to always pass

4. **Repeatable**: The attack can be executed in every round to maintain advantageous positioning indefinitely.

5. **Economic Rationality**: The cost is minimal (standard transaction fee) while the benefit is substantial (guaranteed favorable mining position).

## Recommendation

**Fix 1: Add Validation in ProcessUpdateValue**

Validate that the provided `SupposedOrderOfNextRound` matches the calculated value:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    
    // Calculate expected order from signature
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    var sigNum = updateValueInput.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    // Validate provided order matches expected
    Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
           $"Invalid SupposedOrderOfNextRound. Expected {expectedOrder}, got {updateValueInput.SupposedOrderOfNextRound}");
    
    // Continue with rest of the function...
}
```

**Fix 2: Add Validation in UpdateValueValidationProvider**

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    if (!NewConsensusInformationFilled(validationContext))
        return new ValidationResult { Message = "Incorrect new Out Value." };

    if (!ValidatePreviousInValue(validationContext))
        return new ValidationResult { Message = "Incorrect previous in value." };

    // Add order validation
    if (!ValidateSupposedOrderOfNextRound(validationContext))
        return new ValidationResult { Message = "Invalid SupposedOrderOfNextRound." };

    return new ValidationResult { Success = true };
}

private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

**Fix 3: Correct the Validation Bug**

In `ValidateConsensusAfterExecution`, avoid modifying the state object before comparison:

```csharp
public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
{
    var headerInformation = new AElfConsensusHeaderInformation();
    headerInformation.MergeFrom(input.Value);
    if (TryToGetCurrentRoundInformation(out var currentRound))
    {
        // Create a copy for comparison, don't modify currentRound
        var expectedRound = currentRound.Clone();
        if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
            expectedRound = expectedRound.RecoverFromUpdateValue(headerInformation.Round,
                headerInformation.SenderPubkey.ToHex());

        var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
        if (expectedRound.GetHash(isContainPreviousInValue) !=
            currentRound.GetHash(isContainPreviousInValue))
        {
            // validation failure...
        }
    }
    return new ValidationResult { Success = true };
}
```

## Proof of Concept

A valid test would demonstrate:
1. A miner calling UpdateValue with a manipulated `SupposedOrderOfNextRound` value (e.g., always setting it to 1)
2. The transaction succeeding without validation errors
3. The next round being generated with the miner in the manipulated position
4. Repeated execution showing the miner can maintain position control across rounds

The test would call the UpdateValue method directly with crafted input containing an arbitrary order value, verify it's accepted, and confirm the miner's position in the next round matches the manipulated value rather than the signature-derived value.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L91-92)
```csharp
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** protobuf/aedpos_contract.proto (L205-206)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
