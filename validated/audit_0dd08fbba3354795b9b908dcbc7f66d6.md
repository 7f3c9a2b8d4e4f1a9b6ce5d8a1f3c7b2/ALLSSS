# Audit Report

## Title
Consensus Order Manipulation via Unvalidated SupposedOrderOfNextRound in UpdateValue

## Summary
The AEDPoS consensus contract accepts miner-provided `SupposedOrderOfNextRound` values without validation, allowing any miner to arbitrarily set their mining position in the next round. This breaks the fundamental fairness guarantee where mining order should be deterministically derived from cryptographic signatures.

## Finding Description

The AEDPoS consensus mechanism is designed to deterministically calculate mining order for the next round based on a miner's cryptographic signature using the formula `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [1](#0-0) [2](#0-1) 

However, the `ProcessUpdateValue` function directly accepts and stores the `SupposedOrderOfNextRound` value from `UpdateValueInput` without performing any validation or recalculation: [3](#0-2) 

This manipulated value directly determines the actual mining order in the next round, as `GenerateNextRoundInformation` sorts miners by their `FinalOrderOfNextRound`: [4](#0-3) 

**Why Existing Validations Fail:**

1. The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` fields, completely ignoring `SupposedOrderOfNextRound`: [5](#0-4) 

2. The `NextRoundMiningOrderValidationProvider` is only invoked for `NextRound` behavior, not for `UpdateValue` behavior: [6](#0-5) 

3. The `RecoverFromUpdateValue` function blindly copies order values from the provided round without validation: [7](#0-6) 

4. The `ValidateConsensusAfterExecution` contains a critical bug where it modifies `currentRound` via `RecoverFromUpdateValue` and then compares it to itself, causing validation to always pass: [8](#0-7) 

**Attack Execution Path:**

1. Any miner in the current or previous round can call the public `UpdateValue` method: [9](#0-8) 

2. The miner provides an `UpdateValueInput` with a manipulated `supposed_order_of_next_round` field (e.g., setting it to 1 to always mine first): [10](#0-9) 

3. The `PreCheck` only verifies miner list membership, not order value correctness: [11](#0-10) 

4. The manipulated value persists in state and directly determines the next round's mining order.

## Impact Explanation

This vulnerability fundamentally breaks the AEDPoS consensus fairness guarantee. A malicious miner can:

1. **Monopolize First Mining Slot**: Set `SupposedOrderOfNextRound = 1` in every round to consistently mine first, gaining MEV extraction advantages and the ability to censor transactions.

2. **Manipulate Block Production Timing**: Choose any mining position to maximize economic benefits or coordinate with other malicious actors.

3. **Undermine Consensus Security**: The deterministic, cryptographically-derived mining order is a core security property of AEDPoS. Breaking this allows strategic positioning that can facilitate selfish mining, transaction censorship, or other consensus attacks.

The impact is **CRITICAL** because:
- Any single miner can exploit this without requiring majority control
- The attack is undetectable in the current implementation
- It violates a fundamental consensus invariant
- Affects all network participants through degraded consensus security and fairness

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:

1. **Low Barrier to Entry**: The attacker only needs to be an active miner (part of the current or previous round's miner list), which is the normal operating condition for miners.

2. **Simple Execution**: The attack requires only modifying a single integer field in the transaction input before submission - no complex cryptographic operations or timing requirements.

3. **No Detection**: The flawed validation logic ensures the manipulation cannot be detected - no validator checks if `SupposedOrderOfNextRound` matches the signature-derived value, and the validation bug causes the comparison to always pass.

4. **Repeatable**: The attack can be executed in every round to maintain advantageous positioning indefinitely.

5. **Economic Rationality**: The cost is minimal (standard transaction fee) while the benefit is substantial (guaranteed favorable mining position with MEV advantages).

## Recommendation

Add validation in `ProcessUpdateValue` to verify that the provided `SupposedOrderOfNextRound` matches the signature-derived value:

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
        "Invalid SupposedOrderOfNextRound: does not match signature-derived value");
    
    // Continue with existing logic...
}
```

Additionally, fix the `ValidateConsensusAfterExecution` bug by not modifying `currentRound` before comparison, or by comparing against the original unmodified state.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up an AEDPoS test environment with multiple miners
2. Having a miner call `UpdateValue` with a manipulated `SupposedOrderOfNextRound` value (e.g., 1)
3. Observing that the transaction succeeds without validation failure
4. Verifying that in the next round generation, the miner is assigned the manipulated order position
5. Confirming that this miner consistently mines first in subsequent rounds by repeating the attack

The core proof lies in examining the code flow where `ProcessUpdateValue` directly assigns the input value without validation, and no subsequent validation catches this manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-86)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** protobuf/aedpos_contract.proto (L205-206)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
```
