### Title
Consensus Order Manipulation via Unvalidated SupposedOrderOfNextRound in UpdateValue

### Summary
The `ProcessUpdateValue` function accepts the `SupposedOrderOfNextRound` value directly from miner-provided input without validating it was correctly calculated from the signature. This allows any miner to arbitrarily set their mining order for the next round, breaking the fairness guarantee of the AEDPoS consensus mechanism where order should be deterministically derived from the miner's signature.

### Finding Description

**Root Cause:**

The `SupposedOrderOfNextRound` should be deterministically calculated as `GetAbsModulus(signature.ToInt64(), minersCount) + 1` based on the miner's signature. [1](#0-0) 

However, in `ProcessUpdateValue`, this value is taken directly from the `UpdateValueInput` without validation or recalculation: [2](#0-1) 

**Why Existing Protections Fail:**

1. The `UpdateValueValidationProvider` only validates `OutValue` and `Signature` fields, but does not check if `SupposedOrderOfNextRound` matches the calculated value from the signature: [3](#0-2) 

2. The `RecoverFromUpdateValue` function blindly overwrites the `SupposedOrderOfNextRound` from the provided round without validation: [4](#0-3) 

3. The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with valid orders matches miners who produced blocks, but does not validate the order values themselves: [5](#0-4) 

**Execution Path:**

1. When a miner produces a block with `UpdateValue` behavior, `GetConsensusExtraDataToPublishOutValue` correctly calculates the order via `ApplyNormalConsensusData`: [6](#0-5) 

2. However, the miner can modify the `SupposedOrderOfNextRound` value in the `UpdateValueInput` structure before submitting it (the input structure includes this as a field): [7](#0-6) 

3. The `UpdateValue` function is publicly callable by any miner who passes the `PreCheck` (which only verifies the caller is in the miner list): [8](#0-7) 

4. The manipulated value is used to determine mining order in the next round via `GenerateNextRoundInformation`, which sorts miners by `FinalOrderOfNextRound`: [9](#0-8) 

### Impact Explanation

**Consensus Integrity Violation:**

This vulnerability allows a malicious miner to:
1. **Always mine first**: Set `SupposedOrderOfNextRound = 1` to consistently get the first mining slot in every round
2. **Create order collisions**: Multiple miners can set the same order value, breaking the intended mining schedule
3. **Manipulate block production timing**: Control when they mine to maximize MEV extraction or coordinate with other malicious actors

**Severity Justification:**

This is **CRITICAL** because:
- It breaks a fundamental invariant of the AEDPoS consensus: mining order should be unpredictable and fairly distributed based on cryptographic randomness from signatures
- Any single malicious miner can exploit this without requiring majority control
- The attack is undetectable in the current validation logic
- It undermines the security model of the entire consensus mechanism
- Can be used to facilitate other attacks like selfish mining or transaction censorship

**Affected Parties:**
- All honest miners lose fair access to mining slots
- Users suffer from potential transaction censorship or delayed confirmations
- The entire network's consensus security is compromised

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner in the current or previous round (passes `PreCheck`)
- Can call the public `UpdateValue` method with crafted input
- No special privileges beyond being a miner are required

**Attack Complexity:**
- **Low**: Simply modify the `SupposedOrderOfNextRound` field in the `UpdateValueInput` before submitting
- No complex cryptographic operations or timing requirements
- Can be executed in every round to maintain advantage

**Feasibility:**
- **High**: The attack vector is straightforward and requires only standard transaction submission
- No race conditions or special network states required
- Works under normal consensus operation

**Detection Constraints:**
- **None**: The current validation logic does not detect this manipulation
- The hash comparison in `ValidateConsensusAfterExecution` passes because `RecoverFromUpdateValue` modifies the comparison baseline

**Economic Rationality:**
- **Very High**: Transaction cost is minimal (standard consensus transaction)
- Benefit is significant: guaranteed favorable mining position for subsequent rounds
- No risk of detection or penalty in current implementation

### Recommendation

**Immediate Fix:**

In `ProcessUpdateValue`, recalculate `SupposedOrderOfNextRound` from the signature instead of accepting it from input:

```csharp
// In ProcessUpdateValue function, replace lines 246-247 with:
var minersCount = currentRound.RealTimeMinersInformation.Count;
var sigNum = updateValueInput.Signature.ToInt64();
var calculatedSupposedOrder = GetAbsModulus(sigNum, minersCount) + 1;
minerInRound.SupposedOrderOfNextRound = calculatedSupposedOrder;
minerInRound.FinalOrderOfNextRound = calculatedSupposedOrder;
```

**Additional Validation:**

Add validation in `UpdateValueValidationProvider` to verify the provided order matches the calculated value:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

**Test Cases:**

1. Test that `UpdateValue` with manipulated `SupposedOrderOfNextRound` is rejected
2. Test that correct calculated order is accepted
3. Test that order collisions are prevented
4. Regression test ensuring legitimate miners can still update values with correctly calculated orders

### Proof of Concept

**Initial State:**
- 7 active miners in current round
- Attacker is miner with pubkey `AttackerPubkey`
- Attacker's signature would normally calculate to order 5

**Attack Steps:**

1. Attacker produces a block and generates consensus data with their real signature
2. Before submitting `UpdateValue` transaction, attacker modifies the `UpdateValueInput`:
   ```
   UpdateValueInput {
       signature = <legitimate_signature>,
       supposed_order_of_next_round = 1,  // Manipulated from calculated value 5
       // ... other fields
   }
   ```

3. Attacker submits the transaction - it passes all validations:
   - `PreCheck`: Passes (attacker is a valid miner)
   - `UpdateValueValidationProvider`: Passes (only checks signature and outvalue exist)
   - Hash comparison: Passes (RecoverFromUpdateValue overwrites both sides)

4. `ProcessUpdateValue` accepts the manipulated order value and stores it in state

5. When `GenerateNextRoundInformation` is called for the next round, attacker is assigned order 1

**Expected vs Actual:**
- **Expected**: Attacker should get order 5 (calculated from signature)
- **Actual**: Attacker gets order 1 (manipulated value)

**Success Condition:**
Attacker successfully mines in the first position of the next round despite their signature indicating they should mine in position 5, demonstrating arbitrary control over mining order.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-25)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** protobuf/aedpos_contract.proto (L205-206)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
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
