### Title
Consensus Signature Manipulation Allows Miners to Control Next Round Mining Order

### Summary
The `NewConsensusInformationFilled()` validation function only verifies that consensus signatures exist and are non-empty, without validating their correctness or uniqueness. A malicious miner can provide an arbitrary signature value in their `UpdateValue` transaction to manipulate their `SupposedOrderOfNextRound`, allowing them to control their mining position in subsequent rounds and compromise consensus fairness.

### Finding Description

The vulnerability exists in the consensus validation logic at: [1](#0-0) 

This validation only checks that `Signature` is not null and contains at least one byte, but does NOT verify that the signature was correctly calculated using the expected formula.

The correct signature calculation occurs during block generation at: [2](#0-1) 

Where signatures are computed via `Round.CalculateSignature()`: [3](#0-2) 

However, when the `UpdateValue` transaction is executed, the signature is stored directly without verification: [4](#0-3) 

The malicious signature then determines the attacker's next round mining order through: [5](#0-4) 

This calculated order directly affects the miner's position when generating the next round: [6](#0-5) 

### Impact Explanation

**Consensus Integrity Compromise**: The attacker can manipulate the deterministic miner ordering mechanism that should be based on cryptographic randomness. By controlling their signature value, they can:

1. **Select Preferred Mining Positions**: Choose to mine first (order 1) to become the extra block producer who controls round transitions, or select any other favorable time slot
2. **Increase Block Rewards**: Extra block producers and miners in certain positions receive additional mining opportunities and rewards
3. **Compromise Randomness**: Since signatures contribute to the VRF-based randomness system used throughout consensus, manipulation affects the integrity of random number generation
4. **Violate Fairness**: Breaks the core consensus invariant that all miners have equal probabilistic access to time slots based on unpredictable randomness

This is a **High severity** violation of the "Correct round transitions and miner schedule integrity" critical invariant, allowing manipulation of what should be a trustless, deterministic consensus mechanism.

### Likelihood Explanation

**Attacker Capabilities**: Must be an authorized miner (elected through voting), verified at: [7](#0-6) 

**Attack Complexity**: Trivial - the `UpdateValue` method is a public RPC endpoint: [8](#0-7) 

An attacker simply crafts an `UpdateValue` transaction with a manipulated signature field instead of the correctly calculated value. No sophisticated cryptographic attacks or timing exploits are required.

**Detection**: Difficult - there is no validation comparing the provided signature to the expected value, and no state tracking of previously used signatures. The manipulation would appear as valid consensus participation.

**Feasibility**: Any malicious miner can execute this attack during their normal block production turn. The economic cost is negligible (just transaction fees), while the benefit is continuous preferential mining positions.

### Recommendation

1. **Add Signature Correctness Validation**: Modify `UpdateValueValidationProvider.ValidateHeaderInformation()` to verify the signature matches the expected calculation:

```csharp
private bool ValidateSignatureCorrectness(ConsensusValidationContext validationContext)
{
    var providedSignature = validationContext.ProvidedRound
        .RealTimeMinersInformation[validationContext.SenderPubkey].Signature;
    var previousInValue = validationContext.ProvidedRound
        .RealTimeMinersInformation[validationContext.SenderPubkey].PreviousInValue;
    
    if (previousInValue == null || previousInValue == Hash.Empty) 
        return true;
    
    var expectedSignature = validationContext.PreviousRound
        .CalculateSignature(previousInValue);
    
    return providedSignature == expectedSignature;
}
```

Add this check to the validation at: [9](#0-8) 

2. **Add Invariant Test**: Create test cases verifying that manipulated signatures are rejected during validation

3. **Consider Signature Uniqueness Tracking**: Optionally maintain a bloom filter or recent signature cache to prevent exact signature reuse across rounds

### Proof of Concept

**Initial State**:
- Attacker is an elected miner in current round N
- Previous round N-1 completed normally

**Attack Steps**:
1. Attacker's mining turn arrives in round N
2. Attacker calculates multiple signature candidates: `S1`, `S2`, `S3`... with different hash values
3. For each candidate, computes `order = (candidate.ToInt64() % minerCount) + 1`
4. Selects signature candidate that produces `order = 1` (to become extra block producer)
5. Constructs `UpdateValue` transaction with manipulated signature instead of correctly calculated `previousRound.CalculateSignature(previousInValue)`
6. Transaction passes validation since only existence is checked
7. Manipulated signature is stored in state

**Expected Result**: 
Validation should reject the transaction due to signature mismatch

**Actual Result**: 
- Validation passes
- Attacker's `SupposedOrderOfNextRound` is set to 1
- In round N+1, attacker mines in position 1 as extra block producer
- Attacker gains control over round transition timing and additional block rewards

**Success Condition**: 
Attacker consistently appears in position 1 across multiple rounds by repeatedly manipulating their signature, demonstrating broken randomness and consensus fairness.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-245)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** protobuf/aedpos_contract.proto (L30-30)
```text
    rpc UpdateValue (UpdateValueInput) returns (google.protobuf.Empty) {
```
