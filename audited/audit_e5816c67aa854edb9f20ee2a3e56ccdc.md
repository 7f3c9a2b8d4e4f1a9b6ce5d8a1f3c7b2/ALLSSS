### Title
Missing Signature Validation Allows Mining Order Manipulation in AEDPoS Consensus

### Summary
The `NewConsensusInformationFilled()` function validates OutValue and Signature fields independently without verifying that the Signature is correctly calculated from the consensus round state. This allows malicious miners to submit arbitrary Signature values during UpdateValue transactions, enabling them to manipulate their mining order in subsequent rounds and break the fairness guarantees of the AEDPoS consensus mechanism.

### Finding Description

The vulnerability exists in the validation logic for UpdateValue consensus behavior: [1](#0-0) 

The `NewConsensusInformationFilled()` function only checks that both OutValue and Signature are non-null and contain data, but does not verify the Signature was correctly calculated.

The expected signature calculation is defined as: [2](#0-1) 

During block production, the signature should be calculated from the previous round state: [3](#0-2) 

However, when processing the UpdateValue transaction, the signature is directly assigned without validation: [4](#0-3) 

The signature value directly determines the miner's order in the next round: [5](#0-4) 

Additionally, if the attacker is the first-place miner, their signature determines the extra block producer: [6](#0-5) 

The only validation performed is the PreviousInValue hash check, which does not validate the Signature field: [7](#0-6) 

### Impact Explanation

**Consensus Integrity Breach**: A malicious miner can manipulate their mining order in future rounds by providing arbitrary Signature values. This breaks the core fairness and randomness guarantees of the AEDPoS consensus mechanism.

**Specific Impacts**:
1. **Mining Order Manipulation**: Attacker can engineer their `SupposedOrderOfNextRound` to achieve preferential positions (e.g., mining first to maximize block rewards)
2. **Extra Block Producer Control**: If the attacker is first-place, they control which miner becomes the extra block producer in the next round
3. **Revenue Advantage**: Preferential mining slots lead to higher block production rates and increased mining rewards
4. **Protocol Unfairness**: Honest miners lose expected mining opportunities to the attacker

The manipulation is deterministic—an attacker can offline-calculate signature values to achieve any desired mining order position within the round.

### Likelihood Explanation

**Attacker Capabilities**: Any miner in the active miner list can execute this attack. No special privileges beyond being a valid miner are required.

**Attack Complexity**: LOW
- Attacker computes multiple signature values offline
- Tests which signature gives desired next-round order via modulus operation
- Submits UpdateValue with manipulated signature
- All other fields (OutValue, PreviousInValue) remain valid

**Feasibility Conditions**:
- Attacker must be an active miner (realistic in PoS systems)
- Cost is negligible—only offline computation required
- No detection mechanism exists since validation never checks signature correctness
- Attack is repeatable every round

**Economic Rationality**: Highly profitable. The cost of offline computation is minimal compared to the value of preferential mining positions and increased block rewards.

**Probability**: HIGH. The vulnerability is present in production code and exploitable by any miner in every round.

### Recommendation

Add signature validation to `UpdateValueValidationProvider`:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    var minerInRound =
        validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    if (minerInRound.OutValue == null || minerInRound.Signature == null ||
        !minerInRound.OutValue.Value.Any() || !minerInRound.Signature.Value.Any())
        return false;
    
    // NEW: Validate signature is correctly calculated
    if (validationContext.PreviousRound != null && 
        minerInRound.PreviousInValue != null &&
        minerInRound.PreviousInValue != Hash.Empty)
    {
        var expectedSignature = validationContext.PreviousRound.CalculateSignature(
            minerInRound.PreviousInValue);
        if (minerInRound.Signature != expectedSignature)
            return false;
    }
    
    return true;
}
```

**Invariant to Enforce**: For UpdateValue transactions, `providedSignature == previousRound.CalculateSignature(previousInValue)` must hold.

**Test Cases**:
1. Verify UpdateValue with correct signature passes validation
2. Verify UpdateValue with manipulated signature fails validation
3. Verify mining order cannot be influenced by signature manipulation
4. Add fuzzing tests with random signature values

### Proof of Concept

**Initial State**:
- 5 miners in current round (A, B, C, D, E)
- Attacker is miner A
- Current round N, miner A's turn to produce block

**Attack Steps**:

1. **Offline Computation**: Attacker computes signature candidates
   ```
   for each candidate_sig in range(0, 2^64):
       order = (abs(candidate_sig) % 5) + 1
       if order == 1:  // Desired position
           use candidate_sig
   ```

2. **Submit UpdateValue Transaction**:
   - OutValue: `Hash(currentInValue)` ✓ (correct)
   - PreviousInValue: `actualPreviousInValue` ✓ (correct, passes hash check)
   - Signature: `candidate_sig` ✗ (manipulated, but not validated)

3. **Validation Passes**:
   - `NewConsensusInformationFilled()`: OutValue ≠ null ✓, Signature ≠ null ✓
   - `ValidatePreviousInValue()`: `Hash(PreviousInValue) == PreviousOutValue` ✓
   - No check that `Signature == CalculateSignature(PreviousInValue)` ✗

4. **State Update**: Manipulated signature stored in round state

5. **Next Round Generation**: `ApplyNormalConsensusData()` calculates
   - `supposedOrder = (abs(candidate_sig) % 5) + 1 = 1`
   - Attacker gets first mining position in round N+1

**Expected Result**: Validation should reject manipulated signature
**Actual Result**: Validation passes, attacker achieves order manipulation

**Success Condition**: Attacker consistently achieves preferential mining positions (order 1 or 2) across multiple rounds despite random distribution expecting uniform distribution across all 5 positions.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-244)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-122)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
```
