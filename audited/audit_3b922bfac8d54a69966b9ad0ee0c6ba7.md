# Audit Report

## Title
Missing Signature Validation Allows Mining Order Manipulation in AEDPoS Consensus

## Summary
The AEDPoS consensus contract fails to validate that miner signatures are correctly calculated according to the protocol specification. The `NewConsensusInformationFilled()` validation only checks that the Signature field is non-empty, but does not verify it matches the expected calculation from previous round state. This allows any miner to submit arbitrary signature values that directly determine their mining order in subsequent rounds, breaking consensus fairness guarantees.

## Finding Description

The vulnerability exists in the UpdateValue consensus validation flow. When a miner produces a block, they must submit an UpdateValue transaction containing their OutValue, Signature, and other consensus data.

The validation logic only checks that the Signature field is non-null and contains data: [1](#0-0) 

However, the signature SHOULD be calculated using a specific formula that XORs the miner's previous in-value with all signatures from the previous round: [2](#0-1) 

During normal block production, the signature is correctly calculated: [3](#0-2) 

But when processing the UpdateValue transaction, the signature from user input is directly assigned without any validation: [4](#0-3) 

The signature value directly determines the miner's order in the next round through a modulus operation: [5](#0-4) 

When generating the next round, miners are ordered by their `FinalOrderOfNextRound` value (which is initially set to `SupposedOrderOfNextRound`): [6](#0-5) 

Additionally, if the attacker achieves first place, their manipulated signature determines which miner becomes the extra block producer: [7](#0-6) 

**Attack Flow:**
1. Attacker (a valid miner) calculates multiple candidate signature values offline
2. For each candidate, computes: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`
3. Selects the signature that yields the most favorable mining order (e.g., position 1)
4. Submits UpdateValue transaction with manipulated signature
5. Validation passes because only non-emptiness is checked
6. Manipulated signature is written to state and determines next round order

## Impact Explanation

**Consensus Integrity Breach**: This vulnerability breaks the fundamental fairness guarantees of the AEDPoS consensus mechanism. The mining order in each round should be pseudo-random and unpredictable based on cryptographic commitments. By manipulating signatures, an attacker can:

1. **Guarantee Preferential Mining Positions**: Achieve first position consistently to maximize block rewards
2. **Control Extra Block Producer Selection**: When in first place, determine which miner gets the extra block mining opportunity
3. **Unfair Revenue Distribution**: Systematically earn more rewards than honest miners
4. **Undermine Consensus Randomness**: The deterministic manipulation eliminates the randomness that protects against predictable mining patterns

The impact is severe because it directly violates the consensus protocol's security assumptions. Every round, the attacker gains an unfair advantage over honest miners who follow the protocol correctly.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Profile**: Any miner in the active validator set can execute this attack
- **Prerequisites**: Only requires being a valid miner (normal in PoS systems)
- **Attack Complexity**: LOW - attacker computes multiple signatures offline, tests which gives best order, submits chosen one
- **Cost**: Negligible - only offline computation required
- **Detection**: None - validation never checks signature correctness, so attack is indistinguishable from normal operation
- **Repeatability**: Can be executed every round for sustained advantage

The attack is highly feasible because:
1. No special privileges required beyond being a miner
2. Other validation checks (PreviousInValue) still pass with correct values
3. No on-chain validation compares signature against expected calculation
4. After-execution validation only checks that header data matches state, which always passes because the manipulated signature was already written

## Recommendation

Add signature correctness validation in `UpdateValueValidationProvider`:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // Existing checks
    if (minerInRound.OutValue == null || minerInRound.Signature == null ||
        !minerInRound.OutValue.Value.Any() || !minerInRound.Signature.Value.Any())
        return false;
    
    // NEW: Validate signature correctness
    if (validationContext.PreviousRound != null && 
        validationContext.PreviousRound.RealTimeMinersInformation.Count > 0)
    {
        var previousInValue = minerInRound.PreviousInValue;
        if (previousInValue != null && previousInValue != Hash.Empty)
        {
            var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
            if (minerInRound.Signature != expectedSignature)
                return false;
        }
    }
    
    return true;
}
```

Update the validation error message in `ValidateHeaderInformation`:
```csharp
if (!NewConsensusInformationFilled(validationContext))
    return new ValidationResult { Message = "Incorrect consensus information: Signature does not match expected calculation from previous round state." };
```

## Proof of Concept

A complete proof of concept would require:

1. Setting up a test network with multiple miners
2. Modifying miner client to calculate multiple signature candidates
3. Selecting signature that yields order=1 via `GetAbsModulus(sig.ToInt64(), minerCount) + 1`
4. Submitting UpdateValue transaction with manipulated signature
5. Observing that validation passes and attacker receives first mining position in next round

The core vulnerability is that the validation in `UpdateValueValidationProvider.NewConsensusInformationFilled()` never calls `CalculateSignature()` to verify correctness, allowing arbitrary signature values to pass validation and directly influence mining order through the modulus operation in `Round_ApplyNormalConsensusData`.

## Notes

- The VRF random number validation (`Context.ECVrfVerify`) is separate from this consensus signature validation and does not prevent this attack
- The PreviousInValue hash check provides some protection but does not constrain the Signature field
- This vulnerability exists in the production consensus contract code and is exploitable in every round by any active miner

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-114)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L88-92)
```csharp
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-246)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
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
    }
```
