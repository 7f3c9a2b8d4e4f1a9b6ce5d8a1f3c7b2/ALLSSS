### Title
UpdateValueValidationProvider Allows Manipulation of Next-Round Mining Order

### Summary
The `UpdateValueValidationProvider` fails to validate that `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` values in the provided round match the deterministic calculation based on miner signatures. This allows a malicious miner to manipulate the mining order for the next round by providing arbitrary order values in their block header, breaking the randomized consensus ordering mechanism and enabling preferential position selection.

### Finding Description

The vulnerability exists in the validation flow for `UpdateValue` consensus behavior: [1](#0-0) 

The provider only validates that `OutValue` and `Signature` are filled, and that `PreviousInValue` hashes correctly. It does NOT validate the `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` fields.

The critical issue occurs in the validation sequence. Before validation runs, `RecoverFromUpdateValue` is called: [2](#0-1) 

This method blindly copies order values from the provided round into the base round for ALL miners: [3](#0-2) 

These order values should be deterministically calculated from miner signatures: [4](#0-3) 

The calculation uses `GetAbsModulus(signature.ToInt64(), minersCount) + 1` to determine `SupposedOrderOfNextRound`, with conflict resolution logic for `FinalOrderOfNextRound`. However, the `UpdateValueValidationProvider` never verifies that the provided values match this calculation.

When honest miners generate blocks, they correctly calculate these values: [5](#0-4) 

And include them in the simplified round: [6](#0-5) 

However, a malicious miner can construct a `Round` with arbitrary order values that will pass validation and be applied to consensus state.

### Impact Explanation

**Consensus Integrity Violation**: The attack allows complete control over the mining order for the next round, breaking a critical consensus invariant. Mining order determines:
- Block reward distribution (first miners in round receive rewards before reward pool depletion)
- Transaction ordering and potential MEV opportunities
- Network stability and fairness

**Quantified Damage**: 
- Attacker can guarantee themselves position 1 in every round, maximizing their block rewards
- Honest miners can be pushed to unfavorable late positions
- The randomness mechanism that prevents predictable ordering is completely bypassed
- Over multiple rounds, attacker accumulates significantly more rewards than their fair share

**Affected Parties**: All network participants. Honest miners receive reduced rewards, users experience potential transaction ordering manipulation, and the overall security model of AEDPoS consensus is compromised.

**Severity Justification**: Critical - this breaks the fundamental fairness and randomness guarantees of the consensus mechanism, which are essential for decentralized network security.

### Likelihood Explanation

**Attacker Capabilities**: Any current miner can execute this attack. The attacker needs:
- Ability to produce blocks (already has mining slot)
- Ability to construct custom block headers with manipulated Round data
- Valid signature, OutValue, and PreviousInValue (standard mining requirements)

**Attack Complexity**: Low. The attacker simply:
1. Generates valid consensus values (OutValue, Signature, PreviousInValue) as normal
2. Modifies the `Round` structure in block header to set desired order values
3. Submits the block

**Feasibility Conditions**: Always feasible when the attacker has a mining slot. No special preconditions required.

**Detection Constraints**: The attack is difficult to detect because:
- The manipulated block passes all validation checks
- The impact only becomes visible when the next round starts
- Order manipulation could be subtle (slight favoritism vs. obvious position 1 every round)
- No on-chain evidence distinguishes malicious orders from honest randomness

**Economic Rationality**: Highly rational. The cost is zero (just crafting different header data), while benefits include preferential mining positions, increased block rewards, and potential MEV opportunities.

### Recommendation

Add validation in `UpdateValueValidationProvider` to verify that order values match the deterministic calculation:

```csharp
// In ValidateHeaderInformation method, after line 17:

// Validate SupposedOrderOfNextRound calculation
var providedMinerInfo = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
var signature = providedMinerInfo.Signature;
var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
var expectedSupposedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1;

if (providedMinerInfo.SupposedOrderOfNextRound != expectedSupposedOrder)
    return new ValidationResult { Message = "Invalid SupposedOrderOfNextRound calculation." };

// Validate FinalOrderOfNextRound is within valid range and not conflicting
if (providedMinerInfo.FinalOrderOfNextRound < 1 || providedMinerInfo.FinalOrderOfNextRound > minersCount)
    return new ValidationResult { Message = "FinalOrderOfNextRound out of valid range." };

// Validate that all other miners' order values haven't been manipulated
foreach (var minerInfo in validationContext.ProvidedRound.RealTimeMinersInformation)
{
    if (minerInfo.Key == validationContext.SenderPubkey) continue;
    
    var baseOrder = validationContext.BaseRound.RealTimeMinersInformation[minerInfo.Key].FinalOrderOfNextRound;
    // Only allow changes through TuneOrderInformation in ProcessUpdateValue
    // The provided round should not directly modify other miners' orders during validation
    if (minerInfo.Value.SupposedOrderOfNextRound != 0 || minerInfo.Value.FinalOrderOfNextRound != 0)
    {
        // These should remain at their previous values from baseRound
        if (minerInfo.Value.FinalOrderOfNextRound != baseOrder)
            return new ValidationResult { Message = "Cannot modify other miners' orders." };
    }
}
```

**Additional Checks**:
1. Verify `ImpliedIrreversibleBlockHeight` is reasonable (not far in future, not regressing)
2. Add test cases covering order manipulation attempts
3. Consider adding order validation similar to `NextRoundMiningOrderValidationProvider` for consistency

### Proof of Concept

**Initial State**:
- Network with 5 miners: A, B, C, D, E
- Current round: Miner C has mining slot at time T
- Honest order calculation would assign C order 3 for next round based on signature

**Attack Steps**:

1. Malicious miner C generates valid consensus data:
   - `OutValue = Hash(InValue)` 
   - `Signature = CalculateSignature(PreviousInValue)` (valid)
   - `PreviousInValue` (valid hash from previous round)

2. Miner C constructs malicious `Round` in block header:
   - Sets own `SupposedOrderOfNextRound = 1` (should be 3)
   - Sets own `FinalOrderOfNextRound = 1` (should be 3)
   - Manipulates other miners' orders: A→2, B→3, D→4, E→5

3. Miner C produces block at time T with this manipulated Round data

4. Validation flow:
   - `RecoverFromUpdateValue` copies malicious order values into baseRound
   - `UpdateValueValidationProvider.ValidateHeaderInformation()` checks:
     - ✓ OutValue is filled
     - ✓ Signature is filled  
     - ✓ PreviousInValue hashes correctly
     - ✗ MISSING: Order values validation
   - Validation passes

5. `ProcessUpdateValue` applies the manipulated values to consensus state: [7](#0-6) 

**Expected Result**: Miner C should get order 3 for next round (based on signature modulo calculation)

**Actual Result**: Miner C gets order 1 for next round (as manipulated), gaining first position and maximum rewards

**Success Condition**: In the next round, verify that miner C has `Order = 1` despite their signature calculation indicating they should have `Order = 3`. This demonstrates successful manipulation of the consensus state machine's next-round ordering.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-44)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L35-53)
```csharp
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```
