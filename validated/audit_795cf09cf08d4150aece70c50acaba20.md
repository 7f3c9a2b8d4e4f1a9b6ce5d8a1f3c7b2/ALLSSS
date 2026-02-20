# Audit Report

## Title
Consensus Signature Manipulation via Missing Verification Allows Mining Order Control

## Summary
The AEDPoS consensus contract fails to verify that submitted signature values in `UpdateValue` transactions match the expected calculated signature. This allows any miner to provide arbitrary signature values that directly determine their mining position in the next round, completely bypassing the consensus randomness mechanism.

## Finding Description

The vulnerability exists in the consensus data processing flow where honest miners calculate signatures but validators never verify their correctness.

**Honest Signature Calculation:**
When honest miners produce blocks, the system correctly calculates signatures by aggregating previous round signatures with the previous in-value. [1](#0-0) 

The `CalculateSignature` method performs XOR aggregation of all previous round signatures: [2](#0-1) 

**Vulnerability: Direct Assignment Without Verification:**
When processing `UpdateValue` transactions, the signature and order values are directly assigned from user input without any verification: [3](#0-2) 

**Missing Validation:**
The `UpdateValueValidationProvider` only checks that the signature field is non-null and non-empty, but never recalculates or verifies the expected signature value: [4](#0-3) 

**Direct Impact on Mining Order:**
The signature value directly determines the miner's position in the next round through modulo arithmetic: [5](#0-4) 

The modulo calculation is: [6](#0-5) 

**Order Used Without Verification:**
During next round generation, miners are ordered by their `FinalOrderOfNextRound` values (which originated from unverified user input) without any recalculation: [7](#0-6) 

**No Detection Mechanism:**
The evil miner detection only checks for missed time slots, not for incorrect consensus data: [8](#0-7) 

## Impact Explanation

This vulnerability directly breaks consensus integrity with **HIGH severity** impact:

**Consensus Schedule Manipulation:**
- Attackers can choose position 1 to mine first in each round, gaining MEV opportunities and timing advantages
- Attackers can choose the last position to become extra block producer, controlling round transitions
- The randomness mechanism that ensures fair turn-taking is completely bypassed

**Network-Wide Effects:**
- Unfair distribution of block production opportunities
- Concentration of MEV extraction to malicious miners
- Degradation of consensus security assumptions
- Loss of fairness guarantees that AEDPoS is designed to provide

**Protocol Invariant Violation:**
This directly violates the consensus miner schedule integrity invariant. The protocol assumes signature-based randomness prevents predictable mining order manipulation, but this assumption is not enforced.

## Likelihood Explanation

**HIGH likelihood** - the attack is practical and cost-free:

**Attacker Capabilities:**
Any miner in the validator set can execute this attack. The entry point is the public `UpdateValue` method: [9](#0-8) 

**Attack Complexity: LOW**
- Calculate desired position (e.g., 1 for first position)
- Reverse-calculate signature value: `signature_value = (desired_position - 1) + k * miner_count` for any integer k
- Provide this signature in `UpdateValueInput` with matching `SupposedOrderOfNextRound`
- No cryptographic challenges, no economic costs

**Feasibility:**
- Miners control consensus data generation
- All previous round signatures are publicly available on-chain
- Simple integer arithmetic determines position mapping
- No verification mechanism exists to detect the manipulation

**Detection:**
The attack is completely undetectable because no validator recalculates the expected signature or compares it to the submitted value.

## Recommendation

Add signature verification in the `UpdateValueValidationProvider` or `ProcessUpdateValue` method:

1. **Recalculate Expected Signature:** When processing `UpdateValue`, recalculate what the signature should be using `previousRound.CalculateSignature(providedPreviousInValue)`

2. **Verify Signature Matches:** Compare the calculated signature with the provided signature and reject if they don't match

3. **Verify Order Derivation:** Verify that `SupposedOrderOfNextRound` equals `GetAbsModulus(signature.ToInt64(), minersCount) + 1`

4. **Add to Validation:** Include this verification in `UpdateValueValidationProvider.ValidateHeaderInformation()`

Example fix location: [10](#0-9) 

## Proof of Concept

A malicious miner can:
1. Call the public `UpdateValue` method with arbitrary signature bytes
2. Set `SupposedOrderOfNextRound = 1` to claim first mining position
3. Calculate signature value such that `GetAbsModulus(signature.ToInt64(), minerCount) + 1 == 1`
4. The contract accepts these values without verification
5. In the next round generation, the attacker receives position 1
6. The attacker mines first, gaining timing advantages and MEV opportunities
7. No evil miner detection triggers because the attacker successfully mined their slot

The vulnerability is confirmed by the absence of any signature recalculation or verification logic in the validation providers or processing methods.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-247)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-101)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
```
