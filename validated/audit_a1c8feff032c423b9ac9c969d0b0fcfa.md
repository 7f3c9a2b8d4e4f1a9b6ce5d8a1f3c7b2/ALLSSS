# Audit Report

## Title
Unvalidated Signature Field Allows Consensus Manipulation Through Mining Order Control

## Summary
The `Signature` and `SupposedOrderOfNextRound` fields in `UpdateValueInput` are accepted without validation against their expected calculated values, allowing authorized miners to arbitrarily manipulate their position in subsequent mining rounds and influence extra block producer selection, breaking consensus fairness.

## Finding Description

The AEDPoS consensus mechanism is designed to deterministically calculate mining order based on cryptographic signatures. However, the `UpdateValue` method accepts miner-provided signature and order values without verifying their correctness.

**Missing Signature Validation:**
The `UpdateValueValidationProvider` only performs null/empty checks on the signature field, without validating it matches the expected value calculated via `previousRound.CalculateSignature(previousInValue)`. [1](#0-0) 

The expected signature calculation is defined in the codebase but never used for validation: [2](#0-1) 

**Unchecked Direct Assignment:**
During recovery, the provided signature is blindly copied without validation: [3](#0-2) 

The `ProcessUpdateValue` method directly assigns the attacker-controlled values without verification: [4](#0-3) 

**Critical Usage in Mining Order:**
The signature should determine mining order through modulo calculation: [5](#0-4) 

This `FinalOrderOfNextRound` directly controls the miner's position in the next round: [6](#0-5) 

**Extra Block Producer Manipulation:**
The signature is also used to determine the extra block producer for the next round: [7](#0-6) 

**Attack Execution:**
A malicious miner can exploit this by calling the public `UpdateValue` method: [8](#0-7) 

The only access control is that the sender must be an authorized miner: [9](#0-8) 

## Impact Explanation

**HIGH Impact** - This vulnerability fundamentally breaks consensus fairness, a critical security invariant:

1. **Consensus Integrity Violation:** The deterministic mining order mechanism is completely bypassed, allowing miners to choose their preferred positions.

2. **Unfair Mining Advantages:** Attackers can:
   - Select favorable time slots for block production
   - Maximize their chances of becoming the extra block producer
   - Coordinate with other malicious miners to dominate consecutive slots

3. **Systemic Risk:** If multiple miners collude, they can systematically manipulate the consensus schedule, potentially enabling attacks with less than the expected threshold of malicious mining power.

4. **Reward and MEV Exploitation:** Control over mining position and extra block producer status may grant privileged access to transaction ordering and additional rewards.

## Likelihood Explanation

**HIGH Likelihood** - The attack is straightforward to execute:

1. **Public Entry Point:** The `UpdateValue` method is publicly accessible to all authorized miners.

2. **Low Complexity:** An attacker only needs to:
   - Craft an arbitrary signature value (or directly provide desired order)
   - Call `UpdateValue` with crafted parameters
   - No cryptographic breaking or complex computation required

3. **No Detection:** The validation only checks for null/empty values, not correctness.

4. **Repeatable:** Can be executed in every round where the malicious miner has a time slot.

5. **Economic Rationality:** Negligible cost with significant potential benefits.

## Recommendation

Implement signature validation in `UpdateValueValidationProvider`:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var publicKey = validationContext.SenderPubkey;
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[publicKey];
    
    if (minerInRound.PreviousInValue == null || minerInRound.PreviousInValue == Hash.Empty)
        return true;
        
    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey))
        return true;
    
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(minerInRound.PreviousInValue);
    if (minerInRound.Signature != expectedSignature)
        return false;
    
    // Also validate SupposedOrderOfNextRound matches signature calculation
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Add this validation to the `ValidateHeaderInformation` method before returning success.

## Proof of Concept

A malicious miner can execute this attack by:

1. Calculating desired mining order for next round (e.g., order = 1 for first position)
2. Creating arbitrary signature value (e.g., any hash)
3. Calling `UpdateValue` with:
   - `Signature` = crafted hash value
   - `SupposedOrderOfNextRound` = desired position (1)
   - Other required fields filled correctly
4. Validation passes (only checks non-null/non-empty)
5. `ProcessUpdateValue` assigns the crafted values
6. In next round generation, miner gets their chosen position

The test would demonstrate that a miner can repeatedly call `UpdateValue` with different signature values and observe their resulting position changes in subsequent rounds, confirming the lack of validation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-18)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-247)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
