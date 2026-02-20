# Audit Report

## Title
Missing Signature Validation Allows Mining Order Manipulation in AEDPoS Consensus

## Summary
The AEDPoS consensus contract fails to cryptographically verify that miner signatures match the protocol-specified calculation. The validation only checks that signatures are non-empty, allowing miners to submit arbitrary signature values that directly determine their mining order in subsequent rounds, breaking consensus fairness guarantees.

## Finding Description

The vulnerability exists in the UpdateValue consensus validation flow. According to the protocol specification, a miner's signature should be calculated by XORing their previous in-value with all signatures from the previous round. [1](#0-0) 

The correct signature calculation is implemented in the `CalculateSignature` method, which XORs the in-value with an aggregate of all previous round signatures: [2](#0-1) 

During normal block production, this calculation is correctly performed when generating consensus extra data: [3](#0-2) 

However, when validating UpdateValue transactions, the `NewConsensusInformationFilled` method only checks that the signature field is non-null and contains data - it does NOT verify the signature value matches the expected calculation: [4](#0-3) 

The signature from user input is then directly assigned to state without any cryptographic verification: [5](#0-4) 

This signature value directly determines the miner's order in the next round through a modulus operation: [6](#0-5) 

When generating the next round, miners are ordered by their `FinalOrderOfNextRound` value: [7](#0-6) 

Additionally, if an attacker achieves first place, their manipulated signature determines which miner becomes the extra block producer: [8](#0-7) 

**Attack Flow:**
1. Attacker (a valid miner) computes multiple candidate signature values offline
2. For each candidate, calculates the resulting order: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`
3. Selects the signature yielding the most favorable position (e.g., position 1)
4. Submits UpdateValue transaction with the manipulated signature but correct `OutValue` and `PreviousInValue`
5. Validation passes because only non-emptiness and `PreviousInValue` correctness are checked
6. The manipulated signature is written to state and determines the next round's mining order

## Impact Explanation

**Consensus Integrity Breach**: This vulnerability fundamentally breaks the fairness guarantees of the AEDPoS consensus mechanism. The mining order should be pseudo-random and unpredictable based on cryptographic commitments from the previous round. By manipulating signatures, an attacker can:

1. **Guarantee Preferential Mining Positions**: Consistently achieve first position to maximize block rewards
2. **Control Extra Block Producer Selection**: When in first place, determine which miner gets the extra block mining opportunity through their manipulated signature
3. **Unfair Revenue Distribution**: Systematically earn more rewards than honest miners following the protocol
4. **Undermine Consensus Randomness**: The deterministic manipulation eliminates the cryptographic randomness protecting against predictable mining patterns

The impact is critical because it directly violates the consensus protocol's core security assumptions. Every round, the attacker gains an unfair systematic advantage over honest participants.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Profile**: Any miner in the active validator set can execute this attack
- **Prerequisites**: Only requires being a valid miner (normal in PoS systems)  
- **Attack Complexity**: LOW - attacker computes multiple signatures offline, tests which yields the best order, submits the chosen one
- **Cost**: Negligible - only offline computation required
- **Detection**: None - validation never checks signature correctness, making the attack indistinguishable from normal operation
- **Repeatability**: Can be executed every round for sustained advantage

The attack is highly feasible because:
1. No special privileges required beyond being a miner [9](#0-8) 
2. Other validation checks (PreviousInValue) still pass with correct values [10](#0-9) 
3. No on-chain validation compares signature against expected calculation
4. After-execution validation only checks header-state consistency, which passes since both contain the manipulated signature [11](#0-10) 

## Recommendation

Add cryptographic verification in the `UpdateValueValidationProvider` to ensure the signature matches the expected calculation:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var publicKey = validationContext.SenderPubkey;
    
    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true;
    
    var providedSignature = validationContext.ProvidedRound.RealTimeMinersInformation[publicKey].Signature;
    var previousInValue = validationContext.ExtraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    
    if (previousInValue == null || previousInValue == Hash.Empty) 
        return true;
    
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
    
    return expectedSignature == providedSignature;
}
```

Then call this validation method in the `ValidateHeaderInformation` method before returning success.

## Proof of Concept

A proof of concept would demonstrate:

1. Set up a test network with multiple miners
2. Have one miner (attacker) compute offline: `for (int i = 0; i < 1000; i++) { var testSig = Hash.FromRawBytes(new byte[]{...}); var order = GetAbsModulus(testSig.ToInt64(), minersCount) + 1; if (order == 1) selectedSig = testSig; }`
3. Attacker creates UpdateValue transaction with correct `OutValue` and `PreviousInValue` but manipulated `Signature = selectedSig`
4. Transaction validation passes (only checks non-emptiness)
5. Signature is written to state
6. Next round generation shows attacker has mining order 1
7. Attacker consistently achieves first position across multiple rounds
8. Compare rewards: attacker earns significantly more than honest miners over time

The test would prove that signature manipulation directly controls mining order without any validation preventing it.

### Citations

**File:** protobuf/aedpos_contract.proto (L197-198)
```text
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-244)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-28)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```
