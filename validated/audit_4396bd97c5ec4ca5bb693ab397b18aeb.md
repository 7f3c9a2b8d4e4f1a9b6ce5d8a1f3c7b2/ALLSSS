# Audit Report

## Title
Consensus Signature Forgery Allows Mining Order Manipulation in AEDPoS UpdateValue

## Summary
The AEDPoS consensus mechanism fails to validate that the `Signature` field in `UpdateValueInput` matches the expected deterministic calculation, allowing miners to forge signatures and manipulate their mining order in subsequent rounds. The signature directly determines position via modulus operation but is only checked for null/empty, not correctness.

## Finding Description

The AEDPoS consensus protocol uses a signature value to determine each miner's position in the next round through a deterministic calculation. The signature should be calculated using `CalculateSignature` which XORs the miner's previous in-value with all signatures from the previous round. [1](#0-0) 

During normal block production, the signature is correctly calculated in `GetConsensusExtraDataToPublishOutValue`: [2](#0-1) 

However, miners control the consensus extra data in block headers and can modify the signature field before block submission. The critical vulnerability is that `UpdateValueValidationProvider` only validates that the signature is non-null and non-empty, with no cryptographic verification: [3](#0-2) 

The validation pipeline for UpdateValue behavior confirms this is the only signature check applied: [4](#0-3) 

During validation, `RecoverFromUpdateValue` blindly copies the unverified signature from the header: [5](#0-4) 

The forged signature is then stored to state in `ProcessUpdateValue` without any verification: [6](#0-5) 

This forged signature directly determines the miner's position in the next round through `ApplyNormalConsensusData`: [7](#0-6) 

The post-execution validation in `ValidateConsensusAfterExecution` compares the round hash from the header with the state, but since both contain the same forged signature after `RecoverFromUpdateValue`, this check passes: [8](#0-7) 

## Impact Explanation

This vulnerability fundamentally breaks the AEDPoS consensus fairness guarantees:

**Consensus Integrity Breach:**
- The mining order is supposed to be determined by unpredictable randomness derived from secret in-values revealed through signatures
- Miners can now calculate which signature value yields any desired position (e.g., position #1) by solving: `desiredPosition = (signature.ToInt64() % minersCount) + 1`
- This allows systematic manipulation of block production scheduling across multiple rounds

**Direct Protocol Impact:**
- Violates the core security assumption that miners cannot predict or control their future mining positions
- Undermines the fairness of the consensus mechanism where all miners should have equal probabilistic access to each position
- Affects reward distribution as mining position influences block production opportunities
- Extra block producer selection, which depends on miner signatures, can be influenced

**Severity: HIGH** - This breaks a critical consensus protocol invariant. The deterministic signature calculation exists specifically to prevent position manipulation through unpredictable randomness.

## Likelihood Explanation

**Attacker Profile:**
- Must be an authorized miner in the current miner list
- This is the exact threat model consensus validation is designed to protect against - malicious miners are realistic adversaries

**Attack Execution:**
1. Miner receives consensus command to produce block with UpdateValue behavior
2. Miner calculates target signature: `targetSig = Hash.FromInt64((desiredOrder - 1) + k * minersCount)` for any chosen k
3. Miner modifies the `Signature` field in consensus extra data to the calculated value
4. Miner submits block with forged signature
5. Validation passes (only null/empty check exists)
6. State updated with forged signature
7. Next round mining order reflects the manipulated position

**Feasibility:**
- No special privileges required beyond normal miner status
- Trivial computational effort (single hash value calculation)
- No economic barriers (standard block production)
- Undetectable - no validation mechanism exists to catch the forgery
- Repeatable on every block the miner produces

**Likelihood: HIGH** - Any authorized miner can exploit this with 100% success rate on every block they produce.

## Recommendation

Add cryptographic validation in `UpdateValueValidationProvider` to verify the provided signature matches the expected calculation:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var publicKey = validationContext.SenderPubkey;
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[publicKey];
    
    if (minerInRound.PreviousInValue == null || minerInRound.PreviousInValue == Hash.Empty)
        return true; // First round or no previous in value
    
    // Calculate expected signature from previous round
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(minerInRound.PreviousInValue);
    
    // Verify provided signature matches expected calculation
    return minerInRound.Signature == expectedSignature;
}
```

Add this check to the `ValidateHeaderInformation` method after the existing null/empty validation.

## Proof of Concept

A malicious miner can manipulate their mining order by:

1. Observing the current round's miner count (e.g., 17 miners)
2. Calculating a signature that maps to position #1: `targetSig = Hash.FromInt64(0)` or `Hash.FromInt64(17)` or `Hash.FromInt64(34)`, etc.
3. Modifying the consensus extra data signature field before block submission
4. The block passes validation despite the forged signature
5. The next round assigns the miner to position #1

This can be repeated on every block to maintain advantageous positions across rounds, breaking the randomness guarantee that ensures fair distribution of mining opportunities.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L17-17)
```csharp
        minerInRound.Signature = providedInformation.Signature;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```
