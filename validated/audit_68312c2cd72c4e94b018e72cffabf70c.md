# Audit Report

## Title
Consensus Signature Forgery Allows Mining Order Manipulation in AEDPoS UpdateValue

## Summary
The AEDPoS consensus mechanism fails to verify that the `Signature` field submitted in `UpdateValueInput` matches the deterministically calculated value, allowing any authorized miner to forge signatures that directly control their mining position in the next round. The signature determines next-round order via modulus operation, breaking the randomness-based fairness guarantees of the consensus protocol.

## Finding Description

The vulnerability exists in the UpdateValue consensus flow where miners submit block information including a signature. The signature should be calculated as `XOR(previousInValue, XOR(all signatures from previous round))` [1](#0-0) , but the system never verifies this calculation matches the submitted value.

**Correct Signature Calculation (Block Production):**

During honest block production, the signature is correctly calculated using the previous round's state [2](#0-1) .

**Missing Signature Verification (Block Validation):**

The validation provider only checks that the signature field is non-null and non-empty, never verifying correctness [3](#0-2) .

**Unverified Signature Storage:**

When processing the block, the provided signature is directly stored without verification [4](#0-3) .

**Critical Usage for Next Round Order:**

The unverified signature directly determines the miner's position in the next round through modulus arithmetic [5](#0-4) .

**Attack Execution:**

A malicious authorized miner can:
1. Run consensus command generation locally to get correctly calculated data
2. Calculate which signature value would yield desired next-round position: `targetSignature` where `(targetSignature.ToInt64() % minersCount) + 1 = desired_position`
3. Modify the Round object to replace the correct signature with the forged value before generating block data
4. Broadcast the block with forged signature in both header and UpdateValueInput
5. Validation passes because UpdateValueValidationProvider only performs null/empty check [6](#0-5) 
6. Forged signature is stored and used for next round ordering

The post-execution validation comparing round hashes will pass because both the block header and the updated state contain the same forged signature [7](#0-6) .

## Impact Explanation

This vulnerability breaks a **critical consensus invariant**: that mining order is determined fairly through randomness derived from cryptographic commitments. The impact is HIGH because:

1. **Consensus Integrity Violation**: Any authorized miner can systematically manipulate their position in every round, obtaining position #1 to maximize block rewards and control extra block producer selection
2. **Fairness Breakdown**: The deterministic XOR-based randomness mechanism becomes attacker-controlled, violating the core security property of the AEDPoS protocol
3. **Undetectable Exploitation**: No validation exists to detect the forgery; honest nodes cannot distinguish forged from legitimate signatures
4. **Persistent Attack**: Can be repeated indefinitely across all rounds with no economic cost beyond gas fees

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **Low Barrier**: Any authorized miner can exploit this - protecting against malicious miners is the fundamental purpose of consensus validation
2. **Trivial Execution**: Attack requires simple arithmetic to calculate desired signature value and modifying the Round object before generating block data
3. **Guaranteed Success**: No verification logic exists to block the attack; forged signatures pass all validation checks
4. **No Detection**: The protocol cannot distinguish forged signatures from correct ones without implementing the missing verification

The only precondition is being an authorized miner, which is the exact threat model consensus systems must defend against.

## Recommendation

Add signature verification in `UpdateValueValidationProvider.ValidateHeaderInformation`:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var previousInValue = minerInRound.PreviousInValue;
    
    if (previousInValue == null || previousInValue == Hash.Empty)
        return true; // First round or no previous value
        
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
    return minerInRound.Signature == expectedSignature;
}
```

Then add this check in the `ValidateHeaderInformation` method:

```csharp
if (!ValidateSignature(validationContext))
    return new ValidationResult { Message = "Invalid signature - does not match expected calculation." };
```

## Proof of Concept

A test demonstrating the vulnerability would:

1. Setup a test environment with multiple miners
2. Generate a valid consensus command for a miner
3. Modify the signature field to a calculated value that gives position #1: `forgedSig = Hash.FromRawBytes(BitConverter.GetBytes((long)1))`
4. Submit UpdateValue with the forged signature
5. Verify that validation passes
6. Verify that the miner's `SupposedOrderOfNextRound` is set to 1
7. Confirm no error was raised despite the signature being incorrect

The test would demonstrate that the forged signature is accepted and directly controls the next round position, proving the consensus manipulation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-244)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-80)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```
