# Audit Report

## Title
Missing Content Validation of DecryptedPieces Allows Corruption of Secret Sharing Reconstruction in AEDPoS Consensus

## Summary
The AEDPoS consensus contract's `RevealSharedInValues` function only validates the count of `DecryptedPieces` but not their content, allowing malicious miners to submit empty or corrupted byte arrays. These corrupted pieces are used in Shamir's Secret Sharing reconstruction without verification, producing incorrect `PreviousInValue` hashes that break the commit-reveal accountability mechanism and degrade consensus randomness.

## Finding Description

The vulnerability exists in the secret sharing fallback mechanism used when miners fail to directly reveal their `InValue` commitments. 

**Root Cause 1: Count-Only Validation**

The `RevealSharedInValues` method only checks that `DecryptedPieces.Count >= minersCount` but never validates the byte array content: [1](#0-0) 

**Root Cause 2: Unconditional Storage Without Validation**

The `PerformSecretSharing` method unconditionally stores attacker-provided `DecryptedPieces` without any content validation: [2](#0-1) 

**Root Cause 3: Missing Validation in UpdateValueValidationProvider**

The validation provider only checks `OutValue`, `Signature`, and directly-provided `PreviousInValue` hash relationships, but completely ignores `DecryptedPieces`: [3](#0-2) 

**Attack Execution:**

1. Malicious miner submits `UpdateValueInput` with `DecryptedPieces` containing empty or arbitrary byte arrays (correct count, wrong content) via the public `UpdateValue` method: [4](#0-3) [5](#0-4) 

2. During round transitions, `RevealSharedInValues` extracts `DecryptedPieces` and passes them to `SecretSharingHelper.DecodeSecret`: [6](#0-5) 

3. The Shamir's Secret Sharing implementation converts byte arrays to `BigInteger`. Empty arrays become `BigInteger(0)`, causing incorrect Lagrange interpolation: [7](#0-6) 

4. The corrupted reconstructed value is set as `PreviousInValue` without verification against the previously committed `OutValue`.

5. `SupplyCurrentRoundInformation` uses the corrupted `PreviousInValue` to calculate signatures: [8](#0-7) 

6. The signature calculation XORs the corrupted value with miner signatures: [9](#0-8) 

7. The corrupted signature affects mining order calculation via modulo arithmetic: [10](#0-9) 

## Impact Explanation

**Consensus Integrity Breach:** The AEDPoS consensus relies on a commit-reveal scheme where `OutValue = Hash(InValue)` ensures miners' random contributions are verifiable. The secret sharing mechanism serves as a fallback to reconstruct `InValues` when miners don't reveal them directly. By corrupting this reconstruction, attackers break the cryptographic commitment scheme, allowing miners to escape accountability for their committed random values. The reconstructed `PreviousInValue` is never validated against the previously committed `OutValue`, enabling undetectable corruption.

**Randomness Degradation:** The collective signature used for consensus randomness is calculated by XORing all miners' signatures with their `InValues`. Corrupted reconstructed `InValues` poison this collective randomness, undermining the unpredictability and fairness of the consensus mechanism. Mining order selection, which depends on signature-based modulo arithmetic, becomes susceptible to unpredictable corruption.

**Affected Scope:** All miners whose `InValues` are reconstructed via the secret sharing fallback mechanism are affected. Under Byzantine fault assumptions where up to 1/3 of miners may be malicious, even a single malicious miner can submit corrupted pieces that pass count validation but corrupt the reconstruction, as the implementation incorrectly requires pieces from ALL miners rather than just the 2/3 threshold.

## Likelihood Explanation

**Attack Feasibility:** The attack requires only submitting `UpdateValueInput` with `DecryptedPieces` containing the correct count but arbitrary/empty content through the public `UpdateValue` method. The Shamir Secret Sharing threshold is calculated as 2/3 of miners: [11](#0-10) 

However, the implementation requires ALL miners' pieces (line 36), not just the threshold. This means even a single Byzantine miner can corrupt reconstruction.

**Attack Complexity:** LOW - Attackers simply provide empty `ByteString` values (e.g., `ByteString.Empty`) with the correct count. No cryptographic expertise required.

**Detection Difficulty:** The system explicitly permits miners to not reveal `InValues`: [12](#0-11) 

This design masks the corruption since the system expects incomplete revelations, and count validation passes while content validation is absent.

## Recommendation

Implement multi-layered validation:

1. **Add content validation** in `PerformSecretSharing` to reject empty or malformed `DecryptedPieces`
2. **Verify reconstructed values** against commitments by adding validation in `RevealSharedInValues` that checks `Hash(revealedInValue) == previousOutValue`
3. **Fix threshold logic** to properly use only the 2/3 threshold rather than requiring all miners' pieces
4. **Consider verifiable secret sharing** schemes that provide cryptographic proof of correct decryption

Example fix for verification:

```csharp
// In RevealSharedInValues, after line 50
var revealedInValue = HashHelper.ComputeFrom(
    SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

// Add verification against previous commitment
var previousOutValue = previousRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].OutValue;
if (previousOutValue != null && HashHelper.ComputeFrom(revealedInValue) != previousOutValue)
{
    // Reconstruction failed verification, skip this miner
    continue;
}

currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

## Proof of Concept

A proof of concept would involve:

1. Deploy AEDPoS consensus contract with secret sharing enabled
2. Setup scenario where Miner A doesn't directly reveal `InValue` (sets `PreviousInValue = Hash.Empty`)
3. Malicious Miner B submits `UpdateValue` with `DecryptedPieces[MinerA] = ByteString.Empty` (empty bytes, correct count)
4. Trigger round transition calling `NextRound`
5. Observe `RevealSharedInValues` reconstructs incorrect `PreviousInValue` for Miner A
6. Verify reconstructed value doesn't match `Hash(MinerA.OutValue)` from previous round
7. Confirm corrupted value is used in `CalculateSignature` affecting mining order

The test would demonstrate that empty/corrupted `DecryptedPieces` pass validation and corrupt the secret sharing reconstruction mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L22-23)
```csharp
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L36-36)
```csharp
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L46-52)
```csharp
            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L263-264)
```csharp
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L191-199)
```csharp
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
```

**File:** protobuf/aedpos_contract.proto (L211-212)
```text
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 9;
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-64)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
            {
                var numerator = new BigInteger(sharedParts[i]);
                var denominator = BigInteger.One;
                for (var j = 0; j < threshold; j++)
                {
                    if (i == j) continue;

                    (numerator, denominator) =
                        MultiplyRational(numerator, denominator, orders[j], orders[j] - orders[i]);
                }

                result += RationalToWhole(numerator, denominator);
                result %= SecretSharingConsts.FieldPrime;
            }

            return result.ToBytesArray();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
