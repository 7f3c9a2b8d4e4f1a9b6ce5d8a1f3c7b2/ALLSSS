# Audit Report

## Title
Unvalidated Decrypted Secret Pieces Enable Secret Sharing Corruption in AEDPoS Consensus

## Summary
The `UpdateLatestSecretPieces()` function accepts and stores decrypted secret pieces from miners without cryptographic validation, allowing malicious miners to submit arbitrary data. When `RevealSharedInValues()` uses these corrupted pieces for Shamir's Secret Sharing reconstruction, it produces wrong InValues that are stored as PreviousInValues without validation against the original OutValues, breaking the Byzantine fault tolerance of the secret sharing mechanism and compromising consensus history integrity.

## Finding Description

The vulnerability exists in the secret sharing mechanism of the AEDPoS consensus contract, specifically in how decrypted pieces are handled:

**Root Cause - Missing Validation in UpdateLatestSecretPieces()**: 
The function stores DecryptedPieces from miners with only an existence check, performing no cryptographic validation. [1](#0-0) 

The code only verifies that the target miner exists in `RealTimeMinersInformation` but does not validate:
1. The decrypted piece's cryptographic validity
2. Whether the submitting miner actually received an encrypted piece from the target miner
3. Whether the decrypted piece corresponds to any legitimate encrypted piece

**Attack Execution Path**:

During block production with `UpdateValue` behavior, a malicious miner can inject fake DecryptedPieces into `triggerInformation.DecryptedPieces`. The trigger information is prepared off-chain by `AEDPoSTriggerInformationProvider` and `SecretSharingService`, but the miner controls their node and can modify this data before submitting the consensus transaction. [2](#0-1) 

**Secret Reconstruction Without Validation**:

During the next round transition, `RevealSharedInValues()` reconstructs secrets using ALL stored DecryptedPieces without validating the reconstructed InValue against the original OutValue: [3](#0-2) 

The `SecretSharingHelper.DecodeSecret()` function is a pure mathematical reconstruction that cannot detect corrupted inputs - it will produce a result regardless of whether the input pieces are legitimate. [4](#0-3) 

**Why Existing Protections Fail**:

The `UpdateValueValidationProvider` only validates a miner's OWN submitted PreviousInValue by checking if `Hash(PreviousInValue) == OutValue`: [5](#0-4) 

This validation does NOT apply to PreviousInValues revealed through secret sharing reconstruction in `RevealSharedInValues()`, which are set directly without any hash verification.

## Impact Explanation

**Secret Sharing Byzantine Fault Tolerance Violation**:
The Shamir's Secret Sharing scheme is designed with a 2/3 threshold to tolerate Byzantine failures. However, the lack of validation means a single malicious miner can inject fake DecryptedPieces that corrupt the reconstruction for ANY miner. This fundamentally breaks the security guarantee that the scheme can tolerate up to 1/3 malicious participants. [6](#0-5) 

**Consensus History Integrity Compromise**:
Corrupted PreviousInValues are permanently stored in the blockchain state, creating an inconsistency where the stored values do not satisfy the fundamental invariant `Hash(PreviousInValue) == OutValue`. This affects:
- Auditability of consensus history
- Verifiability of past consensus rounds
- Trust in the stored consensus data

**Signature and Mining Order Impact**:
While honest miners can use their correct PreviousInValue from off-chain caches for signature calculation, the protocol stores corrupted values that cannot be verified. The signature is used to determine mining order for subsequent rounds: [7](#0-6) 

**Severity Assessment**: HIGH - Breaks cryptographic security guarantees and consensus integrity, though immediate operational impact may be limited as honest miners can use correct off-chain values for their own operations.

## Likelihood Explanation

**Attacker Prerequisites**: 
- Must be a miner in the consensus set (achievable through normal consensus participation)
- No special privileges beyond standard mining rights required

**Attack Complexity**: LOW
- Attacker modifies trigger information data before submitting consensus transaction
- No complex cryptographic operations needed
- No coordination with other miners required
- Single transaction can inject multiple fake pieces

**Detection Difficulty**: HIGH
- No on-chain validation exists to detect fake pieces
- Requires off-chain analysis comparing revealed InValues with original OutValues
- Most nodes trust the consensus data and won't perform such verification

**Reproducibility**: Easily reproducible whenever:
- Secret sharing is enabled via configuration contract
- Attacker produces any block with `UpdateValue` behavior

## Recommendation

Add validation in `RevealSharedInValues()` to verify that the reconstructed InValue matches the original OutValue before setting it as PreviousInValue:

```csharp
var revealedInValue = HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

// Add validation: verify reconstructed secret matches the original OutValue
if (HashHelper.ComputeFrom(revealedInValue) != anotherMinerInPreviousRound.OutValue)
{
    Context.LogDebug(() => $"Secret sharing reconstruction failed validation for {publicKeyOfAnotherMiner}");
    continue; // Skip setting this PreviousInValue
}

currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

Additionally, consider implementing cryptographic proofs that bind DecryptedPieces to their corresponding EncryptedPieces, or require miners to provide zero-knowledge proofs that they correctly decrypted the pieces.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a consensus round with secret sharing enabled
2. Having a malicious miner submit fake DecryptedPieces for other miners via `triggerInformation.DecryptedPieces`
3. Observing that `UpdateLatestSecretPieces()` stores these pieces without validation
4. During next round transition, observing that `RevealSharedInValues()` reconstructs a wrong InValue
5. Verifying that the stored PreviousInValue does not satisfy `Hash(PreviousInValue) == OutValue`

This can be tested by modifying the existing consensus tests to inject fake DecryptedPieces and verifying that they are accepted and used for reconstruction without validation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L122-125)
```csharp
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L143-146)
```csharp
        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L46-52)
```csharp
            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-65)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
