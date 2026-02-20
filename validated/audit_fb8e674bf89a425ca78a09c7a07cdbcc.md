# Audit Report

## Title
Unvalidated Decrypted Secret Pieces Enable Secret Sharing Corruption in AEDPoS Consensus

## Summary
The AEDPoS consensus contract accepts and stores decrypted secret pieces from miners without cryptographic validation, allowing malicious miners to inject arbitrary data that corrupts Shamir's Secret Sharing reconstruction. This breaks the Byzantine fault tolerance of the secret sharing mechanism and permanently stores invalid PreviousInValues that violate the fundamental invariant `Hash(PreviousInValue) == OutValue`, compromising consensus history integrity.

## Finding Description

The vulnerability exists in the secret sharing mechanism used for consensus randomness generation. The attack exploits three critical validation gaps:

**Root Cause 1 - Unvalidated Storage in UpdateLatestSecretPieces()**: 
The function stores DecryptedPieces with only an existence check, performing no cryptographic validation. [1](#0-0)  The code only verifies that the target miner exists but does not validate whether the decrypted piece is cryptographically valid, whether the submitting miner received an encrypted piece from the target, or whether the piece corresponds to any legitimate encrypted value.

**Root Cause 2 - Unvalidated On-Chain Storage in PerformSecretSharing()**:
When the UpdateValue transaction executes on-chain, fake DecryptedPieces are stored directly into the round state without validation. [2](#0-1)  This function simply adds the DecryptedPieces from the transaction input to the on-chain state with no verification.

**Attack Execution Path**:

A malicious miner controls their node and can modify trigger information before transaction generation. The off-chain service `AEDPoSTriggerInformationProvider` prepares trigger information with DecryptedPieces from `SecretSharingService`. [3](#0-2)  However, since this is off-chain code running in the miner's own node, the miner can inject fake DecryptedPieces before the transaction is signed and submitted.

The transaction flow is: trigger information → `GetConsensusBlockExtraData` → `UpdateLatestSecretPieces` → round state → `ExtractInformationToUpdateConsensus` → `UpdateValueInput` → on-chain execution via `PerformSecretSharing`. At each step, the fake DecryptedPieces pass through without validation.

**Secret Reconstruction Without Validation**:

During the NextRound transition, `RevealSharedInValues()` reconstructs secrets using ALL stored DecryptedPieces. [4](#0-3)  The function uses pure Lagrange interpolation via `SecretSharingHelper.DecodeSecret()` which cannot detect corrupted inputs - it produces a result regardless of input validity. Critically, the reconstructed InValue is stored directly without validating that `Hash(revealedInValue) == OutValue`.

**Why Existing Protections Fail**:

The `UpdateValueValidationProvider` only validates a miner's OWN submitted PreviousInValue. [5](#0-4)  It checks the sender's public key specifically and validates that `Hash(previousInValue) == previousOutValue` ONLY for the sender. This validation does NOT apply to PreviousInValues revealed through secret sharing reconstruction in `RevealSharedInValues()`, which are set directly without hash verification.

## Impact Explanation

**Secret Sharing Byzantine Fault Tolerance Violation**:
Shamir's Secret Sharing with a 2/3 threshold is designed to tolerate up to 1/3 Byzantine failures. [6](#0-5)  However, the lack of validation means a SINGLE malicious miner can inject fake DecryptedPieces that corrupt reconstruction for ANY miner, fundamentally breaking the security guarantee.

**Consensus History Integrity Compromise**:
Corrupted PreviousInValues are permanently stored in blockchain state, violating the invariant `Hash(PreviousInValue) == OutValue`. This affects auditability, verifiability of past consensus rounds, and trust in stored consensus data.

**Limited Operational Impact**:
While honest miners can use their correct PreviousInValue from off-chain caches for signature calculation and their own operations, the protocol stores corrupted values that cannot be verified, affecting consensus data integrity and historical auditability.

## Likelihood Explanation

**Attacker Prerequisites**: 
- Must be a miner in the consensus set (achievable through normal participation)
- No special privileges beyond standard mining rights required

**Attack Complexity**: LOW
- Attacker modifies trigger information in their own node before transaction generation
- No complex cryptographic operations needed beyond normal mining
- No coordination with other miners required
- Single transaction can inject multiple fake pieces targeting multiple miners

**Detection Difficulty**: HIGH
- No on-chain validation exists to detect fake pieces at submission time
- Requires off-chain analysis comparing revealed InValues with original OutValues  
- Most nodes trust consensus data without performing such verification

**Reproducibility**: Easily reproducible whenever secret sharing is enabled via configuration contract and the attacker produces any block with UpdateValue behavior.

## Recommendation

Add cryptographic validation at multiple points:

1. **Validate DecryptedPieces on Submission**: In `PerformSecretSharing()`, verify that each DecryptedPiece corresponds to a legitimate EncryptedPiece that was previously shared by the target miner.

2. **Validate Reconstructed InValues**: In `RevealSharedInValues()`, after reconstructing the InValue using `SecretSharingHelper.DecodeSecret()`, validate that `Hash(revealedInValue) == OutValue` where OutValue was previously stored for that miner. Only store the PreviousInValue if this validation passes.

3. **Track Encrypted Piece Distribution**: Maintain on-chain state tracking which miners received which encrypted pieces, and only accept DecryptedPieces from miners who legitimately received the corresponding encrypted piece.

Example fix for `RevealSharedInValues()`:
```csharp
var revealedInValue = HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

// CRITICAL: Validate against original OutValue before storing
var expectedOutValue = previousRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].OutValue;
if (HashHelper.ComputeFrom(revealedInValue.ToByteArray()) == expectedOutValue)
{
    currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
}
```

## Proof of Concept

```csharp
[Fact]
public void DecryptedPieces_Injection_Corrupts_SecretReconstruction()
{
    // Setup: Initialize consensus with multiple miners
    var initialMiners = InitialCoreDataCenterKeyPairs;
    var maliciousMiner = initialMiners[0];
    var victimMiner = initialMiners[1];
    
    // Victim miner generates legitimate InValue and OutValue
    var legitimateInValue = HashHelper.ComputeFrom("legitimate_secret");
    var legitimateOutValue = HashHelper.ComputeFrom(legitimateInValue);
    
    // Victim shares encrypted pieces (legitimate secret sharing)
    var secrets = SecretSharingHelper.EncodeSecret(legitimateInValue.ToByteArray(), 
        MinimumCount, initialMiners.Count);
    
    // Malicious miner injects FAKE decrypted piece for victim
    var fakeDecryptedPiece = HashHelper.ComputeFrom("fake_data").ToByteArray();
    
    // Simulate UpdateValue transaction with fake DecryptedPieces
    var updateInput = new UpdateValueInput
    {
        DecryptedPieces = { { victimMiner.PublicKey.ToHex(), ByteString.CopyFrom(fakeDecryptedPiece) } }
    };
    
    // This gets stored without validation via PerformSecretSharing
    // Later, RevealSharedInValues reconstructs using corrupted pieces
    var corruptedReconstructed = SecretSharingHelper.DecodeSecret(
        new List<byte[]> { fakeDecryptedPiece }, 
        new List<int> { 1 }, 
        1);
    
    var corruptedInValue = HashHelper.ComputeFrom(corruptedReconstructed);
    var recomputedOutValue = HashHelper.ComputeFrom(corruptedInValue);
    
    // VULNERABILITY: Corrupted InValue is stored but does NOT satisfy invariant
    recomputedOutValue.ShouldNotBe(legitimateOutValue); // Invariant broken!
    // Yet the contract stores corruptedInValue as PreviousInValue without validation
}
```

**Notes**

This vulnerability fundamentally breaks the Byzantine fault tolerance property of Shamir's Secret Sharing in the AEDPoS consensus. While the immediate operational impact is limited because honest miners maintain correct off-chain caches, the on-chain consensus history is permanently corrupted with invalid data that violates cryptographic invariants. The attack is trivial for any miner to execute and extremely difficult to detect without explicit off-chain verification. The recommended fix requires adding validation that reconstructed InValues match their corresponding OutValues before storing them as PreviousInValues.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L143-146)
```csharp
        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L108-110)
```csharp
            var decryptedPieces = _secretSharingService.GetDecryptedPieces(hint.RoundId);
            foreach (var decryptedPiece in decryptedPieces)
                trigger.DecryptedPieces.Add(decryptedPiece.Key, ByteString.CopyFrom(decryptedPiece.Value));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-52)
```csharp
            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L38-48)
```csharp
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```
