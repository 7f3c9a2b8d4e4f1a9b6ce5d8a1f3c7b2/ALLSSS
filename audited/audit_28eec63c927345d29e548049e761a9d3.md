# Audit Report

## Title
Missing Validation of DecryptedPieces Content Allows Corruption of Secret Sharing Reconstruction

## Summary
The AEDPoS consensus contract's `RevealSharedInValues` function only validates the count of `DecryptedPieces` but not their content, allowing malicious miners to submit empty or corrupted byte arrays that pass validation. When used in Shamir's Secret Sharing reconstruction, these corrupted pieces produce incorrect `PreviousInValue` hashes, breaking the consensus randomness mechanism and miner accountability.

## Finding Description

**Root Cause:** The `RevealSharedInValues` method performs only count-based validation on `DecryptedPieces`, checking that the count meets the minimum threshold but never validating whether the byte arrays contain valid data. [1](#0-0) 

This insufficient validation allows malicious miners to submit `UpdateValueInput` with arbitrary `DecryptedPieces` content. The `PerformSecretSharing` method unconditionally stores these values without any content validation: [2](#0-1) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and the hash relationship of `PreviousInValue`, but completely ignores `DecryptedPieces` content: [3](#0-2) 

**Attack Execution:** When `RevealSharedInValues` is called during round transitions, it extracts all `DecryptedPieces` and passes them to `SecretSharingHelper.DecodeSecret` for reconstruction: [4](#0-3) 

In the Shamir's Secret Sharing implementation, the reconstruction uses Lagrange interpolation where each piece is converted to `BigInteger`. Empty byte arrays become `BigInteger(0)`, and any corrupted value will produce an incorrect reconstruction: [5](#0-4) 

The corrupted `PreviousInValue` is then set for the target miner and subsequently used by `SupplyCurrentRoundInformation` to calculate signatures. This method retrieves the corrupted `PreviousInValue` and uses it in signature calculation: [6](#0-5) 

The signature calculation XORs the corrupted `PreviousInValue` with all miner signatures, producing wrong randomness that determines mining order: [7](#0-6) 

The corrupted signature then affects the mining order calculation: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Breach:** The AEDPoS consensus relies on a commit-reveal scheme where `OutValue = Hash(InValue)` must be verifiable. The secret sharing mechanism serves as a fallback to reconstruct `InValues` when miners fail to reveal them. By corrupting this reconstruction, attackers break the cryptographic commitment scheme, allowing miners to escape accountability for their random number contributions.

**Randomness Manipulation:** The `CalculateSignature` method generates consensus randomness by XORing all miners' signatures derived from their `InValues`. Corrupted `InValues` lead to wrong signatures, which directly affect block producer selection order through modulo arithmetic. This undermines the unpredictability and fairness of the consensus mechanism.

**Affected Parties:** All honest miners whose `InValues` are reconstructed via the corrupted secret sharing fallback, and the entire network suffers from degraded randomness quality, potentially enabling targeted mining order manipulation.

## Likelihood Explanation

**Attack Requirements:** The Shamir's Secret Sharing threshold is set to 2/3 of miners: [9](#0-8) 

Any miner can submit `UpdateValueInput` containing `DecryptedPieces` with arbitrary content through normal block production. Multiple colluding miners (a realistic scenario under Byzantine fault assumptions where up to 1/3 of miners may be malicious) can coordinate to inject corrupted pieces.

**Attack Complexity:** Low - attackers simply provide `DecryptedPieces` with the correct count but empty or malformed `ByteString` values. No cryptographic sophistication required.

**Detection Difficulty:** The system is designed to be permissive about missing `InValues`: [10](#0-9) 

This design masks the corruption, as count validation passes and the system expects some miners may not reveal values directly.

## Recommendation

Add content validation for `DecryptedPieces` in multiple layers:

1. **In `PerformSecretSharing`:** Validate that each decrypted piece is non-empty before storing:
```csharp
foreach (var decryptedPreviousInValue in input.DecryptedPieces)
{
    Assert(decryptedPreviousInValue.Value != null && 
           decryptedPreviousInValue.Value.Length > 0, 
           "Decrypted piece cannot be empty.");
    round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
        .Add(publicKey, decryptedPreviousInValue.Value);
}
```

2. **In `RevealSharedInValues`:** Add a pre-check before reconstruction:
```csharp
var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
    .Select(s => s.ToByteArray()).ToList();

// Validate all pieces are non-empty
Assert(sharedParts.All(p => p != null && p.Length > 0), 
       "All decrypted pieces must contain valid data.");
```

3. **In `UpdateValueValidationProvider`:** Add validation for `DecryptedPieces` content when present.

## Proof of Concept

A proof of concept would demonstrate:
1. Setup a test network with multiple miners
2. Have a malicious miner submit `UpdateValueInput` with `DecryptedPieces` containing correct count but empty `ByteString` values
3. Trigger `NextRound` behavior to invoke `RevealSharedInValues`
4. Observe that the reconstructed `PreviousInValue` is incorrect
5. Verify that the wrong signature is calculated
6. Show that mining order in subsequent rounds is affected

The test would verify that empty `DecryptedPieces` pass validation but corrupt the consensus state, confirming the vulnerability exists in production code paths.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L22-23)
```csharp
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-36)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L46-50)
```csharp
            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
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

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L48-51)
```csharp
            for (var i = 0; i < threshold; i++)
            {
                var numerator = new BigInteger(sharedParts[i]);
                var denominator = BigInteger.One;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-114)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
