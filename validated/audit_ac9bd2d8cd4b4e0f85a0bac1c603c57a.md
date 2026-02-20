# Audit Report

## Title
Missing Validation of DecryptedPieces Content Allows Corruption of Secret Sharing Reconstruction

## Summary
The AEDPoS consensus contract's secret sharing mechanism lacks content validation on `DecryptedPieces` submitted by miners, allowing Byzantine miners to corrupt the reconstruction of `PreviousInValue` for miners who fail to reveal directly. The reconstructed values are never validated against their cryptographic commitments (`OutValue`), breaking consensus randomness integrity.

## Finding Description

The vulnerability exists in the secret sharing fallback mechanism used when miners fail to reveal their `InValue` directly. The attack proceeds through three critical validation gaps:

**Gap 1: No Content Validation on Submission**

When miners submit `UpdateValueInput` during block production, the `PerformSecretSharing` method stores their `DecryptedPieces` without any content validation: [1](#0-0) 

Miners can submit arbitrary byte arrays (empty, corrupted, or malicious data) and the system accepts them unconditionally.

The `UpdateValueValidationProvider` only validates `OutValue` and `Signature`, completely ignoring `DecryptedPieces`: [2](#0-1) 

**Gap 2: Count-Only Validation During Reconstruction**

When `RevealSharedInValues` is called during round transitions, it only validates the COUNT of pieces, never their content: [3](#0-2) 

The method extracts `DecryptedPieces` values and passes them directly to `SecretSharingHelper.DecodeSecret` without any validation. Empty byte arrays become `BigInteger(0)` in the Shamir reconstruction: [4](#0-3) 

**Gap 3: No Validation Against Cryptographic Commitment**

The reconstructed `PreviousInValue` is set directly without verifying that `Hash(revealedInValue) == previousRound.OutValue`. This violates the fundamental commit-reveal security property. Compare this to the validation that EXISTS when miners reveal directly: [5](#0-4) 

But no such validation exists for reconstructed values in `RevealSharedInValues`.

**Attack Propagation to Consensus**

The corrupted `PreviousInValue` is later retrieved and used to calculate signatures that determine mining order: [6](#0-5) 

These signatures are calculated by XORing with all miners' signatures, directly affecting consensus randomness: [7](#0-6) 

## Impact Explanation

**Consensus Integrity Breach**: The AEDPoS protocol relies on a commit-reveal scheme where `OutValue = Hash(InValue)` provides a cryptographic commitment. The secret sharing mechanism is designed as a backup when miners don't reveal directly. By corrupting the reconstruction, attackers break this fundamental guarantee - miners can effectively escape accountability for their random number contributions since the revealed value no longer matches their commitment.

**Randomness Manipulation**: The `CalculateSignature` method generates consensus randomness by XORing all miners' signatures, which are derived from `InValues`. Corrupted `InValues` produce incorrect signatures, manipulating the randomness that determines block producer selection order. This undermines the unpredictability and fairness guarantees of the consensus mechanism.

**Broad Network Impact**: Any honest miner whose `InValue` must be reconstructed via secret sharing becomes vulnerable. The entire network's consensus randomness quality degrades, potentially enabling targeted manipulation of mining schedules.

## Likelihood Explanation

**Feasible Attack Prerequisites**: 
- The Shamir threshold is 2/3 of miners, but reconstruction requires ALL miners to submit pieces
- Up to 1/3 Byzantine miners are within standard consensus assumptions
- Target miners must fail to reveal `InValue` directly (offline, censored, or deliberately withholding)
- Malicious miners submit `UpdateValueInput` through normal block production (no special privileges required) [8](#0-7) 

**Low Attack Complexity**: Attackers simply provide `DecryptedPieces` with correct count but corrupted `ByteString` values. No cryptographic expertise needed - even empty byte arrays corrupt the reconstruction.

**Difficult Detection**: The system explicitly permits miners not to reveal values directly, as shown in the code comment "It is permissible for miners not publish their in values": [9](#0-8) 

This design philosophy makes corruption blend in with expected behavior.

## Recommendation

Add cryptographic validation to verify that reconstructed `PreviousInValue` matches the original commitment:

```csharp
// In RevealSharedInValues, after line 50:
var revealedInValue = HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

// Add validation against commitment:
if (HashHelper.ComputeFrom(revealedInValue) != anotherMinerInPreviousRound.OutValue)
{
    Context.LogDebug(() => $"Revealed in value does not match commitment for {publicKeyOfAnotherMiner}");
    continue; // Skip setting corrupted value
}

currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

Additionally, consider validating individual `DecryptedPieces` during submission by requiring miners to prove they correctly decrypted from the corresponding `EncryptedPieces`, or implement a dispute mechanism where honest miners can challenge invalid pieces.

## Proof of Concept

A proof of concept would demonstrate:

1. Setup: Deploy AEDPoS contract with 3 miners where 1 is Byzantine
2. Round 1: All miners produce blocks normally, establishing `OutValue` commitments
3. Round 2: One honest miner M2 fails to reveal `InValue` directly (goes offline)
4. Byzantine miner M3 submits `UpdateValueInput` with `DecryptedPieces[M2] = empty_bytes`
5. During `NextRound`: `RevealSharedInValues` reconstructs M2's `PreviousInValue` using corrupted piece
6. Verify: `Hash(reconstructedInValue) != M2.OutValue` (commitment broken)
7. Impact: `SupplyCurrentRoundInformation` uses corrupted value to calculate signature
8. Result: Consensus randomness is manipulated, mining order altered

The test would confirm that the reconstructed value doesn't match the commitment and that no validation error occurs, proving the vulnerability is exploitable.

## Notes

The vulnerability is particularly insidious because it exploits the **fallback mechanism** designed for resilience. The secret sharing was meant to improve availability when miners are offline, but the lack of validation transforms it into an attack vector. The strict requirement for ALL miners to participate (line 36 check for `minersCount`) means the system cannot exclude Byzantine miners' corrupted pieces, making the attack more severe than initially apparent.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-297)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
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

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-52)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L80-92)
```csharp
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
                else
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-199)
```csharp
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
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
