# Audit Report

## Title
Threshold Secret Sharing DoS: Incorrect DecryptedPieces Count Check Defeats Fault Tolerance

## Summary
The `RevealSharedInValues()` function in the AEDPoS consensus contract incorrectly requires 100% of miners' decrypted pieces instead of the intended 2/3 threshold. This allows any single miner to DoS the secret revelation mechanism by withholding decrypted pieces, forcing the system to use predictable fallback values and degrading consensus randomness quality.

## Finding Description

The vulnerability exists in the secret sharing revelation logic during consensus round transitions. The `RevealSharedInValues` function is called when producing the extra block that transitions to a new consensus round. [1](#0-0) 

The code correctly calculates a 2/3 threshold (`minimumCount`) for Shamir's Secret Sharing scheme: [2](#0-1) 

However, the critical bug occurs at the decrypted pieces check, which requires 100% participation (`minersCount`) instead of the threshold (`minimumCount`): [3](#0-2) 

This contradicts the cryptographic design, as the actual secret reconstruction correctly uses only the threshold parameter: [4](#0-3) 

The underlying Shamir's Secret Sharing implementation confirms that only `threshold` pieces are needed for reconstruction, not all pieces. The DecodeSecret function only iterates `threshold` times: [5](#0-4) 

The test suite explicitly validates the intended 2/3 threshold behavior, demonstrating that secret recovery should succeed once the minimum count is reached: [6](#0-5) 

When secrets cannot be revealed due to the incorrect check, the system uses predictable fallback values computed from the miner's public key and block height: [7](#0-6) 

This fallback `PreviousInValue` then feeds into signature calculation, which determines the mining order for the next round: [8](#0-7) 

The signature is computed by XORing the `inValue` with all miners' signatures from the current round: [9](#0-8) 

This signature then determines the mining order for the next round: [10](#0-9) 

The validation logic permits empty `PreviousInValue` fields, allowing blocks with unrevealed secrets to pass validation: [11](#0-10) 

Decrypted pieces are added via the `UpdateLatestSecretPieces` method, which simply accepts whatever pieces are provided in the trigger information without enforcing completeness: [12](#0-11) 

## Impact Explanation

**Operational DoS of Secret Revelation**: When any miner withholds their decrypted piece, the count falls below `minersCount`, causing the `continue` statement to skip secret revelation. This can be repeated systematically across rounds to prevent proper secret sharing from functioning.

**Degradation of Consensus Randomness**: The system falls back to predictable values computed from public keys and block heights rather than cryptographically random values from the secret sharing scheme. This reduces the quality of randomness used in consensus, making mining order more predictable.

**Defeat of Fault Tolerance**: The 2/3 threshold design specifically tolerates up to 1/3 Byzantine or offline miners. By requiring 100% participation, the system loses this safety margin and becomes vulnerable to any single point of failure.

**Manipulation of Mining Order**: By selectively preventing certain miners' secrets from being revealed, an attacker can force those miners to use predictable fallback values. Since the signature derived from `PreviousInValue` determines the next round's mining order, this allows potential bias in round transitions.

The entire network's security properties degrade when operating on fallback values instead of proper secret sharing, affecting all consensus participants.

## Likelihood Explanation

**Attacker Capabilities**: Any active miner in the consensus set can execute this attack. No special privileges beyond normal consensus participation are required.

**Attack Complexity**: Trivial. The attacker simply produces blocks normally but intentionally omits specific decrypted pieces from their trigger information. This requires no cryptographic expertise or complex coordination—just selective omission of data during block production.

**Detection Difficulty**: The attack is operationally indistinguishable from legitimate network issues such as packet loss, timing problems, or transient node failures. The validation logic explicitly permits empty `PreviousInValue` fields, so blocks with unrevealed secrets pass all validation checks.

**Economic Rationality**: The attack costs nothing beyond normal consensus participation. There are no penalties for incomplete decrypted pieces, and no on-chain evidence can distinguish malicious withholding from accidental omissions. The attacker can execute the attack repeatedly without consequences.

## Recommendation

Change line 36 in `AEDPoSContract_SecretSharing.cs` from:
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

To:
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This aligns the check with the intended 2/3 threshold design and the actual secret reconstruction logic, restoring the fault tolerance properties of Shamir's Secret Sharing scheme.

## Proof of Concept

The following test demonstrates that secret reconstruction works with only the 2/3 threshold (not 100% of pieces): [13](#0-12) 

The test explicitly breaks out of the loop once `MinimumCount` (2/3 threshold) is reached, proving that full participation is not needed for secret recovery. However, the on-chain contract incorrectly requires `minersCount` (100%) before attempting revelation, defeating this fault tolerance design.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L96-96)
```csharp
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L143-146)
```csharp
        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L22-23)
```csharp
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L36-36)
```csharp
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L50-50)
```csharp
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/InValueRecoveryTest.cs (L20-62)
```csharp
    [Fact]
    public void OffChain_DecryptMessage_Test()
    {
        var message = HashHelper.ComputeFrom("message").ToByteArray();
        var secrets =
            SecretSharingHelper.EncodeSecret(message, MinimumCount,
                EconomicContractsTestConstants.InitialCoreDataCenterCount);
        var encryptedValues = new Dictionary<string, byte[]>();
        var decryptedValues = new Dictionary<string, byte[]>();
        var ownerKeyPair = InitialCoreDataCenterKeyPairs[0];
        var othersKeyPairs = InitialCoreDataCenterKeyPairs.Skip(1).ToList();
        var decryptResult = new byte[0];

        var initial = 0;
        foreach (var keyPair in othersKeyPairs)
        {
            var encryptedMessage = CryptoHelper.EncryptMessage(ownerKeyPair.PrivateKey, keyPair.PublicKey,
                secrets[initial++]);
            encryptedValues.Add(keyPair.PublicKey.ToHex(), encryptedMessage);
        }

        // Check encrypted values.
        encryptedValues.Count.ShouldBe(EconomicContractsTestConstants.InitialCoreDataCenterCount - 1);

        // Others try to recover.
        foreach (var keyPair in othersKeyPairs)
        {
            var cipherMessage = encryptedValues[keyPair.PublicKey.ToHex()];
            var decryptMessage =
                CryptoHelper.DecryptMessage(ownerKeyPair.PublicKey, keyPair.PrivateKey, cipherMessage);
            decryptedValues.Add(keyPair.PublicKey.ToHex(), decryptMessage);

            if (decryptedValues.Count >= MinimumCount)
            {
                decryptResult = SecretSharingHelper.DecodeSecret(
                    decryptedValues.Values.ToList(),
                    Enumerable.Range(1, MinimumCount).ToList(), MinimumCount);
                break;
            }
        }

        decryptResult.ShouldBe(message);
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L42-46)
```csharp
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;
```
