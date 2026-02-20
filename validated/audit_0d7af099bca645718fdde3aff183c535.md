# Audit Report

## Title
Overly Strict Validation in Secret Sharing Reconstruction Defeats Byzantine Fault Tolerance

## Summary
The `RevealSharedInValues` method in the AEDPoS consensus contract requires 100% miner participation for secret reconstruction, contradicting Shamir's Secret Sharing's 2/3 threshold design. This allows a single non-participating miner to prevent all InValue revelation, completely defeating the Byzantine fault tolerance property and enabling manipulation of the consensus randomness mechanism.

## Finding Description

The vulnerability exists in the secret sharing reconstruction validation logic within the consensus contract. The system correctly calculates the 2/3 threshold (minimumCount) required by Shamir's Secret Sharing scheme, [1](#0-0)  but then imposes an incorrect requirement that ALL miners must provide decrypted pieces before reconstruction can proceed. [2](#0-1) 

The actual reconstruction call correctly uses the calculated `minimumCount` (2/3 threshold) parameter, [3](#0-2)  confirming that mathematically only 2/3 of shares are required. The Shamir's Secret Sharing implementation itself only iterates over the threshold number of shares, [4](#0-3)  proving the algorithm only needs threshold shares.

The test suite explicitly demonstrates the intended behavior - reconstruction succeeds when MinimumCount shares are available. [5](#0-4) 

During UpdateValue transactions, decrypted pieces are distributed to other miners through the PerformSecretSharing method. [6](#0-5)  The ExtractInformationToUpdateConsensus function correctly collects only available decrypted pieces, [7](#0-6)  but when RevealSharedInValues is invoked during NextRound, [8](#0-7)  the overly strict validation prevents reconstruction even when sufficient shares exist.

## Impact Explanation

**HIGH severity** - This vulnerability breaks a critical security property of the consensus mechanism:

1. **Consensus Integrity Degradation**: The secret sharing mechanism is designed to reveal miners' committed InValues even if they go offline or act maliciously, ensuring randomness cannot be manipulated. By requiring 100% participation instead of the 2/3 threshold, any single miner can prevent all InValue reconstruction.

2. **Byzantine Fault Tolerance Defeat**: The system was explicitly designed to tolerate up to 1/3 faulty or malicious nodes (hence the 2/3 threshold calculation). This bug creates a single point of failure, completely negating the fault tolerance guarantee that is fundamental to consensus security.

3. **Randomness Manipulation Risk**: Miners can hide their previously committed InValues, potentially manipulating the VRF-based random number generation that underlies consensus security and fairness.

4. **Protocol-Wide Impact**: Affects all consensus participants and any systems or applications relying on consensus randomness integrity.

## Likelihood Explanation

**VERY HIGH likelihood**:

1. **Trivial Attack Complexity**: The attacker simply omits DecryptedPieces from their UpdateValue transaction or provides only partial decryptions. No special timing, economic resources, or coordination required.

2. **Realistic Preconditions**: Attacker must be an active miner in the consensus round - a precondition explicitly expected in the threat model as the system must assume potentially adversarial miners.

3. **Indistinguishable from Benign Failures**: The attack is passive (omission) and appears identical to legitimate network issues or node downtime, making detection extremely difficult.

4. **Frequent Natural Occurrence**: This condition triggers even under normal operations whenever a single miner is offline or lagging, meaning the vulnerability manifests frequently without malicious intent.

## Recommendation

Change the validation check to use the calculated threshold instead of requiring all miners:

**Current (vulnerable) code at line 36:**
```
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**Fixed code:**
```
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This aligns the validation with the mathematical requirements of Shamir's Secret Sharing and restores the Byzantine fault tolerance property by allowing reconstruction with 2/3 of shares.

## Proof of Concept

The existing test suite already demonstrates that reconstruction should work with only MinimumCount shares. [9](#0-8) 

A POC demonstrating the vulnerability would involve:
1. Setting up a consensus round with N miners
2. Having one miner fail to provide DecryptedPieces during UpdateValue
3. Attempting NextRound block production
4. Observing that RevealSharedInValues skips reconstruction at line 36 despite having >= 2N/3 shares
5. Confirming that PreviousInValue remains unset, breaking randomness revelation

The test at lines 52-58 shows the secret can be decoded with only MinimumCount (2/3) shares, proving the current contract validation is overly restrictive.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L36-36)
```csharp
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-62)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L26-28)
```csharp
        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```
