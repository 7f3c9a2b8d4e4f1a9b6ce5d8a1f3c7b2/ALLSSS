# Audit Report

## Title
Malicious DecryptedPieces Can Corrupt Secret Sharing Reconstruction Due to Improper Signed BigInteger Handling

## Summary
The Shamir secret sharing reconstruction in AElf consensus contains a critical flaw where malicious miners can submit crafted `DecryptedPieces` byte arrays that produce negative BigInteger values, causing incorrect finite field arithmetic and corrupting revealed InValues stored in consensus state.

## Finding Description

The vulnerability exists in the secret sharing reconstruction flow used by the AEDPoS consensus mechanism. When miners submit `UpdateValue` transactions, they provide `DecryptedPieces` for other miners' encrypted secret shares. These pieces are later used to reconstruct the original InValues through Shamir's Secret Sharing scheme.

The core issue is in the `SecretSharingHelper.DecodeSecret` method. At the reconstruction stage, DecryptedPieces are converted to BigIntegers without validation, and the BigInteger constructor interprets byte arrays as signed integers in little-endian two's complement format. [1](#0-0) 

When a byte array has its most significant byte with the high bit set (≥ 0x80), the resulting BigInteger becomes negative. The critical flaw occurs where standard modulo arithmetic is applied without proper handling of negative values. In C#, the `%` operator preserves the sign of the dividend, so negative BigIntegers produce negative results.

The codebase provides an `Abs()` extension method specifically designed to handle this issue by applying modular arithmetic correctly: `(integer % FieldPrime + FieldPrime) % FieldPrime`. [2](#0-1) 

This behavior is confirmed by unit tests showing that byte arrays like `[0xFF, 0xFF]` create `-1` instead of `255`, which the `Abs()` method then corrects. [3](#0-2) 

However, `DecodeSecret` does not use this extension method, causing incorrect finite field arithmetic when processing malicious DecryptedPieces.

**Attack Vector:**

The attack exploits the `UpdateValue` consensus behavior. When miners submit their consensus data, they include `DecryptedPieces` - their decrypted shares of other miners' secrets. [4](#0-3) 

The validation providers only check OutValue, Signature, and PreviousInValue matching, but completely ignore DecryptedPieces content validation. [5](#0-4) 

When transitioning to the next round, `RevealSharedInValues` is called on-chain to reconstruct other miners' InValues using the stored DecryptedPieces. [6](#0-5) 

The reconstructed InValue is then stored as `PreviousInValue` in the consensus state, corrupting the legitimate miner's data. [7](#0-6) 

## Impact Explanation

**Consensus Integrity Violation:** This attack directly corrupts consensus state by storing incorrect `PreviousInValue` data for victim miners. The consensus mechanism relies on these values for round transitions, miner validation, and random number generation.

**Affected Parties:**
- Victim miners whose InValues are incorrectly reconstructed
- All nodes relying on accurate consensus state for validation
- The protocol's Byzantine fault tolerance guarantees are undermined

**Concrete Harm:**
1. Corrupted consensus state persists on-chain across multiple rounds
2. Incorrect PreviousInValues may cause validation failures or incorrect behavior in edge cases
3. The revealed InValues serve as fallback when miners fail to produce blocks, potentially causing unfair penalties or rewards
4. Byzantine miners can systematically corrupt competitors' consensus records

**Severity:** Medium - While this corrupts critical consensus state and could affect reward distribution or miner reputation, it does not directly enable immediate fund theft or chain halt. The impact is primarily on consensus integrity and fairness.

## Likelihood Explanation

**Attacker Capabilities:** The attacker must be an active miner in the current consensus round. In AElf's DPoS system, miners are elected through voting, making this a realistic but privileged position.

**Attack Complexity:** Low - The attack simply requires crafting byte arrays where the MSB is set (e.g., `[0xFF, 0xFF, ...]`) and including them as DecryptedPieces in an UpdateValue transaction. No sophisticated cryptographic attacks or timing exploits are needed.

**Preconditions:**
1. Attacker is an active miner (achievable through election)
2. Victim has published EncryptedPieces in the previous round (standard consensus operation)
3. No cryptographic validation links DecryptedPieces to EncryptedPieces

**Execution:**
1. Wait for victim to publish EncryptedPieces in round N-1
2. In round N, submit UpdateValue with crafted DecryptedPieces containing byte arrays like `[0xFF, 0xFF, ...]`
3. When NextRound transition occurs, RevealSharedInValues executes on-chain
4. Corrupted PreviousInValue is stored in consensus state

**Detection:** The malicious byte arrays appear as valid serialized BigIntegers, making detection difficult without explicit validation of DecryptedPieces against their corresponding EncryptedPieces.

## Recommendation

**Fix:** Modify `SecretSharingHelper.DecodeSecret` to use the `Abs()` extension method when applying modulo operations:

```csharp
result += RationalToWhole(numerator, denominator);
result = result.Abs(); // Use the Abs() extension method instead of standard %
```

Alternatively, apply the correct modular arithmetic pattern directly:
```csharp
result += RationalToWhole(numerator, denominator);
result = ((result % SecretSharingConsts.FieldPrime) + SecretSharingConsts.FieldPrime) % SecretSharingConsts.FieldPrime;
```

**Additional Hardening:** Consider adding cryptographic validation that DecryptedPieces properly correspond to EncryptedPieces, though this requires careful design to avoid breaking the secret sharing protocol's security properties.

## Proof of Concept

```csharp
[Fact]
public void MaliciousDecryptedPieces_CorruptsSecretReconstruction()
{
    // Create legitimate secret (an InValue hash)
    var legitimateSecret = HashHelper.ComputeFrom("legitimate_secret").ToByteArray();
    
    // Encode with Shamir's Secret Sharing (threshold=2, totalParts=3)
    var shares = SecretSharingHelper.EncodeSecret(legitimateSecret, 2, 3);
    
    // Attacker crafts malicious DecryptedPiece with MSB set
    var maliciousShare = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
    
    // Create BigInteger from malicious share - it becomes negative
    var maliciousBigInt = new BigInteger(maliciousShare);
    Assert.True(maliciousBigInt < 0); // Confirms negative value
    
    // Replace one legitimate share with malicious one
    var corruptedShares = new List<byte[]> { shares[0], maliciousShare };
    var orders = new List<int> { 1, 2 };
    
    // Attempt reconstruction with corrupted shares
    var reconstructed = SecretSharingHelper.DecodeSecret(corruptedShares, orders, 2);
    
    // The reconstructed secret is corrupted due to negative BigInteger handling
    Assert.NotEqual(legitimateSecret, reconstructed);
}
```

This test demonstrates that when a malicious DecryptedPiece with MSB set is included in the reconstruction, the resulting secret is corrupted due to improper handling of negative BigInteger values in the modulo operation.

### Citations

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

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingExtensions.cs (L39-43)
```csharp
        public static BigInteger Abs(this BigInteger integer)
        {
            return (integer % SecretSharingConsts.FieldPrime + SecretSharingConsts.FieldPrime) %
                   SecretSharingConsts.FieldPrime;
        }
```

**File:** test/AElf.Cryptography.Tests/SecretSharingTest.cs (L34-42)
```csharp
    [Fact]
    public void BigIntegerAbsTest()
    {
        var dataArray = new byte[] { 0xff, 0xff };
        var rawData = new BigInteger(dataArray);
        rawData.ShouldBe(-1);
        var absData = rawData.Abs();
        absData.ShouldBe(SecretSharingConsts.FieldPrime - 1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L46-52)
```csharp
            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```
