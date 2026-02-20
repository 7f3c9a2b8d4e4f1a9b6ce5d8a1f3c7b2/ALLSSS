# Audit Report

## Title
Incorrect Threshold Check in Secret Sharing Reconstruction Defeats Byzantine Fault Tolerance

## Summary
The AEDPoS consensus contract's secret sharing reconstruction logic incorrectly requires 100% of miners to provide decrypted pieces before attempting reconstruction, instead of the mathematically sufficient 2/3 threshold defined by Shamir's Secret Sharing algorithm. This allows any single malicious validator to prevent forced revelation of their InValue by providing incomplete encrypted pieces, breaking the commit-reveal scheme's security guarantees and enabling manipulation of consensus randomness and mining order.

## Finding Description

The vulnerability exists in the `RevealSharedInValues` method where secret reconstruction is performed. The system correctly calculates a 2/3 threshold (`minimumCount`) [1](#0-0)  but then incorrectly validates that ALL miners (100%) have provided decrypted pieces before attempting reconstruction [2](#0-1) 

The secret reconstruction algorithm itself correctly uses the `minimumCount` threshold parameter [3](#0-2)  but this code is never reached when DecryptedPieces.Count < minersCount. The underlying Shamir's Secret Sharing implementation is mathematically correct and only requires the threshold number of shares [4](#0-3) 

**Attack Execution Path:**

1. **Round N**: Malicious validator provides incomplete EncryptedPieces in their `UpdateValue` transaction (e.g., only encrypting for 14 out of 21 validators)
2. **Round N+1**: Only the 14 validators with encrypted pieces can decrypt and add to DecryptedPieces  
3. **Round N+1**: When `RevealSharedInValues` executes, it checks if DecryptedPieces.Count (14) < minersCount (21) and skips reconstruction
4. **Result**: The malicious validator's PreviousInValue is never forcibly revealed through secret reconstruction

**Why Existing Protections Fail:**

1. **No EncryptedPieces completeness validation**: The `UpdateValueValidationProvider` does not validate that miners provide complete encrypted pieces [5](#0-4) 

2. **Hash.Empty explicitly allowed**: PreviousInValue is permitted to be Hash.Empty, bypassing forced revelation requirements [6](#0-5) 

3. **Storage without validation**: EncryptedPieces are stored directly without completeness checks [7](#0-6) 

4. **Evil miner detection insufficient**: The system only detects evil miners based on missed time slots (OutValue == null), not secret sharing non-participation [8](#0-7) 

## Impact Explanation

This vulnerability breaks critical consensus security guarantees with HIGH severity:

**1. Mining Order Manipulation**: The signature value (computed from InValue) determines mining order for the next round [9](#0-8) . The signature is calculated from InValue using XOR operations [10](#0-9)  and this signature computation uses the PreviousInValue [11](#0-10) . Without forced revelation, a malicious validator can avoid verification of their signature computation, allowing them to manipulate their mining position.

**2. Randomness Manipulation**: The commit-reveal scheme requires miners to commit to an InValue (via OutValue hash) and later reveal it. The secret sharing mechanism exists specifically to force revelation even if a miner refuses to cooperate. By defeating this mechanism, miners can selectively choose whether to reveal based on whether the outcome benefits them.

**3. Byzantine Fault Tolerance Defeated**: Shamir's Secret Sharing is mathematically designed to tolerate up to 1/3 Byzantine (malicious) participants. The incorrect threshold check requiring 100% participation effectively reduces this tolerance to 0%, as a single malicious validator can prevent reconstruction.

**4. Consensus Fairness Compromised**: All network participants suffer from compromised consensus fairness, while the malicious validator gains unfair advantages in block production scheduling and associated rewards.

## Likelihood Explanation

The likelihood is **HIGH** due to the following factors:

**Attacker Capabilities**: Any validator in the active miner set can execute this attack. No special privileges beyond being an elected validator are required.

**Attack Complexity**: LOW
- The attacker simply provides incomplete EncryptedPieces in their UpdateValue transaction
- No complex cryptographic manipulation required
- No timing dependencies or race conditions  
- The attack is undetectable at validation time since EncryptedPieces completeness is never checked

**Feasibility**: The attack is immediately executable when:
1. Attacker is an active validator (realistic for any elected miner)
2. Secret sharing is enabled (standard operational configuration)

**Detection Difficulty**: The attack is extremely difficult to detect because:
- Off-chain observers cannot distinguish between network-delayed pieces and deliberately withheld pieces
- No on-chain slashing mechanism exists for incomplete secret sharing participation
- Evil miner detection only tracks missed time slots, not secret sharing compliance

## Recommendation

Change the threshold check in `RevealSharedInValues` to use the calculated `minimumCount` (2/3 threshold) instead of requiring all miners:

```csharp
// Current vulnerable code (line 36):
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

// Should be changed to:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

Additionally, consider adding validation in `UpdateValueValidationProvider` to ensure miners provide complete EncryptedPieces for all current miners, or implement slashing/penalties for miners who fail to provide complete encrypted pieces.

## Proof of Concept

The vulnerability can be demonstrated by examining the test demonstrating correct secret sharing behavior [12](#0-11) . This test shows that reconstruction SHOULD work when `decryptedValues.Count >= MinimumCount`, not when it equals the total count. The production code contradicts this mathematical property by requiring 100% participation instead of the 2/3 threshold.

To exploit this vulnerability:
1. Deploy as an elected validator in the active miner set
2. When calling `UpdateValue`, provide EncryptedPieces that only includes encrypted shares for a subset of miners (e.g., 14 out of 21)
3. In the next round, only those 14 miners can decrypt your pieces and add to DecryptedPieces
4. The reconstruction check at line 36 will see DecryptedPieces.Count (14) < minersCount (21) and skip reconstruction
5. Your PreviousInValue is never forcibly revealed, allowing you to manipulate consensus randomness and mining order without detection

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L50-50)
```csharp
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L290-290)
```csharp
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L89-92)
```csharp
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/InValueRecoveryTest.cs (L52-58)
```csharp
            if (decryptedValues.Count >= MinimumCount)
            {
                decryptResult = SecretSharingHelper.DecodeSecret(
                    decryptedValues.Values.ToList(),
                    Enumerable.Range(1, MinimumCount).ToList(), MinimumCount);
                break;
            }
```
