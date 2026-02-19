### Title
Overly Strict DecryptedPieces Requirement Enables Minority Censorship of InValue Reveals

### Summary
The `RevealSharedInValues` function requires ALL miners to decrypt pieces (line 36) before revealing InValues, despite Shamir's Secret Sharing only requiring 2/3 of shares for reconstruction (as used in line 50). This mismatch allows a minority of 1/3+ miners to block InValue reveals that would otherwise succeed, undermining the transparency and accountability of the consensus random number generation mechanism.

### Finding Description

The vulnerability exists in the secret sharing reveal logic where two inconsistent thresholds are applied: [1](#0-0) 

Line 35 correctly checks if a miner has encrypted their secret for at least `minimumCount` miners (calculated as 2/3 of total miners). However, line 36 checks if `DecryptedPieces.Count < minersCount`, requiring ALL miners to have decrypted pieces before proceeding with the reveal.

The actual secret reconstruction only requires `minimumCount` (2/3) shares: [2](#0-1) 

This inconsistency is confirmed by the test suite, which demonstrates that reconstruction should succeed with exactly `minimumCount` decrypted pieces: [3](#0-2) 

The same flawed check exists in the off-chain service: [4](#0-3) 

When `RevealSharedInValues` is called during round transitions, this overly strict requirement causes reveals to be skipped unnecessarily: [5](#0-4) 

The secret sharing flow involves miners encrypting their InValue shares and other miners decrypting them: [6](#0-5) 

### Impact Explanation

**Operational DoS Impact**: The consensus mechanism's transparency is compromised when InValue reveals are blocked. While validation permits empty `PreviousInValue` fields to pass, the secret sharing mechanism is designed to provide accountability and prevent miners from manipulating random values after observing others' commitments. [7](#0-6) 

**Affected Parties**: All network participants relying on fair random number generation. The consensus mechanism's integrity depends on verifiable randomness.

**Severity**: Medium - While not directly causing fund loss, this enables:
- Minority miners (1/3+) to systematically block reveals
- Reduced accountability in random number generation  
- Potential for selective censorship of specific miners' reveals
- Network issues affecting 1/3+ miners unnecessarily blocking reveals that should succeed

### Likelihood Explanation

**Attacker Capabilities**: Any 1/3+ minority of miners can execute this attack by simply not decrypting other miners' pieces. This is a passive attack requiring no on-chain transactions.

**Attack Complexity**: Trivial - miners simply omit decryption operations during their consensus updates.

**Feasibility Conditions**: 
- No special privileges required beyond being a miner
- Can be executed continuously in every round
- Network partition or operational issues affecting 1/3+ miners triggers the same blocking behavior

**Detection Constraints**: Difficult to distinguish between malicious non-decryption and legitimate network/operational issues.

**Probability**: Medium-High - The attack requires minimal coordination among miners (just 1/3+), and the same blocking occurs naturally during network issues.

### Recommendation

**Code-Level Mitigation**: Change line 36 in both locations to align with the actual secret sharing requirements:

In `AEDPoSContract_SecretSharing.cs` line 36 and `SecretSharingService.cs` line 162, replace:
```
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```
with:
```
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

**Invariant Check**: Ensure that the reconstruction threshold matches the Shamir Secret Sharing minimum requirement of 2/3 throughout the codebase.

**Test Case**: Add a regression test that verifies InValue reveal succeeds with exactly `minimumCount` (2/3) decrypted pieces, not requiring all miners.

### Proof of Concept

**Initial State**:
- 17 miners in consensus (as per initial configuration)
- minimumCount = 17 * 2 / 3 = 11
- minersCount = 17

**Attack Sequence**:
1. Miner A produces a block and encrypts their InValue shares for all 17 miners
2. Miner A's `EncryptedPieces.Count = 17` (passes line 35 check: 17 >= 11)
3. Only 11 miners decrypt Miner A's pieces (2/3 threshold met for reconstruction)
4. Miner A's `DecryptedPieces.Count = 11` < 17 (fails line 36 check)
5. Line 36 executes `continue`, skipping the reveal for Miner A

**Expected Result**: Miner A's InValue should be revealed since 11 decrypted pieces meet the secret sharing threshold of `minimumCount = 11`.

**Actual Result**: Miner A's InValue reveal is skipped because the code requires all 17 miners to decrypt (line 36), even though reconstruction is mathematically possible and the test suite demonstrates this should succeed.

**Success Condition**: With the fix applied, the reveal proceeds when `DecryptedPieces.Count >= 11`, successfully reconstructing the InValue using `SecretSharingHelper.DecodeSecret` with the available 11 pieces.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-36)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L161-162)
```csharp
            if (minerInRound.EncryptedPieces.Count < minimumCount) continue;
            if (minerInRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L290-293)
```csharp
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L42-46)
```csharp
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;
```
