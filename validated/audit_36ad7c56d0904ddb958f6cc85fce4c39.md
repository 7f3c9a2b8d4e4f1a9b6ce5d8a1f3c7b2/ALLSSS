# Audit Report

## Title
Secret Sharing Threshold Validation Requires 100% Participation Instead of Configured 2/3 Threshold

## Summary
The AEDPoS consensus secret sharing mechanism implements Shamir's 2/3 threshold secret sharing for fault tolerance, but the validation logic incorrectly requires 100% miner participation before attempting secret reconstruction. This discrepancy defeats the purpose of threshold cryptography and enables any single miner to prevent all other miners' `PreviousInValue` revelation through a no-cost griefing attack.

## Finding Description

The vulnerability stems from a fundamental mismatch between the cryptographic threshold and the validation threshold in the secret sharing implementation:

**Threshold Configuration (2/3):**
The system correctly calculates `minimumCount = minersCount * 2 / 3` as the threshold for Shamir's Secret Sharing. [1](#0-0) 

**Incorrect Validation Check (100%):**
However, the `RevealSharedInValues` method checks whether `DecryptedPieces.Count < minersCount` (requiring 100% of miners) before attempting reconstruction: [2](#0-1) 

**Cryptographic Reconstruction Uses Correct Threshold:**
The actual `DecodeSecret` call correctly uses `minimumCount` (2/3) for Lagrange interpolation: [3](#0-2) 

The cryptographic implementation in `SecretSharingHelper.DecodeSecret` only requires `threshold` number of shares to reconstruct the secret: [4](#0-3) 

**Attack Execution Path:**
1. A malicious miner omits `DecryptedPieces` from their `UpdateValue` transaction (passive attack)
2. The `PerformSecretSharing` method stores whatever pieces are provided without validation: [5](#0-4) 
3. When `RevealSharedInValues` executes, it fails the 100% check and skips reconstruction for all miners
4. The system falls back to a deterministic fake value computed from the miner's public key and block height: [6](#0-5) 
5. The `PreviousInValue` field is explicitly marked as optional: [7](#0-6) 

**No Punishment Mechanism:**
The evil miner detection only checks `MissedTimeSlots`, not failure to submit `DecryptedPieces`: [8](#0-7) 

## Impact Explanation

**HIGH Severity** - This vulnerability has multiple severe impacts:

1. **Defeats Threshold Cryptography Design**: Shamir's Secret Sharing is specifically designed to provide fault tolerance when only t-of-n parties cooperate. By requiring n-of-n participation, the system completely loses this benefit and becomes as brittle as a non-threshold scheme.

2. **No-Cost Griefing Attack**: Any single malicious miner can prevent ALL other miners' `PreviousInValue` from being revealed by simply omitting their `DecryptedPiece`. This affects the entire miner set, not just targeted victims, making it a powerful denial-of-service vector.

3. **Weakens Consensus Randomness**: When `PreviousInValue` cannot be revealed through secret sharing, the system falls back to a deterministic value. This predictability allows miners to selectively reveal their true `InValue` or use the fallback, potentially manipulating the consensus randomness used for mining order determination.

4. **No Accountability**: Since the attack is passive (omission rather than invalid submission) and there's no punishment mechanism for withholding `DecryptedPieces`, attackers face zero consequences for this behavior.

## Likelihood Explanation

**HIGH Likelihood** - This attack is trivially exploitable:

- **Attacker Capabilities**: Any active miner in the consensus set can execute this attack with no special privileges beyond being a block producer
- **Attack Complexity**: Trivial - the attacker simply omits their `DecryptedPieces` from their `UpdateValue` transaction
- **No Preconditions**: Attack works regardless of network conditions or other miners' behavior
- **Zero Cost**: No economic cost or punishment for the attacker
- **Difficult Detection**: The attack is indistinguishable from legitimate network issues or temporary unavailability

The attack is incentive-compatible for miners who want to create consensus instability, prevent competitors from having their `PreviousInValue` verified, or weaken the randomness mechanism for strategic advantage.

## Recommendation

Change the validation check to use the configured threshold instead of requiring 100% participation:

```csharp
// In AEDPoSContract_SecretSharing.cs, line 36
// Change from:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

// To:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

Additionally:
1. Implement a punishment mechanism for miners who consistently fail to submit `DecryptedPieces`
2. Add monitoring to detect patterns of withheld pieces
3. Consider making `DecryptedPieces` submission mandatory when secret sharing is enabled

## Proof of Concept

The existing test demonstrates that secret reconstruction works with only `MinimumCount` (2/3) pieces: [9](#0-8) 

The test successfully reconstructs the secret after collecting only `MinimumCount` shares and breaks out of the loop, proving the cryptographic scheme only needs 2/3 participation, not 100%.

To demonstrate the vulnerability, a miner would:
1. Join the active miner set
2. During their `UpdateValue` transaction, populate all required fields except omit the `DecryptedPieces` map
3. Observe that all other miners fail to reconstruct `PreviousInValue` in the next round
4. Face no punishment or penalty for this behavior

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-48)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-293)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L96-96)
```csharp
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
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
