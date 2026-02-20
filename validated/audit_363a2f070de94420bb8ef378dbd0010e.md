# Audit Report

## Title
Secret Sharing Threshold Validation Requires 100% Participation Instead of Configured 2/3 Threshold

## Summary
The AEDPoS consensus contract implements Shamir's 2/3 threshold secret sharing for InValue recovery but incorrectly enforces 100% miner participation before attempting secret reconstruction. This defeats the fault-tolerance purpose of threshold cryptography and enables any single miner to prevent all other miners' `PreviousInValue` revelation through a zero-cost griefing attack.

## Finding Description

The vulnerability exists in the `RevealSharedInValues` method where the system validates participation requirements before attempting secret reconstruction.

**The Core Issue:**

The system correctly calculates the threshold as 2/3 of miners [1](#0-0) , but then incorrectly validates that ALL miners (100%) have submitted their decrypted pieces [2](#0-1)  before attempting secret reconstruction.

However, the actual secret reconstruction correctly uses the 2/3 threshold [3](#0-2) , proving that the cryptographic scheme only needs 2/3 of the shares, not all of them. The underlying `SecretSharingHelper.DecodeSecret` implementation confirms it only requires `threshold` shares to reconstruct the secret [4](#0-3) .

**Attack Vector:**

1. Any active miner can call the public `UpdateValue` method [5](#0-4) 

2. During secret sharing, `PerformSecretSharing` stores `DecryptedPieces` without any threshold validation [6](#0-5) 

3. The attacker simply omits their `DecryptedPieces` from the `UpdateValueInput` transaction

4. Later, when `RevealSharedInValues` attempts to reconstruct other miners' `PreviousInValue`, it fails the 100% participation check and skips revelation with `continue` statement

5. The system falls back to a deterministic "fake" value computed from the miner's public key and block height [7](#0-6) 

**Why This Bypasses Protections:**

- `PreviousInValue` validation explicitly allows `Hash.Empty` [8](#0-7) , so the transaction succeeds even without proper revelation

- The `ProcessUpdateValue` method permits empty `PreviousInValue` [9](#0-8) 

- Evil miner detection only checks `MissedTimeSlots` [10](#0-9) , not whether miners submitted `DecryptedPieces`, so the attacker faces no consequences

## Impact Explanation

**1. Defeats Threshold Cryptography Design:**
Shamir's Secret Sharing is specifically designed to reconstruct secrets when only t-of-n parties cooperate. The validation logic requires 100% participation, completely defeating the fault-tolerance benefit that threshold cryptography is designed to provide.

**2. Enables Griefing Attack:**
Any single malicious miner can prevent ALL other miners' `PreviousInValue` from being revealed by withholding their `DecryptedPiece`. This affects the entire miner set, not just the attacker's target. Since there's no punishment mechanism for this behavior, the attack has zero cost.

**3. Weakens Consensus Randomness:**
The commit-reveal scheme for `InValue` is critical for randomness generation. When `PreviousInValue` cannot be revealed through secret sharing, the system uses a predictable deterministic fallback based on pubkey and height. Miners can selectively exploit this to manipulate consensus randomness generation for mining order or other purposes.

**4. Breaks Security Guarantee:**
The AEDPoS consensus design assumes that `PreviousInValue` can be recovered even if a minority of miners are uncooperative. By requiring unanimous participation, this security guarantee is violated, fundamentally compromising the consensus protocol's Byzantine fault tolerance properties.

**Severity: HIGH** - The vulnerability fundamentally breaks the threshold cryptography design, enables no-cost griefing attacks, and weakens the consensus randomness scheme.

## Likelihood Explanation

**Attacker Capabilities:** Any active miner in the consensus set can execute this attack through the public `UpdateValue` method. No special privileges beyond being a block producer are required.

**Attack Complexity:** Trivial - the attacker simply omits the `DecryptedPieces` field from their `UpdateValueInput` message. This is a passive attack (omission) rather than active manipulation, requiring no sophisticated techniques.

**Feasibility Conditions:**
- Attacker must be an active miner (publicly accessible role through the election process)
- No special preconditions needed
- Attack succeeds even if 99% of miners are honest (only one malicious miner needed)
- Zero economic cost to the attacker
- No detection mechanism exists to identify or punish this behavior

**Detection Difficulty:** The attack is virtually indistinguishable from genuine network issues or temporary node unavailability, making it difficult to prove malicious intent versus technical difficulties.

**Probability: HIGH** - The attack is incentive-compatible for miners who want to weaken competitors by preventing their `PreviousInValue` verification, create consensus instability, or manipulate the randomness mechanism for favorable mining order.

## Recommendation

Change the validation check in `RevealSharedInValues` to use the calculated threshold (`minimumCount`) instead of requiring all miners (`minersCount`):

**Current vulnerable code (line 36):**
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**Should be changed to:**
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This change aligns the validation with the actual secret reconstruction requirement and restores the intended fault-tolerance property of threshold cryptography, allowing secret reconstruction as long as at least 2/3 of miners cooperate.

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Deploy a test environment with N miners where N ≥ 3
2. Have one malicious miner call `UpdateValue` with an `UpdateValueInput` that contains empty or omitted `DecryptedPieces` field
3. Observe that when `RevealSharedInValues` executes, it skips revelation for all other miners because `DecryptedPieces.Count` (N-1) is less than `minersCount` (N)
4. Verify that the system falls back to the deterministic fake value generation
5. Confirm that no evil miner detection or penalties are triggered for the malicious miner
6. Verify that even though the `SecretSharingHelper.DecodeSecret` would successfully reconstruct with only 2N/3 shares, the revelation never attempts reconstruction due to the premature validation failure

The test would verify that a single non-cooperating miner prevents all secret revelation, despite the threshold being configured for 2/3 fault tolerance.

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

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-48)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-98)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L263-264)
```csharp
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L96-96)
```csharp
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L179-180)
```csharp
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
```
