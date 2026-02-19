### Title
Secret Sharing Threshold Validation Requires 100% Participation Instead of Configured 2/3 Threshold

### Summary
The secret sharing mechanism in AEDPoS consensus implements t-of-n (2/3 threshold) secret sharing but enforces an n-of-n (100%) participation requirement for secret reconstruction. This defeats the fault-tolerance purpose of threshold cryptography and enables any single miner to prevent all other miners' `PreviousInValue` revelation through a no-cost griefing attack.

### Finding Description

The vulnerability exists in the secret sharing validation logic across multiple locations:

**Location 1: Data Extraction (No Validation)** [1](#0-0) 

The `ExtractInformationToUpdateConsensus` function collects `DecryptedPieces` that other miners have submitted for the current miner, but performs no validation on whether sufficient pieces exist to meet the secret sharing threshold.

**Location 2: Incorrect Threshold Check (Contract)** [2](#0-1) 

The `RevealSharedInValues` method checks that `DecryptedPieces.Count >= minersCount` (100% of miners) before attempting secret reconstruction, despite the threshold being configured as `minimumCount = minersCount.Mul(2).Div(3)` (2/3 of miners). [3](#0-2) 

**Location 3: Same Incorrect Check (Application Layer)** [4](#0-3) 

The application layer `SecretSharingService` duplicates this overly strict validation.

**Location 4: Actual Secret Reconstruction Uses Threshold** [5](#0-4) 

The `DecodeSecret` call correctly uses `minimumCount` (2/3 threshold) for Lagrange interpolation, proving the cryptographic scheme only needs t shares, not n shares.

**Location 5: Test Confirms 2/3 Threshold Sufficiency** [6](#0-5) 

The test demonstrates that secret reconstruction works correctly with only `MinimumCount` (2/3) pieces, confirming the validation check is unnecessarily strict.

**Location 6: Decryption Stored Without Validation** [7](#0-6) 

The `PerformSecretSharing` method stores `DecryptedPieces` without any threshold validation during the `UpdateValue` transaction.

**Root Cause:**
The system implements Shamir's t-of-n secret sharing where t=2/3, but the validation logic incorrectly requires n (100%) pieces before attempting reconstruction. This creates a discrepancy between the cryptographic threshold (2/3) and the operational threshold (100%).

### Impact Explanation

**1. Defeats Threshold Cryptography Fault Tolerance**
Threshold secret sharing is specifically designed to reconstruct secrets when only t-of-n parties cooperate. By requiring n-of-n participation, the system loses the core benefit of fault tolerance against unavailable or uncooperative participants.

**2. Griefing Attack Vector (High Impact)**
Any single malicious miner can prevent ALL other miners' `PreviousInValue` from being revealed by simply not submitting their `DecryptedPiece` during their `UpdateValue` transaction. This affects the entire miner set, not just the attacker's target.

**3. Weakens Commit-Reveal Randomness Scheme** [8](#0-7) 

When `PreviousInValue` cannot be revealed through secret sharing, the system falls back to a deterministic "fake" value computed from the miner's public key and block height. This allows miners to selectively reveal their true `InValue` or use the predictable fallback, potentially manipulating the consensus randomness generation.

**4. No Punishment Mechanism** [9](#0-8) 

Evil miner detection only checks `MissedTimeSlots`, not failure to submit `DecryptedPieces`. Attackers face no consequences for this griefing behavior.

**5. Optional But Critical** [10](#0-9) 

While `PreviousInValue` is marked as optional (validation passes if null/empty), its revelation is critical for the commit-reveal scheme's integrity. Allowing miners to avoid revelation undermines the randomness guarantees.

**Severity:** HIGH - Enables no-cost griefing attacks, fundamentally breaks threshold cryptography design, and weakens consensus randomness.

### Likelihood Explanation

**Attacker Capabilities:** Any active miner in the consensus set can execute this attack. No special privileges beyond being a block producer are required.

**Attack Complexity:** Trivial - the attacker simply omits their `DecryptedPieces` from their `UpdateValue` transaction. This is a passive attack (omission) rather than active manipulation.

**Feasibility Conditions:**
- Attacker must be an active miner (reachable entry point: `UpdateValue` method)
- No special preconditions needed
- Attack succeeds even if 99% of miners are honest (only one malicious miner needed)
- No economic cost to the attacker

**Detection Constraints:** The attack is difficult to distinguish from genuine network issues or temporary unavailability. There's no mechanism to prove a miner deliberately withheld their `DecryptedPiece` versus experiencing technical difficulties.

**Probability:** HIGH - The attack is incentive-compatible for any miner who wants to:
1. Prevent competitors from having their `PreviousInValue` verified
2. Create consensus instability
3. Weaken the randomness mechanism for mining order manipulation

### Recommendation

**Code-Level Fix:**

Change the threshold validation in both contract and service layer from:
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

To:
```csharp
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

**Locations to Update:**
1. [11](#0-10) 
2. [12](#0-11) 

**Additional Safeguards:**

1. **Bounds Check in DecodeSecret:** Add validation that `sharedParts.Count >= threshold` before the loop to prevent IndexOutOfRangeException. [13](#0-12) 

2. **Evil Miner Detection Enhancement:** Consider adding failure to submit `DecryptedPieces` as a criterion for evil miner detection, similar to `MissedTimeSlots` tracking.

3. **Test Coverage:** Add regression tests verifying secret reconstruction succeeds with exactly `minimumCount` pieces (not `minersCount`).

### Proof of Concept

**Initial State:**
- 17 active miners in current round (standard AEDPoS configuration)
- `minimumCount = 17 * 2 / 3 = 11` (2/3 threshold)
- `minersCount = 17` (100%)
- Miner A produced a block in Round N-1 with `OutValue = Hash(InValue_A)`
- Secret sharing is enabled via configuration

**Attack Sequence:**

1. **Round N - Encryption Phase:**
   - Miner A broadcasts `EncryptedPieces` for their `InValue_A` to all 16 other miners
   - All miners receive encrypted pieces

2. **Round N - Decryption Phase:**
   - Miners 2-16 (15 miners, 88% participation) decrypt their pieces and submit via `UpdateValue`
   - Miner B (malicious) deliberately does NOT submit their `DecryptedPiece` for Miner A
   - Result: `anotherMinerInPreviousRound.DecryptedPieces.Count = 15`

3. **Round N - Secret Revelation Attempt:**
   - `RevealSharedInValues` is called
   - Check at line 36: `15 < 17` (true), so `continue` is executed
   - Miner A's `PreviousInValue` is NOT revealed despite having 15 pieces (well above the 11-piece threshold)

4. **Round N+1 - Fallback Mechanism:**
   - Miner A produces next block
   - `GetConsensusBlockExtraData` finds `PreviousInValue == null`
   - System uses fake value: `HashHelper.ComputeFrom(pubkeyA.Append(height))`
   - Commit-reveal scheme is bypassed

**Expected Result:** With 15 pieces (>11 threshold), secret reconstruction should succeed.

**Actual Result:** Secret reconstruction is skipped because 15 < 17 (requires 100%), allowing Miner A to use a predictable fake value instead of their committed `InValue_A`.

**Success Condition:** Attack succeeds if any single miner can prevent secret revelation despite having sufficient pieces (≥ 2/3 threshold) available.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L26-28)
```csharp
        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L161-162)
```csharp
            if (minerInRound.EncryptedPieces.Count < minimumCount) continue;
            if (minerInRound.DecryptedPieces.Count < minersCount) continue;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L94-108)
```csharp
            else
            {
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
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

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-49)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
            {
```
