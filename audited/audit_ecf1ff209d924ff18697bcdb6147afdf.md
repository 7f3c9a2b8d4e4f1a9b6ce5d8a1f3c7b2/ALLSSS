### Title
Secret Sharing Threshold Mismatch Produces Garbage InValues After Term Transitions

### Summary
The `RevealSharedInValues()` function decodes secret shares using a threshold calculated from the current round's miner count, but these shares were originally encoded with a threshold from a different round's miner count. When the miner list changes between term transitions, this mismatch causes Shamir's Secret Sharing to produce incorrect output, corrupting the consensus randomness mechanism.

### Finding Description

The vulnerability occurs due to a temporal mismatch between the threshold parameters used for encoding versus decoding secret shares:

**Encoding Phase (Off-chain):**
When a new round N is added to the blockchain, `AddRoundInformation()` fires a `SecretSharingInformation` event containing `PreviousRound = Round N-1`. [1](#0-0) 

The off-chain `SecretSharingService` receives this event and encodes secrets using the miner count from `PreviousRound` (Round N-1): [2](#0-1) 

**Decoding Phase (On-chain):**
During the transition from Round M to Round M+1, `RevealSharedInValues(currentRound)` is called. [3](#0-2) 

This function calculates `minimumCount` from the **current round's** miner count, then attempts to decode secrets from the **previous round**: [4](#0-3) 

**Root Cause:**
When a term transition occurs (e.g., from 12 miners to 9 miners), the check preventing secret sharing when `IsMinerListJustChanged=true` only applies to the NEW round, not to decoding secrets from the OLD round: [5](#0-4) 

**Concrete Example:**
- Round K-2: 12 miners (old term)
- Round K-1: 12 miners (last round of old term) → secrets encoded with threshold = 12×2/3 = 8
- Round K: 9 miners (first round of new term, `IsMinerListJustChanged=true`)
- Round K+1 transition: `RevealSharedInValues(Round K)` calculates threshold = 9×2/3 = 6, attempts to decode Round K-1 secrets
- **Mismatch: Decoding with threshold 6 when polynomial degree is 7 (threshold-1) produces garbage**

Shamir's Secret Sharing requires exactly `threshold` points to reconstruct a polynomial of degree `threshold-1`. Using fewer points mathematically cannot reconstruct the original polynomial correctly. [6](#0-5) 

### Impact Explanation

**Consensus Integrity Compromise:**
The revealed "in values" are used as part of the consensus randomness generation mechanism. When garbage values are produced due to incorrect decoding:
1. The computed `PreviousInValue` stored in `currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue` is incorrect
2. These corrupted in-values affect subsequent round generation and signature calculations
3. The consensus random number generation, which relies on these values, becomes unpredictable or manipulable

**Affected Parties:**
- All network participants relying on consensus randomness for block production order
- Any protocol features depending on verifiable randomness from consensus
- The integrity of the AEDPoS consensus mechanism itself

**Severity:**
High - This directly corrupts a critical security property (verifiable randomness) of the consensus mechanism. While it doesn't allow direct fund theft, it undermines the fairness and security assumptions of the entire blockchain.

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability triggers automatically during normal consensus operation when transitioning rounds after a term change. No attacker action is required—it's a protocol-level bug that occurs deterministically.

**Feasible Preconditions:**
1. A term transition must occur (happens periodically based on election results)
2. The new term must have a different number of miners than the previous term
3. This is highly likely in practice as election results vary

**Execution Practicality:**
- The vulnerability executes through the standard `GetConsensusExtraData` call made by miners during block production
- Occurs in the `NextRound` behavior during normal round transitions
- No special permissions or malicious input required
- The incorrect decoding happens silently without revert

**Detection:**
The bug is not easily detectable because:
- The DecodeSecret function doesn't validate that the threshold matches what was used during encoding
- No error is thrown when decoding with wrong parameters
- The output appears valid (it's a hash), but is cryptographically incorrect

**Probability:**
Very High - This will occur at every term transition where the miner count changes, which is a regular occurrence in the protocol's designed operation.

### Recommendation

**Immediate Fix:**
Store the encoding threshold alongside the encrypted pieces in each round's data structure. During decoding, use this stored threshold instead of recalculating from the current round's miner count.

**Code Changes:**

1. Modify the `MinerInRound` proto definition to include:
```protobuf
int32 secret_sharing_threshold = [next_field_number];
```

2. In the off-chain `SecretSharingService`, store the threshold used during encoding.

3. In `RevealSharedInValues()`, retrieve and use the stored threshold from `previousRound`:
```csharp
var minimumCount = anotherMinerInPreviousRound.SecretSharingThreshold;
// Validate it matches expected range
Assert(minimumCount > 0 && minimumCount <= previousRound.RealTimeMinersInformation.Count, 
       "Invalid secret sharing threshold");
```

**Additional Validation:**
Add a check to ensure sufficient shares are available:
```csharp
Assert(anotherMinerInPreviousRound.DecryptedPieces.Count >= minimumCount,
       "Insufficient decrypted pieces for secret reconstruction");
```

**Test Cases:**
1. Create a test simulating term transition with miner count change (12→9)
2. Verify that decoded in-values match the original encoded values
3. Add negative test attempting to decode with wrong threshold and verify it produces different output

### Proof of Concept

**Initial State:**
- Round K-2 completes with 12 miners
- Election occurs, new term will have 9 miners

**Step-by-Step Execution:**

1. **Round K-1 (last round of old term, 12 miners):**
   - When Round K-1 is added via `AddRoundInformation()`, event fires
   - Off-chain service encodes each miner's secret with threshold = 12×2/3 = 8
   - Miners exchange and decrypt pieces

2. **Round K (first round of new term, 9 miners):**
   - New term begins with 9 miners
   - `IsMinerListJustChanged = true`
   - Miners produce blocks normally

3. **Transition from Round K to Round K+1:**
   - Extra block producer calls `GetConsensusExtraData` with behavior `NextRound`
   - `GetConsensusExtraDataForNextRound(currentRound=K, ...)` is invoked
   - `RevealSharedInValues(currentRound=K, pubkey)` is called
   - Calculates `minimumCount = 9×2/3 = 6`
   - Retrieves `previousRound = Round K-1` (which had 12 miners)
   - Attempts to decode Round K-1 secrets using only first 6 shares
   - **Lagrange interpolation with 6 points cannot correctly reconstruct a degree-7 polynomial**

**Expected Result:**
Decoded value should match the original in-value from Round K-1

**Actual Result:**
Decoded value is mathematically incorrect garbage, as demonstrated by Shamir's Secret Sharing properties: [7](#0-6) 
Tests show encoding with threshold T and decoding with threshold T produces correct output, but using different thresholds would fail.

**Success Condition:**
The vulnerability is confirmed when `HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(...))` produces a different hash than the original in-value that was encoded, corrupting the `PreviousInValue` field in the consensus round data.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-108)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L110-115)
```csharp
            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-50)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

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

**File:** test/AElf.Cryptography.Tests/SecretSharingTest.cs (L57-66)
```csharp
    public void SharingTest(string str, int threshold, int totalParts)
    {
        var bytes = Encoding.UTF8.GetBytes(str);
        var parts = SecretSharingHelper.EncodeSecret(bytes, threshold, totalParts);
        Assert.Equal(totalParts, parts.Count);

        var result = SecretSharingHelper.DecodeSecret(parts.Take(threshold).ToList(),
            Enumerable.Range(1, threshold).ToList(), threshold);
        Assert.Equal(bytes, result);
    }
```
