# Audit Report

## Title
Threshold Mismatch in Secret Sharing Causes Incorrect InValue Reconstruction When Miner Count Changes

## Summary
The `RevealSharedInValues` function in the AEDPoS consensus contract uses the current round's miner count to calculate the Shamir's Secret Sharing decoding threshold, while secrets were encoded using a different round's miner count. When the miner list size changes between rounds during term transitions, this threshold mismatch causes mathematically incorrect InValue reconstruction, corrupting the consensus randomness beacon.

## Finding Description

The vulnerability exists in the threshold calculation logic within the on-chain secret revelation process. The function calculates the decoding threshold using `currentRound.RealTimeMinersInformation.Count`, but the secrets being decoded were created using a previous round's miner count. [1](#0-0) 

During off-chain secret encoding, when a round is added, the service uses the **previous round's** miner count to encode secrets: [2](#0-1) 

The Shamir's Secret Sharing implementation creates a polynomial of degree `threshold-1`: [3](#0-2) 

The decoding function uses Lagrange interpolation with exactly `threshold` points: [4](#0-3) 

**Exploitation Timeline:**
1. **Round N-2 (7 miners, term T):** Normal operation
2. **Round N-1 (7 miners, term T):** When added, `SecretSharingInformation` event fires with `previousRound=N-2`. Secrets for Round N-1 are encoded with threshold = ⌊7×2/3⌋ = 4 (creates degree-3 polynomial)
3. **Round N (5 miners, term T+1):** New term begins with fewer miners via NextTerm
4. **Round N+1 generation:** `RevealSharedInValues(currentRound=N)` is called, which accesses `previousRound=N-1` and uses threshold = ⌊5×2/3⌋ = 3 to decode
5. **Result:** Lagrange interpolation attempts to reconstruct a degree-3 polynomial using only 3 points, producing a mathematically incorrect InValue

The validation checks do not prevent this: [5](#0-4) 

These checks only verify sufficient pieces exist (7 pieces from Round N-1 ≥ 5 required from Round N), allowing the mismatched decoding to proceed.

## Impact Explanation

**Consensus Randomness Corruption:** The incorrectly reconstructed `PreviousInValue` is stored in the current round: [6](#0-5) 

InValues form the foundation of the consensus random beacon, affecting miner selection, block validation, and time slot assignments. The corrupted value appears cryptographically valid since it passes through hash functions, making it undetectable.

**Quantified Impact:**
- **Automatic Trigger:** Occurs deterministically during every term transition where miner count decreases
- **Protocol-Wide Effect:** All nodes compute the same incorrect value simultaneously
- **Security Guarantee Violation:** Breaks the unpredictability guarantee of the random beacon critical for fair miner selection
- **Severity:** HIGH - Corrupts a core consensus invariant during normal protocol operations

## Likelihood Explanation

**No Attacker Required:** This is a deterministic protocol bug triggered by legitimate operations. The function is invoked automatically during round transitions: [7](#0-6) 

Miner count changes occur during term transitions, which are regular protocol operations when new election results take effect: [8](#0-7) 

The protocol explicitly supports miner count changes via the `IsMinerListJustChanged` flag: [9](#0-8) 

**Execution Certainty:**
- Triggers whenever miner count decreases between consecutive terms
- Example: 7 miners (term T) → 5 miners (term T+1) produces threshold 4 → 3 mismatch
- No special permissions required beyond normal consensus participation
- **Probability:** HIGH - Term transitions with varying miner counts are regular protocol events

## Recommendation

Fix the threshold mismatch by storing the encoding threshold with the encrypted pieces, or use the same reference round for both encoding and decoding:

**Option 1:** Store the original encoding threshold in the Round data structure and use it during decoding.

**Option 2:** Calculate the decoding threshold using the same round that was used for encoding:

```csharp
private void RevealSharedInValues(Round currentRound, string publicKey)
{
    if (!TryToGetPreviousRoundInformation(out var previousRound)) return;
    
    // Get the round that was used for encoding (two rounds back)
    if (!TryToGetRoundInformation(previousRound.RoundNumber.Sub(1), out var encodingRound)) return;
    
    // Use encoding round's miner count for threshold calculation
    var minersCount = encodingRound.RealTimeMinersInformation.Count;
    var minimumCount = minersCount.Mul(2).Div(3);
    minimumCount = minimumCount == 0 ? 1 : minimumCount;
    
    // Rest of the function remains the same...
}
```

## Proof of Concept

```csharp
[Fact]
public void ThresholdMismatch_ProducesIncorrectInValue()
{
    // Scenario: Encode with 7 miners (threshold 4), decode with 5 miners (threshold 3)
    var originalSecret = HashHelper.ComputeFrom("test_secret").ToByteArray();
    
    // Encode with threshold 4 (7 miners)
    var encodingThreshold = 4;
    var encodingTotalParts = 7;
    var shares = SecretSharingHelper.EncodeSecret(originalSecret, encodingThreshold, encodingTotalParts);
    
    // Attempt to decode with threshold 3 (5 miners) - INCORRECT
    var decodingThreshold = 3;
    var wrongResult = SecretSharingHelper.DecodeSecret(
        shares.Take(decodingThreshold).ToList(),
        Enumerable.Range(1, decodingThreshold).ToList(),
        decodingThreshold);
    
    // Decode correctly with threshold 4 for comparison
    var correctResult = SecretSharingHelper.DecodeSecret(
        shares.Take(encodingThreshold).ToList(),
        Enumerable.Range(1, encodingThreshold).ToList(),
        encodingThreshold);
    
    // The results should differ, proving the vulnerability
    Assert.NotEqual(correctResult, wrongResult);
    Assert.Equal(originalSecret, correctResult);
    Assert.NotEqual(originalSecret, wrongResult); // Wrong threshold produces wrong result
}
```

## Notes

This vulnerability affects the core consensus mechanism and can occur during every term transition where the miner count decreases. The mathematical incorrectness is guaranteed by Shamir's Secret Sharing properties: a degree-3 polynomial requires 4 points for unique reconstruction, but only 3 are being used. The protocol's design assumption that miner counts remain constant between encoding and decoding rounds is violated during term transitions, which are expected protocol events.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L17-25)
```csharp
            var coefficients = new BigInteger[threshold];
            // Set p(0) = secret message.
            coefficients[0] = secretMessage.ToBigInteger();
            for (var i = 1; i < threshold; i++)
            {
                var foo = new byte[32];
                Array.Copy(HashHelper.ComputeFrom(Guid.NewGuid().ToByteArray()).ToArray(), foo, 32);
                coefficients[i] = BigInteger.Abs(new BigInteger(foo));
            }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L12-14)
```csharp
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };
```
