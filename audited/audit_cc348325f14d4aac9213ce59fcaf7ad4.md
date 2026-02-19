### Title
Overly Restrictive DecryptedPieces Count Check Defeats Threshold Secret Sharing in Consensus

### Summary
The `RevealSharedInValues()` function requires all miners to submit decrypted pieces (checking `Count < minersCount`) instead of using the cryptographic threshold (`minimumCount` = 2/3), defeating the fault-tolerance property of Shamir's secret sharing. A single malicious or offline miner can prevent reconstruction of another miner's `PreviousInValue`, forcing the system to fall back to fake values and breaking the commit-reveal integrity of random number generation in consensus.

### Finding Description

The vulnerability exists in `RevealSharedInValues()` where line 36 checks if a miner has received decrypted pieces from all miners before attempting secret reconstruction: [1](#0-0) 

The function correctly calculates `minimumCount` (2/3 threshold) on line 22 and uses it for the actual secret reconstruction on line 50: [2](#0-1) [3](#0-2) 

However, the validation check on line 36 requires `DecryptedPieces.Count >= minersCount` (all miners) rather than `>= minimumCount` (2/3 threshold). This contradicts the fundamental design of threshold secret sharing, which specifically enables reconstruction with only a subset of shares.

**Why this is problematic:**
1. Shamir's secret sharing with threshold `t` out of `n` shares allows reconstruction with any `t` shares
2. The AEDPoS implementation uses a 2/3 threshold (line 22)
3. But the check requires all `n` shares to proceed
4. This completely negates the fault-tolerance property

The same overly restrictive check exists in the off-chain service: [4](#0-3) 

**Root cause:** The check conflates availability requirement (all miners must submit) with cryptographic requirement (only threshold needed for reconstruction).

**Execution path:**
1. Round N-1: Miner A shares encrypted pieces with all miners
2. Round N: Malicious miner B withholds their decrypted piece for A; honest miners submit theirs
3. Extra block transition to Round N+1: `RevealSharedInValues` is called: [5](#0-4) 

4. Line 36 check fails (count = minersCount - 1 < minersCount), reconstruction is skipped
5. Miner A's `PreviousInValue` remains null
6. Round N+1: `SupplyCurrentRoundInformation` cannot find A's in-value: [6](#0-5) 

7. System generates fake in-value: [7](#0-6) 

### Impact Explanation

**Consensus Integrity Breach:**
- The commit-reveal scheme requires miners to commit to `in_value` by publishing `out_value = Hash(in_value)` in round N, then reveal `in_value` in round N+1 for verification
- If reconstruction fails, miners' actual `in_value` is lost and replaced with fake values
- This breaks verifiability of the random number generation mechanism

**Random Number Manipulation:**
- The signature calculation uses `previousInValue` to contribute to consensus randomness: [8](#0-7) [9](#0-8) 

- Without proper revelation, the randomness source is compromised

**DoS of Secret Sharing Feature:**
- A single non-cooperative miner can prevent any miner's `PreviousInValue` from being revealed
- This renders the entire secret sharing mechanism ineffective
- The system degrades to trusting individual miners to self-reveal, which they may refuse to do

**Validation Weakness:**
The validation allows null/empty `PreviousInValue` without enforcement: [10](#0-9) 

### Likelihood Explanation

**High Likelihood:**

**Attacker capabilities:** Any single miner in the network can execute this attack by simply withholding data during normal mining operations. No special permissions, economic resources, or technical exploits required.

**Attack complexity:** Trivial - the attacker merely refrains from submitting their decrypted piece for a target miner in their `UpdateValue` transaction: [11](#0-10) 

**Feasibility:** The attack is undetectable from the perspective of other miners. The attacker can claim technical issues, network problems, or simply remain silent. There are no apparent penalties for not submitting decrypted pieces.

**Economic rationality:** 
- No cost to the attacker (simply withhold data)
- Can prevent specific miners from proving their honest participation
- Can be used to manipulate consensus randomness over multiple rounds
- Strategic withholding can influence mining order determination

**Detection constraints:** The blockchain state only shows that reconstruction failed, not which specific miner failed to submit their piece, making attribution difficult.

### Recommendation

**Primary fix:** Change line 36 to use the cryptographic threshold instead of requiring all miners:

```csharp
// Current (vulnerable):
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

// Fixed:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

Apply the same fix to the off-chain service at line 162 in `SecretSharingService.cs`.

**Additional validation:** Consider adding penalties or reputation tracking for miners who consistently fail to submit decrypted pieces, as this behavior indicates either malicious intent or poor node operation.

**Test cases:**
1. Verify reconstruction succeeds with exactly `minimumCount` pieces (2/3 threshold)
2. Verify reconstruction succeeds with `minimumCount + 1` but `< minersCount` pieces
3. Verify the revealed `PreviousInValue` correctly matches the original `OutValue` commitment
4. Test with changing miner lists between rounds
5. Ensure fake in-values are never used when sufficient pieces exist

### Proof of Concept

**Initial state:**
- 7 active miners in AEDPoS consensus
- Secret sharing enabled via configuration
- Round N-1 completed with all miners having shared encrypted pieces

**Attack sequence:**

1. **Round N-1:** Victim miner A produces block, commits `out_value_A = Hash(in_value_A)`, shares encrypted pieces with all 7 miners

2. **Round N:** Six honest miners (C, D, E, F, G, H) mine blocks and submit their `UpdateValue` transactions including decrypted pieces for miner A. Attacker miner B mines but deliberately omits A's decrypted piece from their `UpdateValue.decrypted_pieces` field.

3. **Extra block for Round N→N+1:** Miner produces extra block, triggering `NextRound` → `RevealSharedInValues(currentRound, extraBlockProducer)`

4. **Expected result:** With 2/3 threshold (5 out of 7), miner A's in-value should be reconstructible from the 6 submitted pieces

5. **Actual result:** 
   - Line 36 checks: `6 < 7` evaluates to `true`
   - Reconstruction is skipped via `continue`
   - Miner A's `currentRound.RealTimeMinersInformation[A].PreviousInValue` remains `null`

6. **Round N+1 transition:** `SupplyCurrentRoundInformation` attempts to fill missing values:
   - Line 191: `PreviousInValue` from round N is `null`
   - Line 193: `InValue` from round N-1 is `null` (not stored for miners who mined)
   - Line 208: System generates fake value: `HashHelper.ComputeFrom(minerPubkey)`
   - Miner A's verifiable `in_value_A` is permanently lost

**Success condition:** Attacker successfully prevented reconstruction despite cryptographically sufficient pieces (6 ≥ minimumCount of 5), breaking the consensus commit-reveal scheme with zero cost.

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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L162-162)
```csharp
            if (minerInRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L191-193)
```csharp
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L203-209)
```csharp
            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L42-42)
```csharp
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;
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
