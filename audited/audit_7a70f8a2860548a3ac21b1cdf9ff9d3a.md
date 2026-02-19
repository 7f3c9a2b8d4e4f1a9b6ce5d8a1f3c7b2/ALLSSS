### Title
Incorrect Threshold Validation in Secret Sharing Reconstruction Causes Consensus Corruption During Miner List Transitions

### Summary
The `RevealSharedInValues()` function uses an insufficient validation operator (`<` instead of `!=`) when checking the count of decrypted secret shares against the current round's miner count. This allows secret reconstruction to proceed with a mismatched threshold when the miner list changes between rounds, causing Shamir's secret sharing reconstruction to fail or produce corrupted in-values that break consensus validation.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The vulnerability stems from comparing the previous round's `DecryptedPieces.Count` against the current round's `minersCount` using a less-than operator. The function calculates `minimumCount` (the threshold for secret reconstruction) based on the current round's miner count, but the secret shares were originally encoded in the previous round using a threshold based on the previous round's miner count. [2](#0-1) 

When the miner list shrinks between rounds (e.g., during term transitions managed by NextTerm), the current round has fewer miners than the previous round. The check `DecryptedPieces.Count < minersCount` passes when it shouldn't, allowing reconstruction to proceed. [3](#0-2) 

The reconstruction uses `minimumCount` calculated from the current (smaller) round as the threshold parameter to `DecodeSecret`, but the secret was encoded with a larger threshold from the previous round. In Shamir's secret sharing, using fewer pieces than the encoding threshold produces incorrect results. [4](#0-3) 

**Why Existing Protections Fail:**
The function checks if a miner is in both current and previous rounds, but doesn't validate threshold consistency: [5](#0-4) 

**Execution Path:**
This function is called during NextRound consensus behavior: [6](#0-5) 

### Impact Explanation

**Concrete Harm:**
1. **Corrupted In-Values**: The reconstructed `PreviousInValue` stored for miners will be mathematically incorrect, as Shamir's secret sharing with insufficient pieces (below the encoding threshold) cannot reconstruct the original secret. [7](#0-6) 

2. **Consensus Integrity Breakdown**: Previous in-values are used for signature validation and random number generation in the consensus mechanism. Corrupted values break these critical paths.

3. **Systematic Failure**: All nodes execute the same deterministic (but incorrect) reconstruction, leading to network-wide acceptance of corrupted consensus state.

**Affected Parties:**
- All miners participating in consensus during term transitions
- The entire blockchain network during miner list changes
- Random number generation security

**Severity Justification:**
HIGH severity because it corrupts core consensus data structures during normal operations (term transitions occur regularly), potentially causing validation failures, incorrect randomness, and consensus instability.

### Likelihood Explanation

**Feasibility:**
Term transitions with miner list changes occur naturally in the protocol design: [8](#0-7) 

The miner list is updated during term transitions based on election results: [9](#0-8) 

**Conditions Required:**
1. A term transition occurs (happens regularly, typically every 7 days)
2. The new term has fewer miners than the previous term (common due to election dynamics)
3. A miner from the previous term continues into the new term

**Example Calculation:**
- Previous round: 10 miners → encoding threshold = `10.Mul(2).Div(3)` = 6 pieces required [10](#0-9) 

- Current round: 7 miners → decoding threshold = `7.Mul(2).Div(3)` = 4 pieces used
- Check: `10 < 7`? False, so proceeds with reconstruction
- Attempts to decode with 4 pieces a secret requiring 6 pieces → **FAILS**

**Probability:** HIGH - Term transitions are regular events, and miner list fluctuations are expected protocol behavior.

### Recommendation

**Immediate Fix:**
Change line 36 to use strict equality or validate against the previous round's miner count:

```csharp
// Option 1: Require exact count match (strict but safe)
if (anotherMinerInPreviousRound.DecryptedPieces.Count != minersCount) continue;

// Option 2: Use previous round's count for threshold (more robust)
var previousMinersCount = previousRound.RealTimeMinersInformation.Count;
var previousMinimumCount = previousMinersCount.Mul(2).Div(3);
if (anotherMinerInPreviousRound.DecryptedPieces.Count < previousMinersCount) continue;
// Then use previousMinimumCount for DecodeSecret
```

**Invariant Check:**
Add validation that the decoding threshold matches the encoding threshold:
```csharp
Assert(minimumCount <= anotherMinerInPreviousRound.DecryptedPieces.Count, 
    "Insufficient pieces for secret reconstruction based on original threshold");
```

**Test Cases:**
1. Test term transition with miner list shrinking from 10 to 7 miners
2. Verify DecryptedPieces from previous round are correctly reconstructed or skipped
3. Validate that all nodes produce identical in-values during list transitions

### Proof of Concept

**Initial State:**
- Round N: 10 active miners (A, B, C, D, E, F, G, H, I, J)
- Each miner creates secret with threshold = 6, shares = 10
- Miner A accumulates 10 DecryptedPieces in Round N

**Transaction Steps:**
1. Term transition occurs via NextTerm
2. Round N+1: 7 active miners (A, B, C, D, E, F, G) - miners H, I, J removed
3. NextRound consensus behavior triggers
4. `RevealSharedInValues(roundN+1, "MinerA")` called
5. Iterates through previousRound (Round N) miners
6. For Miner B: `DecryptedPieces.Count` = 10, `currentRound.minersCount` = 7
7. Check at line 36: `10 < 7` evaluates to FALSE, proceeds
8. Line 22: `minimumCount = 7 * 2 / 3 = 4`
9. Line 50: Calls `DecodeSecret(sharedParts, orders, 4)` with 4 pieces
10. Secret was encoded with threshold 6, requires minimum 6 pieces
11. Reconstruction produces garbage/incorrect hash

**Expected Result:**
Should skip reconstruction when threshold mismatch detected

**Actual Result:**
Proceeds with insufficient pieces, produces corrupted `PreviousInValue` for Miner B, breaking consensus validation

**Success Condition:**
After fix, the reconstruction is skipped when `DecryptedPieces.Count != minersCount`, or correctly uses previous round's threshold, preventing corruption during miner list transitions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L30-30)
```csharp
            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L36-36)
```csharp
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-50)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L52-52)
```csharp
            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L79-89)
```csharp
    public static long Mul(this long a, long b)
    {
        checked
        {
            return a * b;
        }
    }

    public static long Div(this long a, long b)
    {
        return a / b;
```
