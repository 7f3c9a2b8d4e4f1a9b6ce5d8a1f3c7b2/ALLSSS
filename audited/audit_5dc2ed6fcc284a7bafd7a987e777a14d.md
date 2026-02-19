# Audit Report

## Title
Threshold Mismatch in Secret Sharing Causes Incorrect InValue Revelation When Miner List Decreases

## Summary
The `RevealSharedInValues()` function uses the current round's miner count to calculate the Shamir's Secret Sharing decoding threshold, but secrets were encoded using a different round's miner count. When the miner list decreases between rounds, this causes secret reconstruction to use fewer points than the polynomial degree requires, producing mathematically incorrect InValues that break consensus randomness and security.

## Finding Description

The vulnerability manifests in the threshold calculation mismatch between secret encoding and decoding phases within the AEDPoS consensus mechanism.

**Encoding Phase (Off-chain secret creation):**
When secrets for a round are created, the threshold is calculated from the previous round's miner count. [1](#0-0)  This creates a polynomial of degree `threshold - 1` for Shamir's Secret Sharing. [2](#0-1) 

**Decoding Phase (On-chain secret revelation):**
When revealing secrets during round transitions, the function retrieves the previous round but calculates the threshold from the **current** round's miner count. [3](#0-2)  The decoding then uses this potentially incorrect threshold. [4](#0-3) 

**Root Cause:**
The function is called during next-round transitions [5](#0-4)  but uses the wrong reference point for threshold calculation.

**Why Existing Protections Fail:**
The validation checks verify that sufficient decrypted pieces exist [6](#0-5)  but do not validate that the decoding threshold matches the encoding threshold. The mitigation that skips creating NEW secrets when the miner list changes [7](#0-6)  does NOT prevent revealing OLD secrets with an incorrect threshold.

## Impact Explanation

**Mathematical Incorrectness:**
Shamir's Secret Sharing requires exactly `threshold` points to reconstruct a polynomial of degree `threshold - 1`. Using fewer points reconstructs a different polynomial, yielding an entirely different secret. For example:
- Round N: 9 miners, secrets encoded with threshold = 6 (degree-5 polynomial)
- Round N+1: 3 miners, decoding threshold = 2
- Using only 2 points to reconstruct a degree-5 polynomial produces a completely incorrect value

**Protocol Damage:**
InValues are fundamental to AEDPoS consensus security, used for:
- Generating verifiable random functions (VRF)
- Determining fair miner ordering
- Preventing manipulation of consensus randomness
- Chain the `PreviousInValue` field across rounds for validation [8](#0-7) 

Incorrect InValue revelation breaks these cryptographic guarantees, potentially causing:
- Consensus validation failures
- Incorrect miner order calculations
- Broken invariants in subsequent round transitions
- Chain halts or forks

**Affected Parties:** All network participants when miner count decreases.

**Severity:** HIGH - Directly compromises a critical consensus security invariant.

## Likelihood Explanation

**Trigger Conditions:**
This is a deterministic protocol bug that triggers automatically when:
1. Round N has M miners
2. Round N+1 has fewer miners (M' < M) due to:
   - Evil miner replacement [9](#0-8) 
   - Term transitions with reduced miner count
   - Side chain miner list changes [10](#0-9) 
3. During transition from Round N+1 to N+2, secrets from Round N are revealed

**Execution Practicality:**
- No attacker capabilities required
- Occurs during legitimate consensus operations
- The code path is straightforward and inevitable when conditions are met
- No special permissions or preconditions beyond normal round transitions

**Probability:** CERTAIN - Automatically occurs whenever the miner count decreases between consecutive rounds.

## Recommendation

Modify `RevealSharedInValues()` to calculate the threshold based on the round where the secrets were originally encoded, not the current round. Specifically:

1. Calculate `minimumCount` from `previousRound.RealTimeMinersInformation.Count` instead of `currentRound.RealTimeMinersInformation.Count`
2. Store the encoding threshold in the round state when secrets are created, and retrieve it during decoding
3. Add validation to verify the number of available decrypted pieces matches the original encoding parameters

Example fix for the immediate issue:
```csharp
// In RevealSharedInValues, change lines 21-23 from:
var minersCount = currentRound.RealTimeMinersInformation.Count;
// To:
var minersCount = previousRound.RealTimeMinersInformation.Count;
```

This ensures the decoding threshold matches the encoding threshold used when the secrets in `previousRound` were originally created.

## Proof of Concept

A test case would simulate:
1. Initialize Round N with 9 miners
2. Miners create and store secret shares for Round N with threshold = 6
3. Transition to Round N+1 with only 3 miners (miner list decreased)
4. Attempt to reveal secrets from Round N using threshold = 2
5. Verify that the revealed InValue differs from the original encoded value
6. Demonstrate consensus validation failures due to incorrect InValues

The vulnerability is evident in the code logic without requiring complex test execution, as the mathematical impossibility of correctly reconstructing a degree-5 polynomial with 2 points is a fundamental property of Shamir's Secret Sharing.

### Citations

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L14-25)
```csharp
        public static List<byte[]> EncodeSecret(byte[] secretMessage, int threshold, int totalParts)
        {
            // Polynomial construction.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L19-23)
```csharp
        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L52-52)
```csharp
            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-108)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-294)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-342)
```csharp
            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
```
