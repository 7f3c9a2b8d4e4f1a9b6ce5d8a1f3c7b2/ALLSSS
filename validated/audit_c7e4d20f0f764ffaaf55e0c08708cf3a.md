# Audit Report

## Title
Cross-Term Secret Sharing Corruption in NextRound Consensus Behavior

## Summary
The `RevealSharedInValues` function is called during `NextRound` consensus behavior without validating that `currentRound` and `previousRound` belong to the same term. When a term transition occurs and miner counts differ, the function uses secret sharing data from the old term with threshold parameters calculated from the new term, causing mismatches that corrupt `PreviousInValue` fields and subsequent consensus signatures.

## Finding Description

When transitioning from the first round to the second round of a new term, `GetConsensusExtraDataForNextRound` calls `RevealSharedInValues` without term validation [1](#0-0) . This function retrieves the previous round [2](#0-1) , which after a term change belongs to the old term with a potentially different miner count.

The function calculates threshold parameters from the NEW term's miner count [3](#0-2)  but applies them to secret sharing pieces from the OLD term. Specifically, the validation checks if `DecryptedPieces.Count < minersCount` where `minersCount` is from the new term, but the pieces were generated for the old term's miner count [4](#0-3) . The function then calls `SecretSharingHelper.DecodeSecret` with the incorrect `minimumCount` threshold [5](#0-4) .

In contrast, `GetConsensusExtraDataToPublishOutValue` properly validates term boundaries before using previous round data with the `IsFirstRoundOfCurrentTerm` check [6](#0-5) . The `IsFirstRoundOfCurrentTerm` method checks if the previous round's term number differs from the current term [7](#0-6) .

While `AddRoundInformation` prevents NEW secret sharing generation when the miner list changes [8](#0-7) , it does NOT prevent `RevealSharedInValues` from USING old cross-term secret sharing data. The first round of a new term has `IsMinerListJustChanged` set to true [9](#0-8) , but this only affects secret sharing generation, not consumption.

The Shamir Secret Sharing `DecodeSecret` implementation uses the provided threshold parameter to perform Lagrange interpolation [10](#0-9) . When the wrong threshold is used, the interpolation produces mathematically incorrect results (garbage data) rather than throwing an error. The corrupted `PreviousInValue` is stored in the current round's miner information [11](#0-10)  and subsequently used in signature calculations via `CalculateSignature` [12](#0-11) .

## Impact Explanation

**Consensus Integrity Corruption**: The incorrectly decoded `PreviousInValue` directly corrupts consensus signatures. These signatures are fundamental to AEDPoS consensus for:

1. **Signature Chain Integrity**: The `CalculateSignature` method XORs the InValue with all existing miner signatures to form a cryptographic chain. Corrupted PreviousInValue values break this chain's verifiability.

2. **Randomness Source**: Signatures are used as sources of randomness that determine mining order and extra block producer selection. Corrupted signatures compromise this randomness, potentially affecting block producer fairness.

3. **Consensus Divergence**: When multiple miners process the corrupted round transition, they may produce inconsistent round data, leading to consensus instability.

**Severity: Medium-High** because:
- Directly impacts core consensus integrity (critical invariant)
- No direct fund theft, but corrupts fundamental security properties
- Affects all miners transitioning across terms
- Can compromise randomness-dependent features (block producer selection, rewards)

## Likelihood Explanation

**Trigger Path**: The public `NextRound` method [13](#0-12)  triggers this vulnerability when called during the first round of a new term.

**Automatic Execution**: The consensus behavior provider determines whether to use `NextRound` or `NextTerm` behavior [14](#0-13) . After any term transition via `ProcessNextTerm` [15](#0-14) , the next round advancement will trigger `NextRound` behavior, not another term change.

**Preconditions**:
1. Term transition occurs (periodic, every `PeriodSeconds`)
2. Miner count or membership changes between terms (set via `GenerateFirstRoundOfNewTerm` which increments both round and term numbers [16](#0-15) )
3. Any miner calls `NextRound` to advance from the first round to the second round of the new term

These are normal consensus operations requiring no special privileges or timing—just being a miner in the current term.

**Probability: High** - Occurs automatically on every term transition where miner count changes. Term transitions are periodic and the vulnerability triggers during standard consensus progression.

## Recommendation

Add term boundary validation in `GetConsensusExtraDataForNextRound` before calling `RevealSharedInValues`, similar to the protection in `GetConsensusExtraDataToPublishOutValue`:

```csharp
private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
    string pubkey, AElfConsensusTriggerInformation triggerInformation)
{
    GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

    nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

    if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };

    // Add term boundary check here
    if (!IsFirstRoundOfCurrentTerm(out _))
    {
        RevealSharedInValues(currentRound, pubkey);
    }

    nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
    Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
    nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
    nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
        .Add(Context.CurrentBlockTime);

    return new AElfConsensusHeaderInformation
    {
        SenderPubkey = ByteStringHelper.FromHexString(pubkey),
        Round = nextRound,
        Behaviour = triggerInformation.Behaviour
    };
}
```

This prevents `RevealSharedInValues` from using secret sharing data that crosses term boundaries where miner counts may have changed.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a blockchain with 7 miners in term 1
2. Generating secret sharing pieces during normal operation
3. Triggering a term transition to term 2 with 5 miners
4. Calling `NextRound` to advance from round 1 to round 2 of term 2
5. Observing that `RevealSharedInValues` uses `minersCount=5` (from term 2) to decode secrets generated with `threshold=4` (2/3 of 7 miners from term 1)
6. Verifying that the decoded `PreviousInValue` is incorrect garbage data
7. Confirming that this corrupted value is used in subsequent `CalculateSignature` calls

The test would verify that the signature calculated using the corrupted `PreviousInValue` differs from the expected signature, demonstrating the consensus integrity violation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L72-72)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L189-189)
```csharp
        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L19-19)
```csharp
        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L21-23)
```csharp
        var minersCount = currentRound.RealTimeMinersInformation.Count;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L52-52)
```csharp
            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L27-34)
```csharp
    private bool IsFirstRoundOfCurrentTerm(out long termNumber)
    {
        termNumber = 1;
        return (TryToGetTermNumber(out termNumber) &&
                TryToGetPreviousRoundInformation(out var previousRound) &&
                previousRound.TermNumber != termNumber) ||
               (TryToGetRoundNumber(out var roundNumber) && roundNumber == 1);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L40-42)
```csharp
        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
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
