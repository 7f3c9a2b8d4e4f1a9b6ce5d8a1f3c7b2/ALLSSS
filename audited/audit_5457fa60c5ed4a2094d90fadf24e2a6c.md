### Title
Alternative Candidates Replacing Evil Miners Unfairly Penalized Due to Missing IsReplacedEvilMiner Flag

### Summary
When evil miners are automatically replaced during consensus round generation, the Treasury contract is never notified to set the `IsReplacedEvilMiner` flag for alternative candidates. This causes alternative candidates to be subjected to performance-based reward penalties despite joining mid-term with no opportunity to produce blocks earlier, resulting in reduced or zero mining rewards when they should receive full shares for their actual contribution.

### Finding Description

The `IsReplacedEvilMiner` state variable is designed to protect replacement miners from performance penalties during reward distribution. [1](#0-0) 

The flag is set in `TreasuryContract.RecordMinerReplacement`, which always sets `State.IsReplacedEvilMiner[input.NewPubkey] = true` regardless of whether the old pubkey was evil. [2](#0-1) 

However, `RecordMinerReplacement` is only called from one location: `AEDPoSContract.RecordCandidateReplacement`. [3](#0-2) 

This call path is only triggered during manual candidate replacements via `Election.ReplaceCandidatePubkey`. [4](#0-3) 

**The critical gap:** When evil miners are automatically detected and replaced during `GenerateNextRoundInformation`, the system directly modifies the consensus round by removing the evil miner and adding the alternative candidate, but never calls `RecordMinerReplacement`. [5](#0-4) 

The alternative candidate receives a fresh `MinerInRound` object with `ProducedBlocks` defaulting to 0, inheriting only the evil miner's time slot and order. [6](#0-5) 

During reward distribution in `UpdateBasicMinerRewardWeights`, miners without the `IsReplacedEvilMiner` flag are subjected to `CalculateShares`, which applies severe penalties for underperformance. [7](#0-6) 

The `CalculateShares` function returns 0 shares if produced blocks < 50% of average, and reduced shares if < 80% of average. [8](#0-7) 

The `IsOldPubkeyEvil` field exists in the proto definition but is never set to true anywhere in the codebase, confirming the notification gap. [9](#0-8) 

### Impact Explanation

**Direct Fund Impact - Reward Misallocation:**

Alternative candidates who replace evil miners lose significant mining rewards they legitimately earned. Since they join mid-term with 0 prior produced blocks, their average is much lower than miners who mined the full term. Without the `IsReplacedEvilMiner` protection:

- If they produce < 50% of average: 0 shares (complete loss of rewards)
- If they produce < 80% of average: quadratic penalty (e.g., 60% of average → only 45% shares)
- Only if they produce ≥ 80% of average: full shares (unlikely for mid-term joiners)

This violates the economic invariant that "dividend distribution and settlement accuracy" must be maintained. The alternative candidates performed their mining duties correctly but receive unfair penalties due to a system bug, not their performance.

**Who is affected:**
- Alternative candidates replacing evil miners lose rewards
- The Treasury scheme misallocates funds intended for these miners
- Other miners may receive slightly higher shares at the expense of alternative candidates

**Severity Justification:** Medium severity because it causes concrete financial harm to alternative candidates on every automatic evil miner replacement, but does not allow theft or enable attacker profit.

### Likelihood Explanation

**High Likelihood - Automatic and Frequent:**

- **Reachable Entry Point:** Evil miner detection is automatic and occurs during normal consensus operation when miners miss ≥ 4320 time slots (3 days). [10](#0-9) 

- **No Attacker Required:** This is a system bug that triggers automatically whenever evil miners are detected and replaced through the consensus mechanism. [11](#0-10) 

- **Feasible Preconditions:** Only requires miners to go offline or miss time slots for 3 days, which is a normal operational scenario for node maintenance, network issues, or hardware failures.

- **Execution Certainty:** Once evil miners are detected, alternative candidates are automatically selected from the election snapshot. [12](#0-11) 

- **Observable Impact:** The reward penalty occurs in the next `Release` call when `UpdateBasicMinerRewardWeights` is invoked. [13](#0-12) 

This vulnerability triggers deterministically on every automatic evil miner replacement, making it highly likely to occur and affect multiple alternative candidates over time.

### Recommendation

**Immediate Fix:**

Modify `GenerateNextRoundInformation` to call `RecordCandidateReplacement` for each evil miner replacement, similar to the manual replacement flow. In `AEDPoSContract_ViewMethods.cs`, after line 338, add:

```csharp
State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
{
    OldPubkey = evilMinerPubkey,
    NewPubkey = alternativeCandidatePubkey,
    CurrentTermNumber = State.CurrentTermNumber.Value,
    IsOldPubkeyEvil = true
});
```

**Alternative Fix:**

Set the `IsOldPubkeyEvil` field properly in the existing manual replacement flow at line 149 of `AEDPoSContract.cs` by checking if the old pubkey is in the banned list before calling `RecordMinerReplacement`.

**Invariant Check:**

Add assertion in `UpdateBasicMinerRewardWeights` that verifies alternative candidates (those in `ReplaceCandidateMap`) either have the `IsReplacedEvilMiner` flag set or were added in a previous term.

**Test Cases:**

1. Test that automatic evil miner replacement sets `IsReplacedEvilMiner` flag
2. Test that alternative candidates receive full shares based on their produced blocks without penalty
3. Test that the flag is properly cleared after reward calculation
4. Test the `IsOldPubkeyEvil = true` path in `RecordMinerReplacement` is reached

### Proof of Concept

**Initial State:**
- Main chain with 17 active miners in current term
- Miner "EvilMiner1" has missed 4320+ time slots and will be detected as evil
- Election snapshot has alternative candidates with sufficient votes

**Exploit Steps:**

1. During consensus round transition, `ProcessNextRound` is called by next block producer
2. `GenerateNextRoundInformation` detects evil miner via `GetMinerReplacementInformation` 
3. System replaces "EvilMiner1" with "AltCandidate1" in the current round
4. "AltCandidate1" mines blocks for the remaining portion of the term (e.g., produces 50 blocks)
5. Other miners who mined the full term produce ~150 blocks each
6. At term end, `ProcessNextTerm` calls `DonateMiningReward` and `Release`
7. `UpdateBasicMinerRewardWeights` is invoked with previous term information
8. Average produced blocks = ~140 (since evil miner had 0)
9. "AltCandidate1" with 50 blocks < 70 blocks (50% threshold) → receives 0 shares
10. "AltCandidate1"'s basic mining rewards are forfeited despite valid mining contribution

**Expected Result:** Alternative candidate should receive shares = 50 (their actual produced blocks)

**Actual Result:** Alternative candidate receives shares = 0 (full penalty applied)

**Success Condition:** Check `IsReplacedEvilMiner["AltCandidate1"]` state - it will be unset/false, confirming the flag was never set during automatic replacement, causing the unfair penalty.

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContractState.cs (L50-50)
```csharp
    public MappedState<string, bool> IsReplacedEvilMiner { get; set; }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L596-596)
```csharp
        State.IsReplacedEvilMiner[input.NewPubkey] = true;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L761-761)
```csharp
        UpdateBasicMinerRewardWeights(new List<Round> { previousPreviousTermInformation, previousTermInformation });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L802-811)
```csharp
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L835-846)
```csharp
    private long CalculateShares(long producedBlocksCount, long averageProducedBlocksCount)
    {
        if (producedBlocksCount < averageProducedBlocksCount.Div(2))
            // If count < (1/2) * average_count, then this node won't share Basic Miner Reward.
            return 0;

        if (producedBlocksCount < averageProducedBlocksCount.Div(5).Mul(4))
            // If count < (4/5) * average_count, then ratio will be (count / average_count)
            return producedBlocksCount.Mul(producedBlocksCount).Div(averageProducedBlocksCount);

        return producedBlocksCount;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L149-154)
```csharp
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L311-339)
```csharp
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
```

**File:** protobuf/treasury_contract.proto (L158-158)
```text
    bool is_old_pubkey_evil = 4;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L357-398)
```csharp
    public override MinerReplacementInformation GetMinerReplacementInformation(
        GetMinerReplacementInformationInput input)
    {
        var evilMinersPubKeys = GetEvilMinersPubkeys(input.CurrentMinerList);
        Context.LogDebug(() => $"Got {evilMinersPubKeys.Count} evil miners pubkeys from {input.CurrentMinerList}");
        var alternativeCandidates = new List<string>();
        var latestSnapshot = GetPreviousTermSnapshotWithNewestPubkey();
        // Check out election snapshot.
        if (latestSnapshot != null && latestSnapshot.ElectionResult.Any())
        {
            Context.LogDebug(() => $"Previous term snapshot:\n{latestSnapshot}");
            var maybeNextCandidates = latestSnapshot.ElectionResult
                // Except initial miners.
                .Where(cs =>
                    !State.InitialMiners.Value.Value.Contains(
                        ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
                // Except current miners.
                .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
                .OrderByDescending(s => s.Value).ToList();
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
            Context.LogDebug(() =>
                $"Found alternative miner from candidate list: {alternativeCandidates.Aggregate("\n", (key1, key2) => key1 + "\n" + key2)}");
        }

        // If the count of evil miners is greater than alternative candidates, add some initial miners to alternative candidates.
        var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
        if (diff > 0)
        {
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
        }

        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
```
