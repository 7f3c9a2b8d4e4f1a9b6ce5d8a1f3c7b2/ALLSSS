# Audit Report

## Title
Alternative Candidates Replacing Evil Miners Unfairly Penalized Due to Missing IsReplacedEvilMiner Flag

## Summary
When evil miners are automatically replaced during consensus round generation, the Treasury contract is never notified to set the `IsReplacedEvilMiner` flag for alternative candidates. This causes alternative candidates to be subjected to performance-based reward penalties despite joining mid-term with no opportunity to produce blocks earlier, resulting in reduced or zero mining rewards.

## Finding Description

The AElf consensus system has two paths for miner replacement: manual (via `Election.ReplaceCandidatePubkey`) and automatic (via evil miner detection in `GenerateNextRoundInformation`). Only the manual path properly notifies the Treasury contract.

**Manual Replacement Path (Works Correctly):**
The Election contract calls `AEDPoS.RecordCandidateReplacement` [1](#0-0) , which then calls `Treasury.RecordMinerReplacement` [2](#0-1) . This sets the protection flag unconditionally [3](#0-2) .

**Automatic Replacement Path (Broken):**
During `GenerateNextRoundInformation`, when evil miners (those who missed ≥4320 time slots) [4](#0-3)  are detected [5](#0-4) , the system obtains alternative candidates [6](#0-5)  and directly modifies the consensus round [7](#0-6) . 

The alternative candidate receives a fresh `MinerInRound` object with `ProducedBlocks` defaulting to 0 [8](#0-7) . **Critically, this automatic replacement never calls `RecordMinerReplacement` to notify the Treasury contract.**

**Reward Distribution Penalty:**
During reward distribution in `UpdateBasicMinerRewardWeights`, miners without the `IsReplacedEvilMiner` flag are subjected to `CalculateShares` [9](#0-8) . This function applies severe penalties: 0 shares if produced blocks < 50% of average, or quadratic penalty if < 80% of average [10](#0-9) .

The `RecordMinerReplacementInput` proto message includes an `is_old_pubkey_evil` field [11](#0-10) , but it's never set to true in the codebase, confirming this notification gap exists by design oversight.

## Impact Explanation

Alternative candidates who replace evil miners suffer concrete financial harm:

- **Complete loss**: If they produce < 50% of the term average, they receive 0 shares (100% reward loss)
- **Quadratic penalty**: If they produce 50-80% of average, their shares are calculated as `(producedBlocks² / average)`, significantly reducing rewards
- **Full shares only if ≥80%**: Unlikely for mid-term joiners who had no opportunity to mine earlier

This violates the economic invariant of fair reward distribution. Alternative candidates performed their mining duties correctly after joining, but are penalized for circumstances beyond their control (joining mid-term). The Treasury misallocates funds that should go to these miners, with other miners receiving proportionally higher shares at the expense of alternative candidates.

## Likelihood Explanation

This vulnerability has **high likelihood** of occurrence:

- **Automatic trigger**: Evil miner detection occurs automatically when any miner misses 4320 time slots (3 days of downtime)
- **No attacker required**: This is a system bug that triggers during normal consensus operations
- **Realistic preconditions**: Miners going offline for 3+ days is common due to maintenance, network issues, or hardware failures
- **Deterministic execution**: Once evil miners are detected, alternative candidates are automatically selected and replaced
- **Observable impact**: The reward penalty manifests in the next `Release` call at term transition

Every automatic evil miner replacement triggers this bug, making it a recurring issue that affects multiple alternative candidates over time.

## Recommendation

Add a call to `Treasury.RecordMinerReplacement` in the automatic replacement flow within `GenerateNextRoundInformation`. Specifically, after replacing the evil miner in the current round, notify the Treasury contract:

```csharp
// After line 338 in AEDPoSContract_ViewMethods.cs
State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
{
    OldPubkey = evilMinerPubkey,
    NewPubkey = alternativeCandidatePubkey,
    CurrentTermNumber = State.CurrentTermNumber.Value,
    IsOldPubkeyEvil = true
});
```

This ensures alternative candidates receive the `IsReplacedEvilMiner` protection flag, allowing them to receive fair rewards based on their actual contribution without being penalized for joining mid-term.

## Proof of Concept

A complete test would require:
1. Setting up a consensus environment with multiple miners
2. Having one miner miss 4320 time slots to trigger evil miner detection
3. Allowing automatic replacement to occur in `GenerateNextRoundInformation`
4. Verifying the alternative candidate's `IsReplacedEvilMiner` flag is NOT set in Treasury state
5. Completing the term and calling `Release` to distribute rewards
6. Observing that the alternative candidate receives penalized shares via `CalculateShares` despite mining correctly after joining

The vulnerability is evident from code inspection: the automatic replacement path in `GenerateNextRoundInformation` never makes any call to the Treasury contract, while the manual path explicitly does through `RecordCandidateReplacement`. This architectural gap ensures alternative candidates lose the protection flag that was designed specifically for this scenario.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L596-596)
```csharp
        State.IsReplacedEvilMiner[input.NewPubkey] = true;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L802-812)
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
                    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L357-399)
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
    }
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

**File:** protobuf/treasury_contract.proto (L154-159)
```text
message RecordMinerReplacementInput {
    string old_pubkey = 1;
    string new_pubkey = 2;
    int64 current_term_number = 3;
    bool is_old_pubkey_evil = 4;
}
```
