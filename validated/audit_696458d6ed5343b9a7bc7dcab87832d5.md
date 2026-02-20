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

The alternative candidate receives a fresh `MinerInRound` object with `ProducedBlocks` defaulting to 0 [8](#0-7) . **Critically, this automatic replacement never calls `RecordMinerReplacement` to notify the Treasury contract** - the entire replacement happens within lines 301-342 with no Treasury notification.

**Reward Distribution Penalty:**

During reward distribution in `UpdateBasicMinerRewardWeights`, miners without the `IsReplacedEvilMiner` flag are subjected to `CalculateShares` [9](#0-8) . This function applies severe penalties: 0 shares if produced blocks < 50% of average, or quadratic penalty if < 80% of average [10](#0-9) .

The `RecordMinerReplacementInput` proto message includes an `is_old_pubkey_evil` field [11](#0-10) , but grep search confirms it's never set to true in the codebase, confirming this notification gap exists by design oversight.

## Impact Explanation

Alternative candidates who replace evil miners suffer concrete financial harm:

- **Complete loss**: If they produce < 50% of the term average, they receive 0 shares (100% reward loss) as shown in the CalculateShares logic
- **Quadratic penalty**: If they produce 50-80% of average, their shares are calculated as `(producedBlocks² / average)`, significantly reducing rewards
- **Full shares only if ≥80%**: Unlikely for mid-term joiners who had no opportunity to mine earlier

This violates the economic invariant of fair reward distribution. Alternative candidates performed their mining duties correctly after joining, but are penalized for circumstances beyond their control (joining mid-term). The Treasury misallocates funds that should go to these miners, with other miners receiving proportionally higher shares at the expense of alternative candidates.

## Likelihood Explanation

This vulnerability has **high likelihood** of occurrence:

- **Automatic trigger**: Evil miner detection occurs automatically when any miner misses 4320 time slots (3 days of downtime, as confirmed in the constants)
- **No attacker required**: This is a system bug that triggers during normal consensus operations [12](#0-11) 
- **Realistic preconditions**: Miners going offline for 3+ days is common due to maintenance, network issues, or hardware failures
- **Deterministic execution**: Once evil miners are detected, alternative candidates are automatically selected and replaced
- **Observable impact**: The reward penalty manifests in the next `Release` call at term transition [13](#0-12) 

Every automatic evil miner replacement triggers this bug, making it a recurring issue that affects multiple alternative candidates over time.

## Recommendation

Modify `GenerateNextRoundInformation` in `AEDPoSContract_ViewMethods.cs` to call `RecordMinerReplacement` when automatic evil miner replacement occurs:

After replacing the evil miner with an alternative candidate (around line 338), add:
```csharp
// Notify Treasury Contract about the replacement
State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
{
    OldPubkey = evilMinerPubkey,
    NewPubkey = alternativeCandidatePubkey,
    CurrentTermNumber = State.CurrentTermNumber.Value,
    IsOldPubkeyEvil = true
});
```

This ensures that alternative candidates joining via automatic replacement receive the same protection as those joining via manual `ReplaceCandidatePubkey`.

## Proof of Concept

Create a test that demonstrates the vulnerability:

1. Set up initial miners and advance to a term
2. Force one miner to miss 4320 time slots (mark as evil)
3. Wait for automatic replacement to occur during `GenerateNextRoundInformation`
4. Advance to next term and call `Release` to distribute rewards
5. Verify the alternative candidate's `IsReplacedEvilMiner` flag is NOT set (currently fails)
6. Verify the alternative candidate receives 0 or reduced shares despite producing blocks correctly
7. Compare with manual replacement path where the flag IS properly set

The test would show that automatic replacements fail to set the protection flag, causing unfair penalty application to innocent alternative candidates.

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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L123-166)
```csharp
    public override Empty Release(ReleaseInput input)
    {
        RequireAEDPoSContractStateSet();
        Assert(
            Context.Sender == State.AEDPoSContract.Value,
            "Only AElf Consensus Contract can release profits from Treasury.");
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.TreasuryHash.Value,
            Period = input.PeriodNumber,
            AmountsMap = { State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L) }
        });
        RequireElectionContractStateSet();
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });

        var currentMinerList = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(p => p.ToHex()).ToList();
        var maybeNewElectedMiners = new List<string>();
        maybeNewElectedMiners.AddRange(currentMinerList);
        maybeNewElectedMiners.AddRange(previousTermInformation.RealTimeMinersInformation.Keys);
        var replaceCandidates = State.ReplaceCandidateMap[input.PeriodNumber];
        if (replaceCandidates != null)
        {
            Context.LogDebug(() =>
                $"New miners from replace candidate map: {replaceCandidates.Value.Aggregate((l, r) => $"{l}\n{r}")}");
            maybeNewElectedMiners.AddRange(replaceCandidates.Value);
            State.ReplaceCandidateMap.Remove(input.PeriodNumber);
        }

        maybeNewElectedMiners = maybeNewElectedMiners
            .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p)).ToList();
        if (maybeNewElectedMiners.Any())
            Context.LogDebug(() => $"New elected miners: {maybeNewElectedMiners.Aggregate((l, r) => $"{l}\n{r}")}");
        else
            Context.LogDebug(() => "No new elected miner.");

        UpdateStateBeforeDistribution(previousTermInformation, maybeNewElectedMiners);
        ReleaseTreasurySubProfitItems(input.PeriodNumber);
        UpdateStateAfterDistribution(previousTermInformation, currentMinerList);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L596-596)
```csharp
        State.IsReplacedEvilMiner[input.NewPubkey] = true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L328-335)
```csharp
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L337-338)
```csharp
                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
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
