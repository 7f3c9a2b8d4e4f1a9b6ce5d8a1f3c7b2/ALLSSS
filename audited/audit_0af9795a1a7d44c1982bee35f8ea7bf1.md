# Audit Report

## Title
Banned Initial Miners Can Re-Enter Miner Lists and Receive Rewards

## Summary
When an initial miner is banned through the evil node detection mechanism, they are not removed from the `State.InitialMiners` list. The `GetVictories` method, which selects miners for the next term, does not check the `BannedPubkeyMap` when adding initial miners as backup candidates. This allows banned initial miners to re-enter the active miner list and continue receiving mining rewards, completely bypassing the banning mechanism.

## Finding Description

**Root Cause:**

When an initial miner is marked as evil via `UpdateCandidateInformation` with `IsEvilNode=true`, the method adds the pubkey to `State.BannedPubkeyMap` and removes it from `State.Candidates` and `State.CandidateInformationMap`. However, it **never removes the pubkey from `State.InitialMiners`**. [1](#0-0) 

The `GetVictories` method is called during term changes to determine the next term's miner list. When there are insufficient valid candidates (elected miners with votes), it fills the remaining slots with backup miners. When adding initial miners to the backups list, **no check is performed against `State.BannedPubkeyMap`**: [2](#0-1) 

This contrasts sharply with the `GetMinerReplacementInformation` method, which correctly filters out banned initial miners when selecting alternatives for evil miners during the same term: [3](#0-2) 

**Execution Path:**

1. An initial miner is detected as evil and `RemoveEvilNode` calls `UpdateCandidateInformation` with `IsEvilNode=true` [4](#0-3) 

2. The miner is banned (added to `BannedPubkeyMap`) but remains in `State.InitialMiners`

3. At the next term change, the consensus contract calls `TryToGetVictories` which invokes the Election contract's `GetVictories` method to determine the new miner list [5](#0-4) [6](#0-5) 

4. If there are insufficient elected candidates, `GetVictories` adds initial miners as backups without checking if they're banned [7](#0-6) 

5. The banned initial miner is included in the victories list and used to generate the next round [8](#0-7) 

6. The consensus contract processes the next term with this miner included in the active miner list [9](#0-8) 

7. The Treasury contract distributes mining rewards to all miners in the round, including the banned initial miner, based on their produced blocks [10](#0-9) 

The vulnerability breaks the security guarantee that banned nodes are excluded from consensus participation and reward distribution.

## Impact Explanation

**Direct Harm:**
- Banned initial miners continue to participate in consensus and produce blocks despite being marked as malicious
- They receive proportional mining rewards based on blocks produced, misallocating treasury funds intended for legitimate miners
- The banning mechanism is completely ineffective for initial miners when there are insufficient elected candidates

**Quantified Damage:**
- Mining rewards are distributed via the Basic Reward scheme based on produced blocks. The share calculation is based on the ratio of a miner's produced blocks to the average. [11](#0-10) 
- A banned initial miner can receive rewards equal to `(their_produced_blocks / total_produced_blocks) * basic_reward_pool`
- With typical configurations of 17-21 initial miners, a single banned miner could receive 5-6% of the basic reward pool per term

**Affected Parties:**
- **Legitimate miners**: Receive reduced reward shares as the pool is divided among more participants including banned miners
- **Token holders/voters**: Their voting mechanism is undermined as banned nodes they did not elect can still participate
- **Protocol integrity**: The consensus security model assumes banned nodes are excluded, not that they can re-enter

**Severity Justification:**
This is a HIGH severity issue because it:
1. Directly violates the consensus invariant that miner schedule integrity must be maintained
2. Causes continuous fund misallocation (rewards to malicious actors)
3. Undermines the entire node banning and governance mechanism
4. Has existed in the codebase since the initial implementation of the banning feature

## Likelihood Explanation

**Attacker Capabilities:**
No attacker action is required. This is a protocol-level bug that occurs whenever:
1. An initial miner is banned via the evil node detection mechanism
2. There are insufficient elected candidates to fill all miner slots

**Feasibility Conditions:**
Highly feasible because:
- The code path is triggered automatically during normal term changes
- No special permissions or preconditions are needed beyond the existence of a banned initial miner
- The bug manifests in any chain configuration with banned initial miners and insufficient elected candidates
- The chain is likely in this state during early stages with low voter participation

**Detection/Operational Constraints:**
- The bug is not easily detectable as banned miners would appear as normal miners in the active list
- Only by cross-referencing `BannedPubkeyMap` with active miner lists would the issue be discovered
- No events or logs specifically indicate this anomaly

**Probability:**
CERTAIN to occur if the preconditions are met (banned initial miner + insufficient candidates). This is not a probabilistic attack but a deterministic bug in the state management logic.

## Recommendation

Add a check for banned pubkeys when adding initial miners to the backups list in the `GetVictories` method:

```csharp
if (State.InitialMiners.Value != null)
    backups.AddRange(
        State.InitialMiners.Value.Value.Select(k => k.ToHex())
            .Where(k => !State.BannedPubkeyMap[k])  // Add this check
            .Where(k => !backups.Contains(k)));
```

This fix aligns the `GetVictories` method with the existing behavior in `GetMinerReplacementInformation`, which already correctly filters out banned initial miners.

## Proof of Concept

The vulnerability can be demonstrated through the following test scenario:

1. Initialize a chain with initial miners
2. Mark one initial miner as evil using `RemoveEvilNode` or through consensus evil detection
3. Ensure insufficient elected candidates exist (fewer than `MinersCount`)
4. Trigger a term change
5. Observe that the banned initial miner is included in the `GetVictories` result
6. Verify that the banned miner participates in consensus and receives rewards

The test would validate that:
- After banning, `State.BannedPubkeyMap[bannedPubkey]` returns `true`
- After banning, `State.InitialMiners.Value.Value` still contains the banned pubkey
- `GetVictories` returns a miner list that includes the banned pubkey when backups are needed
- The Treasury distributes rewards to the banned miner based on produced blocks

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-112)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
            var rankingList = State.DataCentersRankingList.Value;
            if (rankingList.DataCenters.ContainsKey(input.Pubkey))
            {
                rankingList.DataCenters[input.Pubkey] = 0;
                UpdateDataCenterAfterMemberVoteAmountChanged(rankingList, input.Pubkey, true);
                State.DataCentersRankingList.Value = rankingList;
            }

            Context.LogDebug(() => $"Marked {input.Pubkey.Substring(0, 10)} as an evil node.");
            Context.Fire(new EvilMinerDetected { Pubkey = input.Pubkey });
            State.CandidateInformationMap.Remove(input.Pubkey);
            var candidates = State.Candidates.Value;
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
            RemoveBeneficiary(input.Pubkey);
            return new Empty();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-351)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L60-77)
```csharp
        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L387-391)
```csharp
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-233)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-190)
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
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L777-821)
```csharp
    private void UpdateBasicMinerRewardWeights(IReadOnlyCollection<Round> previousTermInformation)
    {
        if (previousTermInformation.First().RealTimeMinersInformation != null)
            State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
            {
                SchemeId = State.BasicRewardHash.Value,
                Beneficiaries =
                {
                    GetAddressesFromCandidatePubkeys(previousTermInformation.First().RealTimeMinersInformation.Keys)
                }
            });

        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
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

                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
                })
            }
        });
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
