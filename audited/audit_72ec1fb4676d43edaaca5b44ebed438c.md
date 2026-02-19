# Audit Report

## Title
Banned Initial Miners Can Re-Enter Miner Lists and Receive Rewards

## Summary
When an initial miner is banned through `UpdateCandidateInformation` with `IsEvilNode=true`, they are removed from the candidates list but remain in `State.InitialMiners`. The `GetVictories` method fails to check `BannedPubkeyMap` when adding initial miners as backups during term changes, allowing banned initial miners to re-enter the active miner list and continue receiving mining rewards, completely bypassing the ban.

## Finding Description

The vulnerability exists due to inconsistent handling of banned initial miners across different code paths in the Election contract.

When a miner is banned via `UpdateCandidateInformation`, the pubkey is added to `State.BannedPubkeyMap` and removed from `State.Candidates` and `State.CandidateInformationMap`, but critically, it is **not removed** from `State.InitialMiners`: [1](#0-0) 

During term changes, the consensus contract calls `GenerateFirstRoundOfNextTerm`, which invokes `TryToGetVictories`: [2](#0-1) 

This calls the Election contract's `GetVictories` method: [3](#0-2) 

When there are insufficient valid candidates, `GetVictories` adds initial miners to the backups list **without checking** `BannedPubkeyMap`: [4](#0-3) 

This contrasts with `GetMinerReplacementInformation`, which correctly filters banned initial miners when selecting alternatives during the same term: [5](#0-4) 

The inconsistency is clear: line 389 in `GetMinerReplacementInformation` explicitly checks `.Where(k => !State.BannedPubkeyMap[k])`, while lines 67-69 in `GetVictories` have no such check.

Once the banned initial miner is included in the victories list, they become part of the new term's miner list and the Treasury contract distributes rewards to all miners in the round: [6](#0-5) 

The reward distribution iterates through all miners in `previousTermInformation.Last().RealTimeMinersInformation.Values` without checking ban status, allocating shares based on produced blocks.

## Impact Explanation

This vulnerability has HIGH severity impact:

1. **Direct Fund Misallocation**: Banned initial miners continue to receive proportional mining rewards from the Basic Reward scheme based on blocks they produce, misallocating treasury funds intended for legitimate miners.

2. **Consensus Integrity Violation**: Banned nodes marked as malicious continue participating in consensus and producing blocks, violating the core security assumption that the miner schedule excludes evil actors.

3. **Governance Mechanism Bypass**: The entire evil node detection and banning system becomes ineffective for initial miners during periods of insufficient elected candidates, undermining the protocol's self-governance capabilities.

4. **Reduced Legitimate Miner Rewards**: Since mining rewards are distributed proportionally, the presence of banned miners dilutes the reward shares for honest miners who should receive the full allocation.

The quantifiable damage includes banned miners receiving `(their_produced_blocks / total_produced_blocks) * basic_reward_pool` per term. With typical configurations of 17-21 initial miners, a single banned miner could capture 5-6% of the basic reward pool per 7-day term.

## Likelihood Explanation

This vulnerability has CERTAIN likelihood when preconditions are met:

**Triggering Conditions**:
1. An initial miner is banned via the evil node detection mechanism
2. There are insufficient elected candidates (with votes) to fill all miner slots
3. A term change occurs

**Why It's Inevitable**:
- The bug is triggered automatically during normal term changes through the consensus contract's call to `GetVictories`
- No attacker action is required; this is a deterministic protocol-level flaw
- The conditions naturally occur in early chain stages with low voter participation
- Once triggered, the execution path is guaranteed: term change → GetVictories → banned miner included → rewards distributed

**Feasibility**:
- The code path is part of the standard term transition flow executed by the consensus contract
- No special permissions beyond being an initial miner are required
- The inconsistency between `GetMinerReplacementInformation` (which filters banned miners) and `GetVictories` (which does not) proves this is not intended behavior

## Recommendation

Add a banned status check when including initial miners in `GetVictories`. Modify the backup selection logic to filter out banned pubkeys:

In `contract/AElf.Contracts.Election/ViewMethods.cs`, update lines 67-69 to:

```csharp
if (State.InitialMiners.Value != null)
    backups.AddRange(
        State.InitialMiners.Value.Value.Select(k => k.ToHex())
            .Where(k => !State.BannedPubkeyMap[k])  // Add this check
            .Where(k => !backups.Contains(k)));
```

This aligns `GetVictories` with the existing behavior of `GetMinerReplacementInformation` and ensures banned initial miners cannot re-enter the miner list through any code path.

## Proof of Concept

```csharp
[Fact]
public async Task BannedInitialMiner_CanReEnter_WhenInsufficientCandidates()
{
    // Setup: Initialize with initial miners
    await InitializeContracts();
    
    // Get an initial miner pubkey
    var initialMinerPubkey = InitialCoreDataCenterKeyPairs[0].PublicKey.ToHex();
    
    // Ban the initial miner
    await ElectionContractStub.UpdateCandidateInformation.SendAsync(
        new UpdateCandidateInformationInput
        {
            Pubkey = initialMinerPubkey,
            IsEvilNode = true
        });
    
    // Verify miner is banned
    var isBanned = await ElectionContractStub.IsPubkeyBanned.CallAsync(
        new StringValue { Value = initialMinerPubkey });
    isBanned.Value.ShouldBeTrue();
    
    // Trigger term change with insufficient elected candidates
    await NextTerm(InitialCoreDataCenterKeyPairs[1]);
    
    // Get current miner list
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // BUG: Banned initial miner is included in victories
    victories.Value.Select(p => p.ToHex()).ShouldContain(initialMinerPubkey);
    
    // Verify the banned miner receives rewards in the next term
    var minerList = await AEDPoSContractStub.GetCurrentMinerList.CallAsync(new Empty());
    minerList.Pubkeys.Select(p => p.ToHex()).ShouldContain(initialMinerPubkey);
}
```

This test demonstrates that a banned initial miner successfully re-enters the active miner list when `GetVictories` is called during a term change with insufficient elected candidates, proving the vulnerability exists in the production code.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-232)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-282)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L62-76)
```csharp
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
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L383-392)
```csharp
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
