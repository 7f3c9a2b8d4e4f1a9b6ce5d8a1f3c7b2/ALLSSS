# Audit Report

## Title
Incomplete Evil Miner Replacement Due to Insufficient Alternative Candidates

## Summary
The AEDPoS consensus contract contains a critical logic flaw in the miner replacement mechanism where the replacement loop iterates based on the count of available alternative candidates rather than the count of evil miners requiring replacement. When alternative candidate pools are depleted, unreplaced evil miners persist in active consensus rounds, degrading network liveness and block production capacity.

## Finding Description

The vulnerability exists in the interaction between the Election and Consensus contracts during mid-term evil miner replacement.

**Evil Miner Detection**: The system identifies evil miners as those who have missed at least 4320 time slots (representing 3 days at 1 slot/minute). [1](#0-0) 

The detection logic filters miners based on this threshold, returning all miners whose `MissedTimeSlots >= TolerableMissedTimeSlotsCount`. [2](#0-1) 

**Replacement Candidate Selection**: The Election contract's `GetMinerReplacementInformation` attempts to find replacements from election snapshot candidates (excluding initial and current miners), then falls back to initial miners. [3](#0-2) 

The function returns `MinerReplacementInformation` containing two lists that can have different counts when candidate pools are exhausted. [4](#0-3) 

**The Vulnerability**: In the consensus contract's replacement logic, the loop only iterates `AlternativeCandidatePubkeys.Count` times, accessing both lists with the same index. [5](#0-4) 

When `AlternativeCandidatePubkeys.Count < EvilMinerPubkeys.Count`, only the first N evil miners are removed from `currentRound.RealTimeMinersInformation`. The remaining evil miners persist in the dictionary and are carried forward to the next round. [6](#0-5) 

This breaks the consensus invariant that all scheduled miners must be capable of producing blocks.

## Impact Explanation

**Consensus Integrity Degradation**: Unreplaced evil miners remain in the active miner schedule but cannot produce blocks. In a typical 21-miner AEDPoS network, if 10 miners become evil but only 3 get replaced, 7 unreliable miners occupy consensus slots. This represents approximately 33% reduction in effective block production capacity, causing increased block times, potential consensus stalls, and degraded transaction throughput affecting all users.

**Network Liveness Risk**: With sufficient unreplaced evil miners, the network may fail to meet consensus requirements for block finalization. This creates an operational denial-of-service condition where the blockchain cannot process transactions or advance state.

**Affected Parties**: All network participants including validators, end users, dApps, treasury operations, profit distributions, and cross-chain indexing mechanisms that depend on stable consensus.

**Severity Assessment**: HIGH - This directly compromises the core consensus mechanism's integrity. While no funds are immediately stolen, the network's ability to function is severely impaired, potentially leading to complete service disruption.

## Likelihood Explanation

**Trigger Conditions**: The vulnerability activates under realistic network stress scenarios when multiple miners simultaneously fail or go offline for 3+ days (infrastructure outages, coordinated attacks, or natural disasters) and the election candidate pool becomes depleted because most eligible candidates are already serving as miners or have been previously banned.

**Feasibility**: MEDIUM-HIGH probability because the condition occurs automatically without requiring attacker privileges. Mature blockchain networks naturally develop stable miner sets, reducing the available candidate pool over time. Infrastructure failures affecting multiple data centers can cause simultaneous miner outages.

**Detection Difficulty**: The degradation is observable through monitoring but may not trigger immediate alarms since the network continues operating at reduced capacity rather than failing completely.

## Recommendation

Modify the replacement loop to handle all evil miners, even when insufficient alternatives exist:

```csharp
// Process all evil miners, not just those with alternatives
for (var i = 0; i < minerReplacementInformation.EvilMinerPubkeys.Count; i++)
{
    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];
    
    // Update history information of evil node
    UpdateCandidateInformation(evilMinerPubkey,
        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);
    
    // Remove evil miner from active set
    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
    
    // Only add alternative if available
    if (i < minerReplacementInformation.AlternativeCandidatePubkeys.Count)
    {
        var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
        Context.Fire(new MinerReplaced { NewMinerPubkey = alternativeCandidatePubkey });
        
        var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
        currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, new MinerInRound
        {
            Pubkey = alternativeCandidatePubkey,
            ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
            Order = evilMinerInformation.Order,
            PreviousInValue = Hash.Empty,
            IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
        });
    }
}
```

This ensures all evil miners are removed from the active set, even when replacement candidates are insufficient, forcing the network to operate with fewer miners rather than keeping unreliable ones in the schedule.

## Proof of Concept

A valid test demonstrating this vulnerability would need to:
1. Set up a scenario with multiple evil miners (miners with MissedTimeSlots >= 4320)
2. Deplete the alternative candidate pool
3. Trigger round generation
4. Verify that unreplaced evil miners remain in `RealTimeMinersInformation`
5. Confirm these miners persist into the next round

The test would show that when `GetMinerReplacementInformation` returns fewer alternatives than evil miners, the replacement loop only processes `AlternativeCandidatePubkeys.Count` iterations, leaving unreplaced evil miners in the active consensus set.

### Citations

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L363-392)
```csharp
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
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L394-398)
```csharp
        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-56)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```
