# Audit Report

## Title
Insufficient Alternative Candidates Allows Banned Miners to Remain in Consensus

## Summary
The AEDPoS consensus contract's miner replacement mechanism contains a critical logic error that allows banned miners to continue participating in consensus when the alternative candidate pool is insufficient. The replacement loop iterates based on the number of available alternatives rather than the number of evil miners, causing partial replacement and allowing unreplaced banned miners to continue producing blocks and earning rewards.

## Finding Description

When generating the next consensus round, the system calls `GetMinerReplacementInformation` to identify banned miners and find replacement candidates. [1](#0-0) 

The replacement logic uses a loop that iterates based on `AlternativeCandidatePubkeys.Count` and accesses both the alternatives and evil miners lists by index: [2](#0-1) 

However, `GetMinerReplacementInformation` can legitimately return fewer alternatives than evil miners when the candidate pool is exhausted. It first attempts to take candidates from the election snapshot (limited by availability): [3](#0-2) 

Then tries to fill the gap with initial miners, but these are filtered to exclude banned and currently active miners: [4](#0-3) 

The method returns both lists potentially with mismatched sizes: [5](#0-4) 

**Root Cause:** When `AlternativeCandidatePubkeys.Count < EvilMinerPubkeys.Count`, the replacement loop only removes the first N evil miners (where N equals the alternative count). The remaining evil miners at indices N and beyond are never accessed and remain in `currentRound.RealTimeMinersInformation`.

Subsequently, `Round.GenerateNextRoundInformation` generates the next round using whatever miners exist in `RealTimeMinersInformation` without filtering for banned status: [6](#0-5) 

The unreplaced banned miners propagate into the next round and can continue producing blocks because block validation only checks if the miner is in the current miner list, not if they're banned: [7](#0-6) 

Miners become banned when they miss too many time slots (4320 time slots = 3 days): [8](#0-7) 

The system detects evil miners and marks them as banned: [9](#0-8) 

And sets their banned status in the Election contract: [10](#0-9) 

## Impact Explanation

**Critical Consensus Integrity Violation:** This vulnerability breaks the fundamental invariant that miners banned via `State.BannedPubkeyMap` for violating consensus rules must be excluded from consensus participation. Unreplaced evil miners continue producing blocks despite being penalized for excessive missed time slots, directly compromising consensus integrity.

**Reward Misallocation:** Banned miners continue earning block production rewards through the Treasury contract's mining reward distribution mechanism. This undermines the economic security model that relies on punishment to discourage misbehavior, as malicious miners can avoid the intended economic penalty.

**Attack Amplification:** Multiple malicious miners can coordinate to simultaneously misbehave (miss time slots). If the alternative candidate pool is shallow due to low election participation or most initial miners being already active or banned, several evil miners will remain active. This enables sustained coordinated attacks against chain liveness and security while continuing to earn rewards.

**Severity: Critical** - This breaks core consensus assumptions, allows complete circumvention of the punishment mechanism, and enables persistent malicious activity that threatens the blockchain's security guarantees.

## Likelihood Explanation

**Automatically Triggered:** The vulnerability is part of the normal consensus block production flow through `GenerateNextRoundInformation`, requiring no special permissions or attacker intervention to be invoked during regular round transitions.

**Realistic Preconditions:**
1. Multiple miners marked as evil in the same term (naturally occurs through network issues, bugs, or coordinated attacks)
2. Limited alternative candidates in the election snapshot (common during periods of low voter participation)
3. Most initial miners already in the current miner list or also banned (typical in mature blockchain networks)

**High Execution Practicality:** The scenario occurs naturally when election participation is low, multiple miners fail simultaneously, or the initial miner set is largely exhausted. Attackers controlling multiple miner nodes can deliberately cause time slot misses across their nodes, and with shallow candidate pools, some nodes will remain active despite being marked evil.

**Limited Detection:** The mismatch is only visible through debug logs, and unreplaced evil miners continue normal operation, making the issue difficult to detect without specifically monitoring the banned pubkey map against active miner lists.

**Likelihood: High** - All preconditions are realistic in production environments, especially during low election participation periods or network stress events.

## Recommendation

Add a validation check to ensure the replacement loop handles all evil miners, not just those with available alternatives. Additionally, add banned-miner filtering to prevent any banned miner from participating in consensus:

```csharp
// In GenerateNextRoundInformation (AEDPoSContract_ViewMethods.cs)
if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
{
    // Replace miners where alternatives are available
    for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
    {
        // ... existing replacement logic ...
    }
    
    // Remove remaining evil miners without replacement
    for (var i = minerReplacementInformation.AlternativeCandidatePubkeys.Count; 
         i < minerReplacementInformation.EvilMinerPubkeys.Count; i++)
    {
        var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];
        UpdateCandidateInformation(evilMinerPubkey,
            currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
            currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);
        currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
    }
    
    isMinerListChanged = true;
}

// Alternative: Add filtering in Round.GenerateNextRoundInformation
// Filter out any banned miners before generating next round
var activeMinerKeys = RealTimeMinersInformation.Keys
    .Where(k => !IsBanned(k)) // Would need to check BannedPubkeyMap
    .ToList();
```

## Proof of Concept

```csharp
[Fact]
public async Task BannedMinersRemainActive_WhenInsufficientAlternatives()
{
    // Setup: Initialize consensus with 5 miners
    var miners = await InitializeConsensusWithMiners(5);
    
    // Mark 3 miners as evil by having them miss excessive time slots
    foreach (var miner in miners.Take(3))
    {
        await MakeMinerMissTimeSlots(miner, TolerableMissedTimeSlotsCount);
    }
    
    // Setup election contract with only 1 alternative candidate
    // (while 3 evil miners need replacement)
    await SetupElectionWithAlternatives(1);
    
    // Trigger next round generation
    await ProcessNextRound();
    
    // Verify: Check that 2 evil miners remain in the active miner list
    var currentRound = await GetCurrentRound();
    var evilMinersStillActive = miners.Take(3)
        .Count(m => currentRound.RealTimeMinersInformation.ContainsKey(m.Pubkey));
    
    // Expected: 2 evil miners remain (3 evil - 1 alternative = 2 unreplaced)
    Assert.Equal(2, evilMinersStillActive);
    
    // Verify these banned miners can still produce blocks
    var bannedMiner = miners[1]; // Second evil miner (unreplaced)
    var blockProduced = await bannedMiner.ProduceBlock();
    Assert.True(blockProduced, "Banned miner should not be able to produce blocks");
}
```

## Notes

This vulnerability represents a **genuine consensus security failure** where the protocol's enforcement mechanism for punishing misbehaving miners can be partially bypassed. The issue is particularly concerning because:

1. **Silent Failure:** The system appears to function normally even when banned miners remain active
2. **Economic Impact:** Banned miners continue earning rewards they should forfeit
3. **Coordination Potential:** Attackers can exploit this during low election participation
4. **Detection Difficulty:** Requires cross-referencing banned status with active miner lists

The fix must ensure that ALL evil miners are either replaced or removed, never allowed to remain in consensus regardless of alternative candidate availability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L376-379)
```csharp
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
            Context.LogDebug(() =>
                $"Found alternative miner from candidate list: {alternativeCandidates.Aggregate("\n", (key1, key2) => key1 + "\n" + key2)}");
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L383-391)
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
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L394-398)
```csharp
        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L16-18)
```csharp
        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-20)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L179-181)
```csharp
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L96-96)
```csharp
            State.BannedPubkeyMap[input.Pubkey] = true;
```
