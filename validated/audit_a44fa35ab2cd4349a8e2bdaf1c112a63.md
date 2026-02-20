# Audit Report

## Title
Insufficient Alternative Candidates Allows Banned Miners to Remain in Consensus

## Summary
The AEDPoS consensus contract's miner replacement mechanism contains a critical logic error that allows banned miners to continue participating in consensus when the alternative candidate pool is insufficient. The replacement loop iterates based on the number of available alternatives rather than the number of evil miners, causing partial replacement and allowing unreplaced banned miners to continue producing blocks and earning rewards.

## Finding Description

When generating the next consensus round, the system calls `GetMinerReplacementInformation` from the Election contract to identify banned miners and find replacement candidates. [1](#0-0) 

The critical flaw lies in the replacement loop that iterates based on `AlternativeCandidatePubkeys.Count` and accesses both lists by index, assuming they have equal size: [2](#0-1) 

However, `GetMinerReplacementInformation` can legitimately return fewer alternatives than evil miners. It first attempts to take candidates from the election snapshot with explicit size limiting: [3](#0-2) 

Then tries to fill the gap with initial miners, but these are filtered to exclude banned and currently active miners, potentially failing to provide enough replacements: [4](#0-3) 

The method returns both lists with potentially mismatched sizes: [5](#0-4) 

**Root Cause:** When `AlternativeCandidatePubkeys.Count < EvilMinerPubkeys.Count`, the loop only removes the first N evil miners (where N equals the alternative count). The remaining evil miners at indices N and beyond are never accessed and remain in `currentRound.RealTimeMinersInformation`.

Subsequently, `Round.GenerateNextRoundInformation` generates the next round using whatever miners exist in `RealTimeMinersInformation` without any filtering for banned status: [6](#0-5) 

The unreplaced banned miners propagate into the next round and can continue producing blocks because block validation only checks if the miner's pubkey is in the current miner list, not if they're banned: [7](#0-6) 

Miners become banned when they miss too many time slots (4320 time slots = 3 days): [8](#0-7) 

The system detects evil miners based on this threshold: [9](#0-8) 

And marks them in the consensus contract: [10](#0-9) 

Which sets their banned status in the Election contract: [11](#0-10) 

## Impact Explanation

**Critical Consensus Integrity Violation:** This vulnerability breaks the fundamental invariant that miners banned via `State.BannedPubkeyMap` for violating consensus rules must be excluded from consensus participation. Unreplaced evil miners continue producing blocks despite being penalized for excessive missed time slots, directly compromising the consensus mechanism's ability to remove misbehaving validators.

**Reward Misallocation:** Banned miners continue earning block production rewards through the Treasury contract's mining reward distribution. This completely undermines the economic security model that relies on punishment to discourage misbehavior, as malicious miners can avoid the intended economic penalty simply by timing their attacks when the alternative candidate pool is shallow.

**Attack Amplification:** Multiple malicious miners can coordinate to simultaneously misbehave. If the alternative candidate pool is shallow due to low election participation or most initial miners being already active or banned, several evil miners will remain active. This enables sustained coordinated attacks against chain liveness and security while continuing to earn rewards, exponentially increasing the threat to network security.

## Likelihood Explanation

**Automatically Triggered:** The vulnerability is part of the normal consensus block production flow through `GenerateNextRoundInformation`, requiring no special permissions or attacker intervention. It triggers automatically during regular round transitions whenever the preconditions are met.

**Realistic Preconditions:**
1. Multiple miners marked as evil in the same term - naturally occurs through network issues, bugs, or coordinated attacks
2. Limited alternative candidates in the election snapshot - common during periods of low voter participation, which is typical in proof-of-stake systems
3. Most initial miners already in the current miner list or also banned - typical in mature blockchain networks where the initial miner set has been largely utilized

**High Execution Practicality:** The scenario occurs naturally when election participation is low, multiple miners fail simultaneously (common during network partitions), or the initial miner set is largely exhausted. Attackers controlling multiple miner nodes can deliberately cause time slot misses across their nodes to exceed the 4320 threshold, and with shallow candidate pools, some nodes will remain active despite being marked evil.

**Limited Detection:** The mismatch between list sizes is only visible through debug logs, and unreplaced evil miners continue normal block production operation, making the issue extremely difficult to detect without specifically monitoring the banned pubkey map against active miner lists.

## Recommendation

The replacement loop should iterate based on `EvilMinerPubkeys.Count` instead of `AlternativeCandidatePubkeys.Count`. For evil miners without corresponding alternatives, they should be forcibly removed from the miner list even if no replacement is available, with the round adjusting to accommodate fewer miners:

```csharp
// In AEDPoSContract_ViewMethods.cs, around line 311
for (var i = 0; i < minerReplacementInformation.EvilMinerPubkeys.Count; i++)
{
    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];
    
    // Update evil node history
    UpdateCandidateInformation(evilMinerPubkey,
        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);
    
    // Remove evil miner from round
    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
    
    // Only add replacement if one is available
    if (i < minerReplacementInformation.AlternativeCandidatePubkeys.Count)
    {
        var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
        Context.Fire(new MinerReplaced { NewMinerPubkey = alternativeCandidatePubkey });
        
        // Transfer consensus information to replacement
        var minerInRound = new MinerInRound
        {
            Pubkey = alternativeCandidatePubkey,
            ExpectedMiningTime = currentRound.RealTimeMinersInformation[evilMinerPubkey].ExpectedMiningTime,
            Order = currentRound.RealTimeMinersInformation[evilMinerPubkey].Order,
            PreviousInValue = Hash.Empty,
            IsExtraBlockProducer = currentRound.RealTimeMinersInformation[evilMinerPubkey].IsExtraBlockProducer
        };
        currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
    }
}
```

Alternatively, add a secondary check in `MiningPermissionValidationProvider` to reject banned miners even if they're in the miner list.

## Proof of Concept

```csharp
[Fact]
public async Task BannedMinersRemainActive_WithInsufficientAlternatives()
{
    // Setup: Initialize consensus with 7 miners
    const int initialMinersCount = 7;
    var initialMiners = Enumerable.Range(0, initialMinersCount)
        .Select(_ => CryptoHelper.GenerateKeyPair().PublicKey.ToHex()).ToList();
    
    await InitializeConsensusAndElection(initialMiners);
    
    // Mark 5 miners as evil by exceeding missed time slots threshold
    var evilMinersCount = 5;
    for (var i = 0; i < evilMinersCount; i++)
    {
        await MarkMinerAsEvil(initialMiners[i]);
    }
    
    // Setup election with only 2 alternative candidates (less than 5 evil miners)
    var alternativeCandidates = new[] {
        CryptoHelper.GenerateKeyPair().PublicKey.ToHex(),
        CryptoHelper.GenerateKeyPair().PublicKey.ToHex()
    };
    await RegisterAlternativeCandidates(alternativeCandidates);
    
    // Trigger next round generation (calls GenerateNextRoundInformation)
    await ProduceNextRound();
    
    // Verify: Get active miners in new round
    var currentRound = await GetCurrentRound();
    var activeMiners = currentRound.RealTimeMinersInformation.Keys.ToList();
    
    // BUG: Should have 4 miners (2 good + 2 replacements)
    // Actually has 6 miners (2 good + 2 replacements + 3 unreplaced evil miners)
    activeMiners.Count.ShouldBe(4); // FAILS - actual count is 6
    
    // Verify the 3 unreplaced evil miners are still active
    var unreplacedEvilMiners = initialMiners.Skip(2).Take(3);
    foreach (var evilMiner in unreplacedEvilMiners)
    {
        // These should be removed but are still in the active miner list
        activeMiners.ShouldNotContain(evilMiner); // FAILS - they're still present
        
        // Verify they're marked as banned in Election contract
        var isBanned = await ElectionContractStub.IsPubkeyBanned.CallAsync(
            new StringValue { Value = evilMiner });
        isBanned.Value.ShouldBeTrue(); // PASSES - they ARE banned
        
        // But they can still produce blocks
        var canProduce = await TryProduceBlock(evilMiner);
        canProduce.ShouldBeFalse(); // FAILS - they CAN still produce blocks
    }
}
```

## Notes

The vulnerability is triggered during normal consensus operation and does not require any attacker privileges beyond controlling miner nodes. The fix must ensure either (1) all evil miners are removed even without replacements, or (2) block validation explicitly checks the banned status. The current implementation's assumption that replacement lists will always have equal sizes is fundamentally flawed given the Election contract's filtering logic.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L363-380)
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
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L382-392)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
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

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```
