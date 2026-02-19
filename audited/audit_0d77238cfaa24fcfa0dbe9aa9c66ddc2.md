### Title
Insufficient Alternative Candidates Allows Banned Miners to Remain in Consensus

### Summary
The miner replacement mechanism in `GenerateNextRoundInformation` assumes a 1-to-1 correspondence between `EvilMinerPubkeys` and `AlternativeCandidatePubkeys` lists when replacing banned miners. However, `GetMinerReplacementInformation` can return fewer alternatives than evil miners when the candidate pool is exhausted. This causes only partial replacement, allowing unreplaced banned miners to continue participating in consensus, producing blocks, and earning rewards.

### Finding Description

The vulnerability exists in the consensus contract's miner replacement logic. When generating the next round, the system calls `GetMinerReplacementInformation` to identify banned miners and find replacements. [1](#0-0) 

The replacement loop iterates based on `AlternativeCandidatePubkeys.Count` and accesses both lists by index without verifying equal lengths: [2](#0-1) 

In `GetMinerReplacementInformation`, the logic ensures `alternativeCandidates.Count <= evilMinersPubKeys.Count` by design. First, it takes candidates from the election snapshot (limited by availability): [3](#0-2) 

Then attempts to fill the gap with initial miners, but these are filtered to exclude banned and currently mining nodes: [4](#0-3) 

The returned structure contains mismatched list sizes: [5](#0-4) 

**Root Cause:** When `AlternativeCandidatePubkeys.Count < EvilMinerPubkeys.Count`, only the first N evil miners (where N equals the alternative count) are removed from `currentRound.RealTimeMinersInformation`. The remaining evil miners at indices N and beyond are never accessed by the loop and remain in the data structure.

Subsequently, `Round.GenerateNextRoundInformation` generates the next round using whatever miners exist in `RealTimeMinersInformation`, with no filtering for banned miners: [6](#0-5) 

The unreplaced banned miners thus propagate into the next consensus round.

### Impact Explanation

**Consensus Integrity Compromise:** Miners marked as evil (banned via `State.BannedPubkeyMap`) for violating consensus rules (missing time slots beyond the tolerance threshold) can continue participating in block production. This directly violates the fundamental invariant that banned miners must be excluded from consensus.

**Reward Misallocation:** Unreplaced evil miners continue earning block production rewards and mining dividends despite being penalized. This undermines the economic security model that relies on punishment to discourage misbehavior.

**Attack Amplification:** Multiple malicious miners can coordinate to misbehave simultaneously. If the alternative candidate pool is shallow (few voted candidates, most initial miners already active or banned), several evil miners will remain active. This enables persistent malicious activity.

**Severity: Critical** - This breaks core consensus assumptions, allows circumvention of the punishment mechanism, and enables coordinated attacks against chain liveness and security.

### Likelihood Explanation

**Reachable Entry Point:** The vulnerability is triggered automatically during normal round generation via `GenerateNextRoundInformation`, which is part of the consensus block production flow. No special permissions required.

**Feasible Preconditions:**
1. Multiple miners marked as evil in the same term (detectable through missed time slots)
2. Limited alternative candidates in the election snapshot (requires low voter participation or few announced candidates)
3. Most initial miners already in the current miner list or also banned (common in mature networks)

**Execution Practicality:** The scenario naturally occurs when:
- Election participation is low (few candidates with votes)
- Multiple miners fail simultaneously (network issues, coordinated attack, or bugs)
- The initial miner set is largely in use

**Economic Rationality:** Attackers controlling multiple miner nodes can deliberately cause time slot misses across their nodes simultaneously. With shallow candidate pools, some of their nodes will remain active despite being marked evil, allowing continued block production and rewards.

**Detection Constraints:** The mismatch is only visible through debug logs. The unreplaced evil miners continue normal operation, making detection difficult without monitoring the banned pubkey map against active miner lists.

**Likelihood: High** - The conditions are realistic in production environments, especially during low election participation periods or coordinated failures.

### Recommendation

**Immediate Fix:** Add validation and handling for count mismatches in `GenerateNextRoundInformation`:

```csharp
if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
{
    // Assert lists match or handle mismatches
    var replacementCount = Math.Min(
        minerReplacementInformation.AlternativeCandidatePubkeys.Count,
        minerReplacementInformation.EvilMinerPubkeys.Count
    );
    
    for (var i = 0; i < replacementCount; i++)
    {
        // Existing replacement logic
    }
    
    // CRITICAL: Remove any unreplaced evil miners
    for (var i = replacementCount; i < minerReplacementInformation.EvilMinerPubkeys.Count; i++)
    {
        var unreplacedEvilMiner = minerReplacementInformation.EvilMinerPubkeys[i];
        currentRound.RealTimeMinersInformation.Remove(unreplacedEvilMiner);
        Context.LogDebug(() => $"Removed unreplaced evil miner: {unreplacedEvilMiner}");
    }
    
    isMinerListChanged = true;
}
```

**Invariant Checks:**
1. Assert `currentRound.RealTimeMinersInformation` contains no keys present in `State.BannedPubkeyMap` after replacement
2. Validate round miner count matches expected count after evil miner removal
3. Add explicit count mismatch logging when alternatives are insufficient

**Test Cases:**
1. Test with 3 evil miners but only 1 alternative candidate available
2. Test with all initial miners already in miner list or banned
3. Test with empty election snapshot and exhausted initial miner pool
4. Verify unreplaced evil miners are excluded from next round

### Proof of Concept

**Initial State:**
- Current round has 17 miners: [M1, M2, ..., M17]
- During the round, miners M1, M2, M3 miss time slots beyond tolerance
- Consensus contract marks M1, M2, M3 as evil (`State.BannedPubkeyMap[M1/M2/M3] = true`)
- Election snapshot has only 1 voted candidate (C1) not currently mining
- Initial miners: 5 total, but 4 are already in current miner list, 1 is banned
- Available alternatives: C1 only (1 alternative)

**Execution Steps:**

1. Next block production triggers `GenerateNextRoundInformation`
2. Calls `GetMinerReplacementInformation` with current miner list
3. Returns:
   - `EvilMinerPubkeys = [M1, M2, M3]` (3 evil miners)
   - `AlternativeCandidatePubkeys = [C1]` (1 alternative)
4. Replacement loop runs once (i=0):
   - Removes M1 from `currentRound.RealTimeMinersInformation`
   - Adds C1 to `currentRound.RealTimeMinersInformation`
5. Loop exits (count = 1)
6. M2 and M3 remain in `currentRound.RealTimeMinersInformation`
7. `Round.GenerateNextRoundInformation` creates next round with M2 and M3 still present
8. Next round miners: [C1, M2, M3, M4, ..., M17] (M2, M3 are banned but active)

**Expected Result:** All evil miners (M1, M2, M3) removed from consensus

**Actual Result:** Only M1 replaced; M2 and M3 continue producing blocks despite being banned

**Success Condition:** Check next round's `RealTimeMinersInformation.Keys` contains M2 and M3, confirming banned miners remain active.

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L368-380)
```csharp
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

**File:** protobuf/election_contract.proto (L497-502)
```text
message MinerReplacementInformation {
    // The alternative candidate public keys.
    repeated string alternative_candidate_pubkeys = 1;
    // The evil miner public keys.
    repeated string evil_miner_pubkeys = 2;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-37)
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
```
