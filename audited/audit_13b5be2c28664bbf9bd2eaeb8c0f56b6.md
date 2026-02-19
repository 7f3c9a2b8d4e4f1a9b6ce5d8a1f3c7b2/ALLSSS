### Title
MissedTimeSlots Counter Reset at Term Boundaries Allows Malicious Miners to Evade Evil Node Detection

### Summary
The `MissedTimeSlots` counter is unconditionally reset to 0 during term transitions without performing evil miner detection, while detection only occurs during normal round transitions. This allows malicious miners to strategically miss time slots below the threshold (4319 out of 4320) and have their counters reset every term change (typically 7 days), enabling them to evade punishment indefinitely despite repeated mining failures.

### Finding Description

The evil miner detection mechanism in `TryToDetectEvilMiners()` checks if a miner's `MissedTimeSlots` exceeds the tolerance threshold of 4320 slots (representing 3 days of missed mining at 1 slot per minute). [1](#0-0) [2](#0-1) 

However, this detection only occurs during normal round transitions in `ProcessNextRound`, where the system checks for evil miners and marks them accordingly in the Election contract. [3](#0-2) 

The critical flaw exists in `ProcessNextTerm`, which handles term transitions. This method first counts any final missed time slots, then **unconditionally resets** all miners' `MissedTimeSlots` and `ProducedBlocks` counters to 0 for the next term, without performing evil miner detection. [4](#0-3) 

The `MissedTimeSlots` counter is incremented in two places:
1. During normal round generation when miners fail to produce blocks [5](#0-4) 
2. During term transitions via `CountMissedTimeSlots()` [6](#0-5) 

When evil miners are successfully detected (only in `ProcessNextRound`), they are permanently banned and removed from the candidate list. [7](#0-6) 

### Impact Explanation

This vulnerability enables malicious miners to:
- **Evade accountability**: Miss up to 4319 time slots per term (approximately 60% of their mining obligations over a 7-day term period) without being marked as evil nodes
- **Compromise consensus reliability**: Consistently reduce block production capacity by allowing unreliable miners to remain in the miner set indefinitely
- **Violate protocol invariants**: The system's intended guarantee that miners exceeding the missed slot threshold will be removed is completely bypassed

The accumulated statistics are reported to the Election contract, but only as informational data without triggering the punishment mechanism. [8](#0-7) 

This directly undermines the consensus mechanism's integrity by allowing persistently poor-performing or malicious miners to avoid removal, reducing network security and block production reliability.

### Likelihood Explanation

**Attack Complexity**: Low - The attacker only needs to control their own mining node behavior.

**Preconditions**: 
- Attacker must be an active miner (realistic for consensus attacks)
- Term period is typically 7 days (604800 seconds) per the system configuration
- No special permissions or external conditions required

**Execution Practicality**: 
- The miner simply needs to selectively miss their time slots, staying under the 4320 threshold
- Term transitions occur automatically and regularly (weekly)
- The counter reset is deterministic and unavoidable at each term boundary
- No detection mechanisms exist to catch this pattern across term boundaries

**Economic Rationality**: 
- Minimal cost - the attacker pays no penalties while maintaining miner status
- Can be combined with other attacks or simply reduce network reliability
- Reward structure remains intact despite reduced participation

**Detection Difficulty**: The current implementation provides no cross-term tracking of cumulative missed slots, making this pattern invisible to the protocol's monitoring mechanisms.

### Recommendation

**Primary Fix**: Perform evil miner detection in `ProcessNextTerm` before resetting counters:

In `AEDPoSContract_ProcessConsensusInformation.cs`, add evil miner detection before the reset in `ProcessNextTerm`:

```csharp
// After line 168 (CountMissedTimeSlots)
if (State.IsMainChain.Value && 
    currentRound.TryToDetectEvilMiners(out var evilMiners))
{
    Context.LogDebug(() => "Evil miners detected during term transition.");
    foreach (var evilMiner in evilMiners)
    {
        Context.LogDebug(() => 
            $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
        State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
        {
            Pubkey = evilMiner,
            IsEvilNode = true
        });
    }
}
// Then perform the reset (lines 178-183)
```

**Secondary Enhancement**: Consider implementing cumulative tracking across terms in the Election contract to detect patterns of borderline behavior.

**Test Cases**: Add regression tests covering:
1. Miner with 4320+ missed slots at term boundary → should be marked evil before counter reset
2. Miner with 4319 slots in term N, 4319 in term N+1 → cumulative tracking should detect pattern
3. Verify evil miners are excluded from next term's miner list

### Proof of Concept

**Initial State**:
- Network running with standard configuration
- TolerableMissedTimeSlotsCount = 4320
- Term period = 604800 seconds (7 days)
- Malicious miner is part of the active miner set

**Attack Sequence**:

1. **Term N (Days 1-7)**:
   - Malicious miner deliberately misses 4319 time slots
   - Produces minimal blocks to avoid immediate suspicion
   - MissedTimeSlots counter reaches 4319 (below threshold)
   
2. **Term Transition (Day 7 end)**:
   - `NextTerm` is called triggering `ProcessNextTerm`
   - `CountMissedTimeSlots()` may increment to 4320 if miner missed final slot
   - System calls `UpdateCurrentMinerInformationToElectionContract()` - reports statistics only
   - **Critical**: Lines 178-183 reset `MissedTimeSlots = 0` without evil detection
   - Miner enters Term N+1 with clean counter

3. **Term N+1 (Days 8-14)**:
   - Malicious miner repeats pattern
   - Misses 4319 more time slots
   - Counter reset again at next term boundary

**Expected Result**: Miner should be marked as evil node after exceeding threshold

**Actual Result**: Miner's counter is reset to 0 at each term boundary, allowing indefinite evasion of detection despite cumulative missed slots far exceeding the tolerance threshold

**Success Condition**: Malicious miner remains in active miner set indefinitely while maintaining 60%+ absence rate over extended periods, demonstrating complete bypass of the evil miner detection mechanism.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L168-183)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L52-55)
```csharp
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L37-51)
```csharp
    private void UpdateCurrentMinerInformationToElectionContract(Round previousRound)
    {
        State.ElectionContract.UpdateMultipleCandidateInformation.Send(new UpdateMultipleCandidateInformationInput
        {
            Value =
            {
                previousRound.RealTimeMinersInformation.Select(i => new UpdateCandidateInformationInput
                {
                    Pubkey = i.Key,
                    RecentlyProducedBlocks = i.Value.ProducedBlocks,
                    RecentlyMissedTimeSlots = i.Value.MissedTimeSlots
                })
            }
        });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L87-96)
```csharp
    private void CountMissedTimeSlots()
    {
        if (!TryToGetCurrentRoundInformation(out var currentRound)) return;

        foreach (var minerInRound in currentRound.RealTimeMinersInformation)
            if (minerInRound.Value.OutValue == null)
                minerInRound.Value.MissedTimeSlots = minerInRound.Value.MissedTimeSlots.Add(1);

        TryToUpdateRoundInformation(currentRound);
    }
```

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
