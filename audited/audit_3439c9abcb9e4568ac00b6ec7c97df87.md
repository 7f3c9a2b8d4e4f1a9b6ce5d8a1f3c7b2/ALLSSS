# Audit Report

## Title
Evil Miner Detection Bypassed During Term Transitions Allowing Persistent Consensus Violations

## Summary
The `ProcessNextTerm` method in the AEDPoS consensus contract fails to invoke evil miner detection before resetting missed time slot counters, creating a systematic bypass that allows malicious miners to avoid penalties indefinitely by timing their absences around predictable 7-day term boundaries.

## Finding Description

The AEDPoS consensus mechanism tracks miner reliability through `MissedTimeSlots` counters and is designed to detect and remove miners who exceed 4,320 missed time slots (3 days). However, this critical security check is only performed during normal round transitions, not during term transitions.

**The Vulnerability:**

During normal round transitions, `ProcessNextRound` correctly detects evil miners by calling `TryToDetectEvilMiners` [1](#0-0) , which identifies miners whose `MissedTimeSlots >= TolerableMissedTimeSlotsCount` [2](#0-1)  and marks them via the Election Contract [3](#0-2) .

However, during term transitions, `ProcessNextTerm` executes the following sequence without any evil miner detection [4](#0-3) :

1. Line 168: Calls `CountMissedTimeSlots()` to increment counters for the current round [5](#0-4) 
2. Lines 179-183: Immediately resets `MissedTimeSlots = 0` for all miners in the next term
3. No evil miner detection occurs between these operations

The tolerable threshold is configured as 4,320 slots [6](#0-5) , and codebase analysis confirms `TryToDetectEvilMiners` is called only once in the entire system - within `ProcessNextRound`, never in `ProcessNextTerm`.

**Why Existing Safeguards Fail:**

The `UpdateCurrentMinerInformationToElectionContract` method sends accumulated statistics to the Election Contract [7](#0-6) , but crucially does NOT include the `IsEvilNode` flag that triggers removal. Without this flag, the Election Contract cannot identify or penalize these miners despite having their statistics.

## Impact Explanation

This vulnerability fundamentally undermines the consensus mechanism's ability to maintain validator reliability:

**Direct Consensus Impact:**
- Miners can strategically miss up to 4,319 time slots within each term (just below the 4,320 threshold)
- Even miners exceeding the threshold during term transitions escape detection due to immediate counter resets
- This allows unreliable or malicious miners to remain active indefinitely while contributing minimal block production

**Affected Stakeholders:**
- **Network integrity:** Reduced block production reliability increases consensus delays and potential finality issues
- **Token holders:** Degraded network security as unreliable validators persist without consequences
- **Honest miners:** Unfair operational burden as non-performing miners avoid accountability

**Severity Assessment:**
This qualifies as HIGH severity because it:
1. Completely bypasses a core security mechanism designed to maintain consensus quality
2. Enables persistent protocol violations without detection or penalty
3. Affects fundamental blockchain operation rather than isolated features
4. Can be exploited deterministically and repeatedly

## Likelihood Explanation

The vulnerability has HIGH exploitation likelihood due to:

**Attacker Profile:**
- Any active miner in the consensus set can exploit this (no special privileges required)
- Only requires monitoring publicly observable blockchain state for term boundaries
- Rational actors have economic incentive to minimize effort while maintaining validator status

**Attack Simplicity:**
- Term transitions occur predictably every `PeriodSeconds` (default 604,800 seconds = 7 days)
- Exploitation requires only timing absences to span term boundaries
- No complex technical setup or coordination needed

**Exploitation Frequency:**
- Repeatable every term cycle (52 times per year with default configuration)
- A miner could systematically miss ~15% of assigned time slots (4,319 out of ~30,240 weekly slots) without ever being flagged
- Pattern persists indefinitely as counters reset each term

**Detection Difficulty:**
- Per-term statistics appear normal since counters reset
- Historical analysis would require cross-term correlation to identify abuse patterns
- No automatic on-chain detection mechanism exists

## Recommendation

Add evil miner detection to `ProcessNextTerm` before resetting counters:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    RecordMinedMinerListOfCurrentRound();
    
    // Count missed time slot of current round.
    CountMissedTimeSlots();
    
    // ADD: Detect and mark evil miners before resetting counters
    if (State.IsMainChain.Value && 
        TryToGetCurrentRoundInformation(out var currentRound) &&
        currentRound.TryToDetectEvilMiners(out var evilMiners))
    {
        foreach (var evilMiner in evilMiners)
        {
            Context.LogDebug(() => $"Evil miner {evilMiner} detected during term transition.");
            State.ElectionContract.UpdateCandidateInformation.Send(
                new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
        }
    }
    
    // Continue with existing logic...
    Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");
    // ... rest of method
}
```

This ensures evil miners are detected and marked before their counters are reset during term transitions, closing the bypass window.

## Proof of Concept

The vulnerability can be demonstrated by examining the code flow:

1. **Setup:** A miner accumulates 4,319 missed time slots during rounds within Term N
2. **Trigger:** Term boundary is reached at the 7-day mark
3. **Execution:** `ProcessNextTerm` is called
4. **Vulnerable Sequence:**
   - `CountMissedTimeSlots()` potentially increments counter to 4,320+
   - Lines 179-183 immediately reset `MissedTimeSlots = 0`
   - No call to `TryToDetectEvilMiners` occurs
   - Miner enters Term N+1 with clean slate
5. **Result:** Miner avoids evil node detection and ban despite exceeding threshold

The code evidence is conclusive: grep search confirms `TryToDetectEvilMiners` appears only in `ProcessNextRound`, not in `ProcessNextTerm`, and the counter reset happens without any intervening threshold check during term transitions.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
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

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```
