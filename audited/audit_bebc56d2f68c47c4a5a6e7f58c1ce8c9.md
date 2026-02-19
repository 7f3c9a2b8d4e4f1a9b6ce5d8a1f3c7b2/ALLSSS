### Title
Stale Miner Performance Metrics in Election Contract Due to Bypassable NextTerm Transition

### Summary
The bulk synchronization of miner performance metrics (ProducedBlocks and MissedTimeSlots) to the Election Contract occurs exclusively during NextTerm transitions via `UpdateCurrentMinerInformationToElectionContract`. If term changes are delayed or bypassed by preventing `NeedToChangeTerm` from triggering (requiring <2/3 miners to meet term change threshold), these metrics remain unsynchronized, causing the Election Contract to maintain stale candidate performance data that affects election rankings and voter decisions.

### Finding Description

The vulnerability exists in the consensus behavior selection logic and metric synchronization flow:

**Root Cause Location:**
In `GetConsensusBehaviourToTerminateCurrentRound()`, the decision between NextTerm and NextRound determines whether metrics are synchronized: [1](#0-0) 

The method returns NextRound (skipping metric sync) when: (1) it's the first round, (2) `NeedToChangeTerm` returns false, or (3) there's only one miner.

**Metric Synchronization Path:**
The bulk update of all miners' performance metrics to the Election Contract happens ONLY in `ProcessNextTerm`: [2](#0-1) 

This calls `UpdateCurrentMinerInformationToElectionContract` which sends all miners' ProducedBlocks and MissedTimeSlots: [3](#0-2) 

**Term Change Condition:**
`NeedToChangeTerm` requires at least 2/3 of miners to have ActualMiningTimes indicating the term period has passed: [4](#0-3) 

**Why Protections Fail:**
In `ProcessNextRound`, only evil miners (with excessive MissedTimeSlots) are individually marked, but no bulk metric synchronization occurs: [5](#0-4) 

The Election Contract accumulates these metrics cumulatively: [6](#0-5) 

If NextTerm transitions are delayed, the Election Contract never receives updated metrics, causing divergence between consensus state and election state.

### Impact Explanation

**Governance and Election Integrity Impact:**
- Election rankings become inaccurate as they're based on outdated ProducedBlocks and MissedTimeSlots data
- Voters make delegation decisions using stale performance metrics, potentially choosing underperforming candidates
- Candidate performance evaluations from the Election Contract perspective do not reflect recent behavior
- The time window for stale data can extend indefinitely if term changes are continuously delayed

**Affected Parties:**
- Token holders/voters relying on Election Contract data for informed voting decisions
- Well-performing candidates whose recent improvements aren't reflected in rankings
- The election system's credibility and fairness

**Severity Justification (Medium):**
While this doesn't directly lead to fund theft, it compromises election integrity—a critical governance mechanism. The consensus contract itself maintains accurate metrics, but the Election Contract's view diverges, affecting a fundamental protocol function.

### Likelihood Explanation

**Attack Preconditions:**
To delay term changes and prevent metric synchronization, attackers need to ensure less than 2/3 of miners have ActualMiningTimes indicating term change threshold is met. This requires:
- Collusion of more than 1/3 of the miner set (Byzantine threshold)
- Coordinated avoidance of block production near term boundaries
- Sustained coordination across multiple rounds

**Execution Practicality:**
The attack is executable within AElf's consensus model. Miners can selectively choose when to produce blocks, and the 2/3 threshold in `NeedToChangeTerm` creates an exploitable gap. The term period is typically 7 days (604800 seconds): [7](#0-6) 

**Economic Rationality:**
Miners lose block rewards by not producing blocks, which creates economic friction against the attack. However, if incumbent miners benefit from stale election data (e.g., preventing new competitors from showing strong performance), they might accept short-term revenue loss for longer-term incumbency protection.

**Detection Constraints:**
The attack would be detectable through monitoring term change frequency, but automated recovery mechanisms are absent. Metrics in ProcessNextTerm are reset after synchronization: [8](#0-7) 

**Likelihood Assessment: MEDIUM**
Requires Byzantine-level collusion (>1/3 miners) but is technically feasible and might be economically rational for incumbent protection scenarios.

### Recommendation

**Code-Level Mitigation:**

1. **Add metric synchronization to NextRound:** Modify `ProcessNextRound` to periodically sync metrics even when term hasn't changed, ensuring Election Contract data freshness:
```
// After line 158 in ProcessNextRound, add:
if (currentRound.RoundNumber % SYNC_INTERVAL == 0) {
    UpdateCurrentMinerInformationToElectionContract(currentRound);
}
```

2. **Add term change deadline enforcement:** Implement a maximum rounds-per-term limit that forces NextTerm after a threshold:
```
// In GetConsensusBehaviourToTerminateCurrentRound, add:
if (CurrentRound.RoundNumber - GetFirstRoundOfCurrentTerm() > MAX_ROUNDS_PER_TERM) {
    return AElfConsensusBehaviour.NextTerm; // Force term change
}
```

3. **Add monitoring event:** Emit an event when NextRound is chosen over NextTerm to enable governance monitoring:
```
Context.Fire(new TermChangeDelayed {
    RoundNumber = CurrentRound.RoundNumber,
    TermNumber = CurrentRound.TermNumber,
    MinersNotReady = /* count of miners not meeting threshold */
});
```

**Invariant Checks:**
- Assert that metric staleness doesn't exceed MAX_ACCEPTABLE_STALENESS_ROUNDS
- Verify Election Contract metrics are updated at least once per N rounds
- Monitor the ratio of NextRound vs NextTerm consensus behaviors

**Test Cases:**
- Test scenario where exactly 1/3 miners coordinate to prevent term changes
- Verify metric synchronization occurs even when term change is delayed
- Test forced term change after maximum rounds threshold
- Validate Election Contract data freshness under adversarial conditions

### Proof of Concept

**Initial State:**
- Current term number: T
- Current round number: R  
- 17 miners in consensus (typical AElf configuration)
- Miner performance metrics accumulated over previous rounds in Round state

**Attack Sequence:**

1. **Setup Phase:** At least 6 miners (>1/3 of 17) collude to delay term change

2. **Round R (near term boundary):**
   - 11 miners produce blocks normally with ActualMiningTimes indicating term should change
   - 6 colluding miners deliberately skip their time slots or delay block production
   - Result: Only 11/17 (65%) < 2/3 threshold met

3. **Consensus Behavior Selection:**
   - `NeedToChangeTerm` returns false (line 216-224 of Round.cs)
   - `GetConsensusBehaviourToTerminateCurrentRound` returns NextRound instead of NextTerm (line 34)
   - `ProcessConsensusInformation` routes to `ProcessNextRound` (line 39)

4. **Metric Synchronization Skipped:**
   - `UpdateCurrentMinerInformationToElectionContract` is NOT called
   - Election Contract's CandidateInformation retains old ProducedBlocks/MissedTimeSlots values
   - Consensus contract's Round state continues accumulating accurate metrics

5. **Rounds R+1 to R+N:**
   - Attack repeats: colluding miners maintain <2/3 threshold
   - Multiple rounds pass without any NextTerm transition
   - Metric divergence grows between consensus and election states

**Expected vs Actual Result:**
- **Expected:** Election Contract receives updated metrics every term (every 7 days)
- **Actual:** With >1/3 miner collusion, NextTerm can be indefinitely delayed, Election Contract metrics remain frozen at last NextTerm value

**Success Condition:**
Query Election Contract's `CandidateInformationMap[miner_pubkey].ProducedBlocks` and compare to consensus contract's current round metrics—observe significant divergence indicating stale synchronization. Election rankings based on stale data do not reflect recent miner performance, demonstrating the attack's impact on election integrity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L179-183)
```csharp
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L201-201)
```csharp
        UpdateCurrentMinerInformationToElectionContract(previousRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L115-118)
```csharp
        candidateInformation.ProducedBlocks = candidateInformation.ProducedBlocks.Add(input.RecentlyProducedBlocks);
        candidateInformation.MissedTimeSlots =
            candidateInformation.MissedTimeSlots.Add(input.RecentlyMissedTimeSlots);
        State.CandidateInformationMap[input.Pubkey] = candidateInformation;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```
