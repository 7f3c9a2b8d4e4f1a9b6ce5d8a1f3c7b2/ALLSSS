### Title
Term Change Deadlock Due to Threshold Mismatch Between Total and Active Miners

### Summary
The `GetConsensusBehaviourToTerminateCurrentRound()` function can incorrectly return `NextRound` instead of `NextTerm` when the term period has elapsed, due to a threshold calculation flaw in `NeedToChangeTerm()`. The threshold (`MinersCountOfConsent`) is calculated based on total miners in the round, but the consensus count only includes miners who have actually mined blocks. When more than one-third of miners go offline or fail to mine, the 2/3 threshold becomes mathematically unreachable, causing indefinite round advancement without term changes, leading to stale miner lists, missing election snapshots, and delayed reward distributions.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The `NeedToChangeTerm()` method has a threshold calculation flaw: [2](#0-1) 

The threshold `MinersCountOfConsent` is defined as: [3](#0-2) 

This calculates as `(TotalMiners * 2 / 3) + 1` based on `RealTimeMinersInformation.Count` (all miners in the round).

However, `NeedToChangeTerm` only counts miners who satisfy `m.ActualMiningTimes.Any()` - meaning they must have mined at least one block. If more than 1/3 of miners are offline or haven't mined, the active miner count can never reach the threshold.

**Why Protections Fail:**
The conditional logic returns `NextRound` when `!NeedToChangeTerm(...)` is true: [4](#0-3) 

When `NextRound` executes instead of `NextTerm`, critical term transition operations are skipped: [5](#0-4) 

Only `NextTerm` performs essential state updates: [6](#0-5) 

### Impact Explanation

**Consensus State Corruption:**
- **Round number advances** without corresponding term number updates (line 158 vs line 173-174 in ProcessConsensusInformation)
- **Miner list remains stale** - new election results are never applied since `SetMinerList()` only executes in `ProcessNextTerm`: [7](#0-6) 

**Economic Impact:**
- **Mining rewards not distributed** - `DonateMiningReward()` and treasury release only occur in `ProcessNextTerm`: [8](#0-7) 

- **Election snapshots never taken** - critical for vote-based rewards: [9](#0-8) 

**Duration:** The desynchronization persists until evil miners are detected (after `TolerableMissedTimeSlotsCount` = 4,320 slots ≈ 3 days): [10](#0-9) 

Then replacement occurs: [11](#0-10) 

**Affected Parties:** All network participants - miners don't receive rewards, voters don't receive dividends, elected candidates aren't promoted to active miner status.

### Likelihood Explanation

**Natural Occurrence (No Attack Required):**
This vulnerability triggers through normal network conditions when miners experience downtime or connectivity issues. No malicious attacker is needed.

**Feasible Preconditions:**
- Configuration: 7 miners (typical testnet/small network), requiring 5 for consensus (2/3 + 1)
- Scenario: 3+ miners experience extended downtime during term transition period
- This is realistic in networks with geographic distribution or infrastructure variability

**Execution Path:**
1. Term period elapses (configured `period_seconds`, typically 7 days)
2. Block production continues with 4 active miners (3 offline)
3. All 4 active miners cross term boundary in their timestamps
4. `NeedToChangeTerm()` evaluates: `count(4) < MinersCountOfConsent(5)` → returns `false`
5. `GetConsensusBehaviourToTerminateCurrentRound()` returns `NextRound`
6. Rounds advance for days until evil miner detection/replacement completes

**Detection Difficulty:** Low - monitoring tools would show round/term number divergence, but operators might assume this is normal behavior waiting for miner consensus.

**Probability:** Medium-High in smaller networks or during network instability periods. Larger networks (17+ miners) have more redundancy but remain vulnerable if >1/3 experience simultaneous issues.

### Recommendation

**Code-Level Mitigation:**
Modify `MinersCountOfConsent` calculation to be based on active miners or adjust `NeedToChangeTerm` logic:

**Option 1:** Calculate threshold from active miners only:
```csharp
public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
{
    var activeMiners = RealTimeMinersInformation.Values
        .Where(m => m.ActualMiningTimes.Any())
        .ToList();
    
    if (activeMiners.Count == 0) return false;
    
    var activeMinersConsent = activeMiners.Count.Mul(2).Div(3).Add(1);
    
    return activeMiners
        .Select(m => m.ActualMiningTimes.Last())
        .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp, t, currentTermNumber, periodSeconds))
        >= activeMinersConsent;
}
```

**Option 2:** Add time-based fallback in `GetConsensusBehaviourToTerminateCurrentRound`:
```csharp
protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
{
    if (CurrentRound.RoundNumber == 1 || 
        CurrentRound.RealTimeMinersInformation.Keys.Count == 1)
        return AElfConsensusBehaviour.NextRound;
    
    // Force term change if well past term boundary (e.g., 1.5x period)
    var termElapsed = (CurrentBlockTime - _blockchainStartTimestamp).Seconds;
    var expectedTermNumber = termElapsed.Div(_periodSeconds) + 1;
    if (expectedTermNumber > CurrentRound.TermNumber + 1)
        return AElfConsensusBehaviour.NextTerm;
    
    return !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp, 
        CurrentRound.TermNumber, _periodSeconds)
        ? AElfConsensusBehaviour.NextRound
        : AElfConsensusBehaviour.NextTerm;
}
```

**Invariant Checks:**
Add assertion in `ProcessNextRound` to detect prolonged term staleness:
```csharp
var currentTime = Context.CurrentBlockTime;
var termElapsed = (currentTime - blockchainStartTimestamp).Seconds;
var expectedTerm = termElapsed.Div(periodSeconds) + 1;
Assert(expectedTerm <= currentRound.TermNumber + 1, 
    "Term number critically stale - force term change required");
```

**Test Cases:**
Add regression test covering:
1. Configure 7-miner network
2. Advance time past term boundary
3. Have only 4 miners produce blocks
4. Verify term change occurs within reasonable timeframe (not 3+ days)
5. Verify miner list updates, snapshots taken, rewards distributed

### Proof of Concept

**Initial State:**
- 7 miners in Term 1, Round N
- `period_seconds` = 604800 (7 days)
- Time: Day 7 (term boundary crossed)
- Miners: 4 active, 3 offline (no `ActualMiningTimes`)

**Transaction Sequence:**

1. **Day 7**: Active miner produces block, calls `GetConsensusCommand()`
   - Current time crosses term boundary
   - `NeedToChangeTerm()` checks: 
     - Active miners with crossed timestamps: 4
     - `MinersCountOfConsent`: (7 * 2 / 3) + 1 = 5
     - 4 < 5 → returns `false`
   - `GetConsensusBehaviourToTerminateCurrentRound()` returns `NextRound`

2. **Day 7-10**: Multiple rounds execute with `NextRound` behavior
   - Round number increments: N, N+1, N+2, ...
   - Term number stays: 1
   - Miner list unchanged
   - No election snapshots
   - No reward distributions

3. **Day 10**: Evil miner detection threshold reached (3 days × 1440 slots/day)
   - `TryToDetectEvilMiners()` identifies 3 offline miners
   - `GenerateNextRoundInformation()` replaces them

4. **Day 10+**: New miners start producing blocks
   - Eventually all 7 miners have `ActualMiningTimes` crossing boundary
   - `NeedToChangeTerm()` returns `true`
   - `NextTerm` finally executes

**Expected Result:** Term change on Day 7 when time crosses boundary

**Actual Result:** Term change delayed until Day 10+, with 3+ days of state desynchronization

**Success Condition:** Monitor logs showing rounds N through N+X all in Term 1, followed by jump to Term 2 after multi-day delay.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

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

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-342)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

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
