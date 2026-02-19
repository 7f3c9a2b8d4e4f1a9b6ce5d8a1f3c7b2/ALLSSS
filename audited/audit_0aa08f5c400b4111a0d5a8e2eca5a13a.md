### Title
MissedTimeSlots Counter Reset at Term Transitions Allows Indefinite Miner Retention Despite Poor Performance

### Summary
The consensus contract resets each miner's `MissedTimeSlots` counter to zero at every term transition, preventing the evil miner detection mechanism from functioning correctly when term durations are shorter than the time required to accumulate the ejection threshold of 4,320 missed slots. This allows underperforming miners to remain in the miner set indefinitely as long as they maintain sufficient votes, undermining consensus integrity and network liveness.

### Finding Description

The `GenerateNextRoundInformation()` function increments the `MissedTimeSlots` counter for miners who fail to produce blocks [1](#0-0) .

The system defines a maximum threshold of 4,320 missed time slots (representing 3 days at 1 slot per minute) [2](#0-1) .

The `TryToDetectEvilMiners()` method checks if any miner has exceeded this threshold [3](#0-2) , and detected evil miners are marked for removal during round processing [4](#0-3) .

**Root Cause**: At every term transition, the `ProcessNextTerm()` function unconditionally resets all miners' `MissedTimeSlots` counters to zero [5](#0-4) . This reset occurs before the counter can reach the 4,320 threshold if the term duration (configured via `PeriodSeconds`) is shorter than the time needed to accumulate that many missed slots.

**Why Protections Fail**: 
1. Evil miner detection only checks the Round-level `MissedTimeSlots` counter, which resets at term boundaries
2. Miner selection for new terms is based solely on voting power, with no consideration of accumulated missed slots [6](#0-5) 
3. Although missed slot statistics are sent to the Election contract [7](#0-6) , this cumulative data is never used to prevent miner re-selection

### Impact Explanation

**Consensus Integrity Degradation**: Miners who consistently fail to produce blocks can occupy consensus slots indefinitely, reducing the network's block production rate and increasing the risk of consensus delays or failures. With 17 miners typically in the set, even a few inactive miners significantly impact network performance.

**Network Liveness Risk**: If multiple miners exploit this mechanism, the effective number of active block producers decreases, potentially preventing the network from achieving the required two-thirds consensus threshold for critical operations.

**Opportunity Cost**: Active, high-performing candidates are denied miner positions while underperforming miners retain their slots based solely on voting power, misaligning the consensus set with actual network contribution.

**Severity**: Medium - While miners lose block rewards for non-production [8](#0-7) , they can maintain consensus participation rights indefinitely, affecting protocol security.

### Likelihood Explanation

**Feasible Preconditions**: This vulnerability manifests when the term duration is configured shorter than approximately 3-4 days. For example, with 17 miners and 4-second mining intervals, accumulating 4,320 missed slots requires approximately 293,760 seconds (≈3.4 days). Configuration files show terms can be set to values like 2 seconds or 120 seconds in various deployments [9](#0-8) .

**Execution Practicality**: A miner simply stops producing blocks during their time slots. This requires no special transactions or exploit code - passive non-participation is sufficient.

**Economic Rationality**: While the miner loses block production rewards, they may benefit from:
- Maintaining consensus voting rights for governance decisions
- Avoiding infrastructure costs while keeping their position
- Waiting for more favorable market conditions to resume mining

**Detection Difficulty**: The behavior appears as normal missed blocks, which can occur legitimately due to network issues, making it difficult to distinguish intentional from accidental non-production.

### Recommendation

**Option 1 - Accumulate Across Terms**: Modify `ProcessNextTerm()` to preserve `MissedTimeSlots` counters across term boundaries instead of resetting them:

```csharp
// In ProcessNextTerm, remove or modify lines 179-183
// Instead: only reset for newly added miners, not existing ones
foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
{
    if (previousRound.RealTimeMinersInformation.ContainsKey(minerInRound.Pubkey))
    {
        // Preserve MissedTimeSlots from previous term
        minerInRound.MissedTimeSlots = previousRound.RealTimeMinersInformation[minerInRound.Pubkey].MissedTimeSlots;
    }
    minerInRound.ProducedBlocks = 0;
}
```

**Option 2 - Enforce Minimum Term Duration**: Add a validation check ensuring `PeriodSeconds` is configured sufficiently long:

```csharp
// In consensus initialization
Assert(periodSeconds >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount * GetMiningInterval() / 1000,
    "Term duration must be long enough to allow evil miner detection");
```

**Option 3 - Use Election Contract Statistics**: Modify `GetVictories()` to exclude candidates whose cumulative `MissedTimeSlots` in the Election contract exceeds a threshold [10](#0-9) .

**Test Cases**: Add tests verifying that miners missing more than 4,320 slots across multiple terms are eventually ejected, and that term transitions don't reset the ejection mechanism.

### Proof of Concept

**Initial State**:
- Network configured with `PeriodSeconds = 86400` (1 day)
- 17 miners in consensus set
- Mining interval = 4 seconds
- Miner X has sufficient votes to be re-elected

**Exploitation Steps**:

1. **Term N Begins**: Miner X is selected for the miner set, `MissedTimeSlots = 0`

2. **During Term N**: Miner X never produces blocks for their assigned slots
   - Each round, `GenerateNextRoundInformation()` increments their `MissedTimeSlots` [11](#0-10) 
   - After 1 day: MissedTimeSlots ≈ 1,273 (far below 4,320 threshold)

3. **Term Transition to Term N+1**:
   - `ProcessNextTerm()` executes [12](#0-11) 
   - Line 181: `minerInRound.MissedTimeSlots = 0` resets the counter
   - Miner X has sufficient votes, so `GetVictories()` re-selects them [13](#0-12) 

4. **Repeat**: Steps 2-3 continue indefinitely

**Expected Result**: Miner X should be ejected after accumulating 4,320 total missed slots

**Actual Result**: Miner X's counter resets every term, never reaching the ejection threshold despite never producing blocks

**Success Condition**: Miner X remains in the consensus set for 10+ consecutive terms while producing zero blocks, demonstrating indefinite retention despite complete non-participation.

### Notes

This vulnerability is **configuration-dependent** - it only manifests when term duration is shorter than the time required to accumulate the ejection threshold. However, the code provides no validation or warning about this constraint, making it a design flaw rather than merely a misconfiguration issue. The constant's comment explicitly references "3 days" [2](#0-1) , suggesting the design intent, but the implementation doesn't enforce compatibility between term duration and ejection threshold.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L46-56)
```csharp
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

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

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L86-95)
```csharp
    private List<string> GetValidCandidates()
    {
        if (State.Candidates.Value == null) return new List<string>();

        return State.Candidates.Value.Value
            .Where(c => State.CandidateVotes[c.ToHex()] != null &&
                        State.CandidateVotes[c.ToHex()].ObtainedActiveVotedVotesAmount > 0)
            .Select(p => p.ToHex())
            .ToList();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L115-118)
```csharp
        candidateInformation.ProducedBlocks = candidateInformation.ProducedBlocks.Add(input.RecentlyProducedBlocks);
        candidateInformation.MissedTimeSlots =
            candidateInformation.MissedTimeSlots.Add(input.RecentlyMissedTimeSlots);
        State.CandidateInformationMap[input.Pubkey] = candidateInformation;
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L131-142)
```csharp
            SchemeId = State.TreasuryHash.Value,
            Period = input.PeriodNumber,
            AmountsMap = { State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L) }
        });
        RequireElectionContractStateSet();
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });

        var currentMinerList = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(p => p.ToHex()).ToList();
```

**File:** src/AElf.ContractTestKit.AEDPoSExtension/AEDPoSExtensionConstants.cs (L13-13)
```csharp
    public const int PeriodSeconds = 120;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-280)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
```
