# Audit Report

## Title
Miner Collusion Can Delay Term Changes and Prevent Election Snapshot Creation

## Summary
Colluding miners controlling more than 1/3 of the mining power can deliberately prevent term transitions by forcing `NextRound` instead of `NextTerm`, which blocks the execution of `ElectionContract.TakeSnapshot`. This causes election vote data to remain stale, prevents reward distribution for affected terms, and results in loss of historical election data. The attack can persist for up to 3 days before evil miner detection triggers replacement.

## Finding Description

The vulnerability exists in the consensus behavior determination logic. The `GetConsensusBehaviourToTerminateCurrentRound()` method in `MainChainConsensusBehaviourProvider` returns `NextTerm` only when `NeedToChangeTerm()` returns true. [1](#0-0) 

The `NeedToChangeTerm()` function requires at least `MinersCountOfConsent` (calculated as ⌊count × 2/3⌋ + 1) miners to have their latest `ActualMiningTime` passing the term threshold check. [2](#0-1) [3](#0-2) 

**Root Cause:**

Miners only get their `ActualMiningTimes` updated when they actively produce blocks (UpdateValue or TinyBlock). [4](#0-3) [5](#0-4) 

**Attack Execution:**

1. More than 1/3 of miners coordinate to stop producing blocks just before the term threshold time
2. Their last `ActualMiningTime` remains from before the threshold
3. Less than 2/3 of miners have `ActualMiningTime` values indicating term change should occur
4. `NeedToChangeTerm()` returns false, causing `NextRound` to be returned instead of `NextTerm`
5. `ProcessNextRound()` is executed instead of `ProcessNextTerm()` [6](#0-5) 

6. Critical operations in `ProcessNextTerm()` are skipped, including `TakeSnapshot` [7](#0-6) 

**Why Existing Protections Fail:**

Evil miner detection operates with a tolerance threshold of 4,320 missed time slots (3 days). [8](#0-7) 

Evil miners are detected during `ProcessNextRound`, but detection doesn't immediately force a term change - the system still relies on `NeedToChangeTerm()` returning true. [9](#0-8) 

After detection, evil miners are replaced via `GenerateNextRoundInformation()`, but replacement takes additional rounds and new miners must produce blocks before the 2/3 threshold can be met. [10](#0-9) 

## Impact Explanation

When `ProcessNextTerm()` is not executed, critical protocol operations are skipped:

**1. Election Snapshots Not Created:**
The `TakeSnapshot` call to the Election Contract is only made in `ProcessNextTerm()`, not in `ProcessNextRound()`. [11](#0-10) 

**2. Historical Election Data Lost:**
`SavePreviousTermInformation()` creates term snapshots with election results (vote counts per candidate) and mined blocks. [12](#0-11) 

**3. Vote Weight Data Remains Stale:**
Vote Contract snapshots are not taken during the affected period. [13](#0-12) 

**4. Candidate Information Updates Skipped:**
Candidate term tracking and continual appointment counts are not updated. [14](#0-13) 

**5. Treasury Profit Release Prevented:**
Treasury contract release calls do not occur for affected terms. [15](#0-14) 

**6. Profit Distribution Skipped:**
Subsidy and welfare profit distributions are not executed. [16](#0-15) 

**Affected Parties:**
- Token holders who voted receive no rewards during the attack period
- Candidates lose historical voting records and accurate term tracking
- The protocol loses term-based reward distribution accuracy and historical election data integrity

## Likelihood Explanation

**Attacker Capabilities Required:**
- Control or coordination of more than 1/3 of the active miner set (with typical 17 miners, at least 6 must collude)
- Ability to coordinate simultaneous cessation of block production at the term threshold
- Willingness to sacrifice block production rewards during the attack period

**Attack Complexity:**
- Medium - requires precise timing to stop producing blocks just before the term threshold
- Requires sustained coordination for up to 3 days
- Miners accumulate missed time slots leading to evil miner status and eventual replacement

**Feasibility Constraints:**
- **Economic Irrationality:** Attacking miners forfeit all block rewards during the attack, making this economically irrational under typical circumstances
- **Detection:** Missed time slots accumulate and are visible on-chain
- **Limited Duration:** After 4,320 missed slots (3 days), evil miner detection triggers and miners are eventually replaced
- **Reputational Damage:** Detected evil miners are banned and removed from candidate lists [17](#0-16) 

**Probability Assessment:**
While technically feasible and the attack path is validated, this requires significant miner collusion (>33%) and has questionable economic motivation under normal circumstances. The attack is most plausible in scenarios where miners have alternative incentives beyond immediate block rewards, such as:
- Manipulating election outcomes to favor specific candidates
- Preventing reward distribution to competitor candidates
- Disrupting governance during contentious protocol decisions
- Causing protocol instability for strategic advantage

## Recommendation

**Short-term Mitigation:**
1. Reduce the `TolerableMissedTimeSlotsCount` threshold from 4,320 (3 days) to a shorter period (e.g., 1 day = 1,440 slots) to accelerate evil miner detection and replacement.

2. Implement an alternative term change trigger that doesn't rely solely on miner `ActualMiningTimes`, such as:
   - Allow term change if the blockchain time has exceeded the term threshold by a certain margin, regardless of individual miner timestamps
   - Add a fallback mechanism that forces term change after a maximum delay threshold

**Long-term Solution:**
Modify the `NeedToChangeTerm()` logic to consider miners who have stopped producing blocks:

```csharp
public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds, Timestamp currentBlockTime)
{
    var minersWithRecentActivity = RealTimeMinersInformation.Values
        .Where(m => m.ActualMiningTimes.Any())
        .Select(m => new { Miner = m, LastTime = m.ActualMiningTimes.Last() });
    
    var minersPassingThreshold = minersWithRecentActivity
        .Count(m => IsTimeToChangeTerm(blockchainStartTimestamp, m.LastTime, currentTermNumber, periodSeconds));
    
    // If current block time is past threshold and we don't have 2/3 consensus,
    // check if non-responsive miners are preventing term change
    if (IsTimeToChangeTerm(blockchainStartTimestamp, currentBlockTime, currentTermNumber, periodSeconds) &&
        minersPassingThreshold < MinersCountOfConsent)
    {
        // Force term change if a significant portion of miners have stopped responding
        var totalMiners = RealTimeMinersInformation.Count;
        var nonResponsiveMiners = totalMiners - minersWithRecentActivity.Count();
        if (nonResponsiveMiners > 0 && minersPassingThreshold >= (totalMiners - nonResponsiveMiners) * 2 / 3 + 1)
        {
            return true;
        }
    }
    
    return minersPassingThreshold >= MinersCountOfConsent;
}
```

This modification ensures that if all actively producing miners have passed the term threshold, the term change proceeds even if inactive miners would push the count below 2/3.

## Proof of Concept

Due to the complexity of the AEDPoS consensus system and the requirement for multi-miner coordination, a complete PoC would require:

1. Setting up a test network with 17 miners
2. Advancing time to approach a term threshold
3. Having 6 miners (>1/3) stop calling `UpdateValue`/`NextRound`
4. Observing that `GetConsensusBehaviourToTerminateCurrentRound()` returns `NextRound` instead of `NextTerm`
5. Verifying that `TakeSnapshot` is never called
6. Confirming the attack persists for 4,320 rounds until evil miner detection

The attack is validated through code analysis showing:
- The mathematical threshold requirement (⌊17 × 2/3⌋ + 1 = 12 miners needed)
- If 6 miners stop producing blocks, only 11 remain active (11 < 12)
- The conditional logic in `GetConsensusBehaviourToTerminateCurrentRound()` returns `NextRound` when `NeedToChangeTerm()` is false
- `ProcessNextRound()` executes instead of `ProcessNextTerm()`, skipping all term transition operations

**Notes:**
- The vulnerability is technically valid and has concrete protocol impact on governance, rewards, and historical data integrity
- While economically irrational under normal circumstances, the threat becomes realistic during governance disputes or when miners have non-monetary incentives
- The attack duration is bounded by the evil miner detection mechanism (3 days), but this window is sufficient to skip term-based operations and cause permanent loss of historical election data
- This represents a consensus-level vulnerability that affects protocol integrity rather than direct fund loss

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L304-304)
```csharp
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L299-342)
```csharp
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L422-426)
```csharp
        State.VoteContract.TakeSnapshot.Send(new TakeSnapshotInput
        {
            SnapshotNumber = input.TermNumber,
            VotingItemId = State.MinerElectionVotingItemId.Value
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L442-454)
```csharp
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.SubsidyHash.Value,
            Period = input.TermNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.WelfareHash.Value,
            Period = input.TermNumber,
            AmountsMap = { amountsMap }
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L459-479)
```csharp
    private void SavePreviousTermInformation(TakeElectionSnapshotInput input)
    {
        var snapshot = new TermSnapshot
        {
            MinedBlocks = input.MinedBlocks,
            EndRoundNumber = input.RoundNumber
        };

        if (State.Candidates.Value == null) return;

        foreach (var pubkey in State.Candidates.Value.Value)
        {
            var votes = State.CandidateVotes[pubkey.ToHex()];
            var validObtainedVotesAmount = 0L;
            if (votes != null) validObtainedVotesAmount = votes.ObtainedActiveVotedVotesAmount;

            snapshot.ElectionResult.Add(pubkey.ToHex(), validObtainedVotesAmount);
        }

        State.Snapshots[input.TermNumber] = snapshot;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L481-492)
```csharp
    private void UpdateCandidateInformation(string pubkey, long lastTermNumber,
        List<string> previousMiners)
    {
        var candidateInformation = State.CandidateInformationMap[pubkey];
        if (candidateInformation == null) return;
        candidateInformation.Terms.Add(lastTermNumber);
        var victories = GetVictories(previousMiners);
        candidateInformation.ContinualAppointmentCount = victories.Contains(ByteStringHelper.FromHexString(pubkey))
            ? candidateInformation.ContinualAppointmentCount.Add(1)
            : 0;
        State.CandidateInformationMap[pubkey] = candidateInformation;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L205-208)
```csharp

```
