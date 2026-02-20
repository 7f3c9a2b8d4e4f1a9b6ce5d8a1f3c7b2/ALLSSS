# Audit Report

## Title
Miner Collusion Can Delay Term Changes and Prevent Election Snapshot Creation

## Summary
Colluding miners controlling more than 1/3 of the mining power can deliberately prevent term transitions by forcing `NextRound` instead of `NextTerm`, which blocks the execution of `ElectionContract.TakeSnapshot`. This causes election vote data to remain stale, prevents reward distribution for affected terms, and results in loss of historical election data. The attack can persist for up to 3 days before evil miner detection triggers replacement.

## Finding Description

The vulnerability exists in the consensus behavior determination logic. The term change decision depends on `NeedToChangeTerm()` which requires at least `MinersCountOfConsent` (calculated as ⌊count × 2/3⌋ + 1) miners to have their latest `ActualMiningTime` passing the term threshold check. [1](#0-0) [2](#0-1) 

The `GetConsensusBehaviourToTerminateCurrentRound()` method returns `NextTerm` only when `NeedToChangeTerm()` returns true, otherwise it returns `NextRound`. [3](#0-2) 

**Root Cause:**

Miners only get their `ActualMiningTimes` updated when they actively produce blocks via `UpdateValue` or `TinyBlock` transactions. [4](#0-3) [5](#0-4) 

**Attack Execution:**

1. More than 1/3 of miners (e.g., 6 out of 17) coordinate to stop producing blocks before the term threshold
2. Their last `ActualMiningTime` remains from before the threshold
3. Less than 2/3 of miners have `ActualMiningTime` values indicating term change should occur
4. `NeedToChangeTerm()` returns false, causing `NextRound` to be executed instead of `NextTerm`
5. Critical operations in `ProcessNextTerm()` are skipped, including `TakeSnapshot` [6](#0-5) 

**Why Existing Protections Fail:**

Evil miner detection operates with a tolerance threshold of 4,320 missed time slots (3 days). [7](#0-6) 

Evil miners are detected during `ProcessNextRound`, but detection doesn't immediately force a term change. [8](#0-7) 

After detection, replacement candidates receive empty `ActualMiningTimes` lists and must produce blocks before contributing to the 2/3 threshold. [9](#0-8) 

## Impact Explanation

When `ProcessNextTerm()` is not executed, critical protocol operations are skipped:

**1. Election Snapshots Not Created:**
The `TakeSnapshot` call to the Election Contract only occurs in `ProcessNextTerm()`. [10](#0-9) 

**2. Historical Election Data Lost:**
`SavePreviousTermInformation()` creates term snapshots with election results and mined blocks. [11](#0-10) 

**3. Vote Weight Data Remains Stale:**
Vote Contract snapshots are not taken during the affected period. [12](#0-11) 

**4. Candidate Information Updates Skipped:**
Candidate term tracking and continual appointment counts are not updated. [13](#0-12) 

**5. Treasury Profit Release Prevented:**
Treasury contract release calls only occur in `ProcessNextTerm()`. [14](#0-13) 

**6. Profit Distribution Skipped:**
Subsidy and welfare profit distributions are not executed. [15](#0-14) 

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
- Medium - requires precise timing to stop producing blocks before the term threshold
- Requires sustained coordination for up to 3 days
- Miners accumulate missed time slots leading to evil miner status and eventual replacement

**Feasibility Constraints:**
- **Economic Irrationality:** Attacking miners forfeit all block rewards during the attack, making this economically irrational under typical circumstances
- **Detection:** Missed time slots accumulate and are visible on-chain
- **Limited Duration:** After 4,320 missed slots (3 days), evil miner detection triggers and miners are eventually replaced
- **Reputational Damage:** Detected evil miners are banned and removed from candidate lists [16](#0-15) 

**Probability Assessment:**
While technically feasible and the attack path is validated, this requires significant miner collusion (>33%) and has questionable economic motivation under normal circumstances. The attack is most plausible in scenarios where miners have alternative incentives beyond immediate block rewards, such as manipulating election outcomes, preventing reward distribution to competitors, or disrupting governance during contentious protocol decisions.

## Recommendation

Implement a forced term change mechanism that does not rely solely on miner ActualMiningTime updates:

1. **Time-based forced term change:** Add an absolute timestamp check that forces term change after a maximum period regardless of ActualMiningTime consensus, ensuring term transitions cannot be indefinitely delayed.

2. **Alternative term change trigger:** Allow term changes to proceed if sufficient blockchain age has elapsed, even without 2/3 miner ActualMiningTime consensus.

3. **Reduce evil miner tolerance:** Consider reducing the 3-day tolerance window to limit attack duration.

4. **Emergency term change mechanism:** Implement governance-triggered emergency term changes for situations where miner collusion is detected.

## Proof of Concept

```csharp
// Test scenario demonstrating the vulnerability
// Scenario: 6 out of 17 miners stop producing blocks before term threshold

// 1. Setup: 17 miners in current round, term threshold approaching
// 2. Attack: 6 miners stop calling UpdateValue/UpdateTinyBlockInformation
// 3. Result: Only 11 miners have updated ActualMiningTime
// 4. Verification: 11 < 12 (MinersCountOfConsent), so NeedToChangeTerm() returns false
// 5. Consequence: NextRound executes instead of NextTerm
// 6. Impact: TakeSnapshot is not called, election data not recorded, rewards not distributed

// The test would verify:
// - NeedToChangeTerm() returns false when <2/3 miners have current ActualMiningTime
// - GetConsensusBehaviourToTerminateCurrentRound() returns NextRound instead of NextTerm
// - ProcessNextRound is executed without calling TakeSnapshot
// - Election Contract's TakeSnapshot method is not invoked
// - Treasury Release is not triggered
```

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L328-338)
```csharp
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
