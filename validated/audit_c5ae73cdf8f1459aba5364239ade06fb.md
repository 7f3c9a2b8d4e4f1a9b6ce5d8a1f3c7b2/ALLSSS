# Audit Report

## Title
Miner Collusion Can Delay Term Changes and Prevent Election Snapshot Creation

## Summary
Colluding miners controlling more than 1/3 of the mining power can deliberately prevent term transitions by forcing `NextRound` instead of `NextTerm`, which blocks the execution of `ElectionContract.TakeSnapshot`. This causes election vote data to remain stale, prevents reward distribution for affected terms, and results in loss of historical election data.

## Finding Description

The vulnerability exists in the consensus behavior determination logic. The `GetConsensusBehaviourToTerminateCurrentRound()` method returns `NextTerm` only when `NeedToChangeTerm()` returns true. [1](#0-0) 

The `NeedToChangeTerm()` function requires at least `MinersCountOfConsent` (calculated as ⌊count × 2/3⌋ + 1) miners to have their latest `ActualMiningTime` passing the term threshold check. [2](#0-1) [3](#0-2) 

**Root Cause:**

Miners only get their `ActualMiningTimes` updated when they actively produce blocks through UpdateValue or TinyBlock transactions. [4](#0-3) [5](#0-4) 

**Attack Execution:**

If more than 1/3 of miners (e.g., 6 out of 17) coordinate to stop producing blocks before the term threshold, then less than 2/3 of miners will have `ActualMiningTime` values indicating the term should change. This causes `NeedToChangeTerm()` to return false, resulting in `ProcessNextRound()` being executed instead of `ProcessNextTerm()`. [6](#0-5) 

When `ProcessNextRound()` is called instead of `ProcessNextTerm()`, the critical `TakeSnapshot` operation is skipped. [7](#0-6) 

**Why Existing Protections Fail:**

Evil miner detection operates with a tolerance threshold of 4,320 missed time slots (3 days). [8](#0-7) 

Evil miners are detected during `ProcessNextRound`, but detection only marks them as evil without forcing a term change. [9](#0-8) 

After detection, evil miners are replaced via `GenerateNextRoundInformation()`, but replacement miners are initialized without any `ActualMiningTimes`, meaning they don't contribute to the 2/3 threshold until they produce their first blocks. [10](#0-9) 

## Impact Explanation

When `ProcessNextTerm()` is not executed, critical protocol operations are skipped:

**1. Election Snapshots Not Created:**
`SavePreviousTermInformation()` creates term snapshots with election results (vote counts per candidate) and mined blocks, which is essential for historical election data. [11](#0-10) 

**2. Vote Weight Data Remains Stale:**
Vote Contract snapshots are not taken during the affected period. [12](#0-11) 

**3. Candidate Information Updates Skipped:**
Candidate term tracking and continual appointment counts are not updated. [13](#0-12) 

**4. Treasury Profit Release Prevented:**
Treasury contract release calls do not occur for affected terms. [14](#0-13) 

**5. Profit Distribution Skipped:**
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
Medium - requires precise timing and sustained coordination for up to 3 days. Miners accumulate missed time slots leading to evil miner status and eventual replacement.

**Feasibility Constraints:**
- **Economic Irrationality:** Attacking miners forfeit all block rewards during the attack
- **Detection:** Missed time slots accumulate and are visible on-chain
- **Limited Duration:** After 4,320 missed slots (3 days), evil miner detection triggers
- **Reputational Damage:** Detected evil miners are banned

**Probability Assessment:**
While technically feasible and the attack path is validated, this requires significant miner collusion (>33%) and has questionable economic motivation under normal circumstances. The attack is most plausible in scenarios where miners have alternative incentives beyond immediate block rewards, such as manipulating election outcomes, preventing reward distribution to competitors, or disrupting governance.

## Recommendation

Implement a mechanism to force term changes even when miner consensus is not reached. Consider:

1. **Automatic Term Transition:** After a maximum number of rounds within a term (e.g., configurable limit), force a term change regardless of `NeedToChangeTerm()` result
2. **Count All Miners:** Modify `NeedToChangeTerm()` to count all miners in the round, not just those with `ActualMiningTimes`, and use a different timestamp source for non-producing miners
3. **Emergency Term Change:** Add a governance-controlled method to force term transitions when the system detects extended delays
4. **Penalize Non-Production:** Increase the penalty for non-producing miners to make the attack economically prohibitive

Example fix approach:
```csharp
public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds, long maxRoundsPerTerm)
{
    // Force term change after maximum rounds
    if (RoundNumber - State.FirstRoundNumberOfEachTerm[TermNumber] >= maxRoundsPerTerm)
        return true;
        
    // Existing logic
    return RealTimeMinersInformation.Values
        .Where(m => m.ActualMiningTimes.Any())
        .Select(m => m.ActualMiningTimes.Last())
        .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp, t, currentTermNumber, periodSeconds))
        >= MinersCountOfConsent;
}
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up a network with 17 miners
2. Advance time to just before term threshold
3. Have 6+ miners stop producing blocks (not calling UpdateValue/TinyBlock)
4. Show that `NeedToChangeTerm()` returns false despite time passing the threshold
5. Verify that `ProcessNextRound()` continues to be called instead of `ProcessNextTerm()`
6. Confirm that `TakeSnapshot` is never invoked
7. Validate that historical election data is not saved

The core vulnerability is that term transitions depend on voluntary miner action (producing blocks to update `ActualMiningTimes`) rather than being time-driven or having a fallback mechanism, allowing coordinated miners to indefinitely delay critical protocol operations.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L36-44)
```csharp
        {
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
            case NextTermInput nextTermInput:
                randomNumber = nextTermInput.RandomNumber;
                ProcessNextTerm(nextTermInput);
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-244)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-305)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L328-339)
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
