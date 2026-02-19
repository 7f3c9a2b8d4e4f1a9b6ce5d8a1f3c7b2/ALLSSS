# Audit Report

## Title
Term Transition Failure Due to Offline Miner Threshold Causing Indefinite Miner Entrenchment and Treasury Halt

## Summary
The AEDPoS consensus contract contains a critical threshold mismatch in `NeedToChangeTerm()` that prevents term transitions when more than 1/3 of miners are offline. The function counts only active miners (those who produced blocks) but compares against `MinersCountOfConsent` which is calculated from the total miner count. This causes `GetConsensusBehaviourToTerminateCurrentRound()` to return `NextRound` instead of `NextTerm`, permanently freezing the miner list, halting treasury distributions, and preventing newly elected miners from taking office.

## Finding Description

The vulnerability exists in the term transition decision logic where an inconsistent threshold comparison prevents legitimate term changes.

**Root Cause:**

The `NeedToChangeTerm()` function filters for miners with actual mining activity but compares the count against a threshold based on all miners: [1](#0-0) 

This method only counts miners who have `ActualMiningTimes.Any()`, meaning miners who have produced at least one block. However, the threshold `MinersCountOfConsent` is calculated as: [2](#0-1) 

This calculation uses `RealTimeMinersInformation.Count` which represents the **total** number of miners, not just active ones.

**Exploitation Flow:**

When determining whether to transition terms, the consensus system calls: [3](#0-2) 

If `NeedToChangeTerm()` returns `false` (the `!` negation makes the condition true), the system executes `NextRound` instead of `NextTerm`.

**Concrete Example:**
- Total miners: 17
- MinersCountOfConsent = (17 × 2 ÷ 3) + 1 = 12
- Active miners (producing blocks): 11
- Offline miners: 6
- Even if all 11 active miners have timestamps in the new term period, the count (11) < threshold (12)
- Result: `NeedToChangeTerm()` returns `false`, term transition fails

**Why This Breaks Security Guarantees:**

When `NextRound` is executed instead of `NextTerm`, the system continues producing blocks but skips critical governance operations. The `ProcessNextRound` method: [4](#0-3) 

This method does NOT update the miner list, sync election results, release treasury funds, or donate mining rewards. All these critical operations are exclusive to `ProcessNextTerm`: [5](#0-4) 

## Impact Explanation

The impact is **CRITICAL** because it breaks multiple core protocol mechanisms:

**1. Miner List Frozen:** The `SetMinerList` function is only called in `ProcessNextTerm`: [6](#0-5) 

New miners from election results (obtained via `TryToGetVictories()` in `GenerateFirstRoundOfNextTerm`) never take office: [7](#0-6) 

**2. Election Results Never Applied:** Performance data synchronization to the Election contract only occurs in `ProcessNextTerm`: [8](#0-7) 

**3. Treasury Distributions Halt:** Treasury fund releases are exclusive to term transitions: [9](#0-8) 

**4. Mining Rewards Not Donated:** Reward donations to the Treasury only happen in `ProcessNextTerm`: [10](#0-9) 

**5. Term Number Frozen:** The term number increment only occurs in `ProcessNextTerm`: [11](#0-10) 

This creates permanent state inconsistency where block production continues but governance is completely frozen.

## Likelihood Explanation

The likelihood is **HIGH** due to multiple realistic trigger scenarios:

**Attack Vector 1 - Miner Collusion:**
Current miners facing election defeat can coordinate >1/3 of the miner set to intentionally stop producing blocks. This requires no network attacks, only agreement among miners who have direct financial incentive to retain their positions. With 17 miners, only 6 need to collude (35% of the miner set).

**Attack Vector 2 - Natural Network Issues:**
Network partitions, infrastructure failures, or maintenance windows can naturally cause >1/3 of miners to go offline temporarily. When this coincides with a term boundary, the bug triggers without any malicious intent.

**Economic Rationality:**
Miners earn significant block rewards and have strong financial incentive to prevent being voted out. Coordinating 6 out of 17 miners is economically feasible and provides ongoing revenue from mining rewards that would otherwise be lost.

**No Recovery Mechanism:**
The `SetMinerList` function has only two call sites - initialization (`FirstRound`) and term transitions (`ProcessNextTerm`): [12](#0-11) 

There is no governance override or manual recovery mechanism to force a term transition once this condition is met.

## Recommendation

Modify `NeedToChangeTerm()` to compare against the count of active miners instead of total miners:

```csharp
public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
{
    var activeMiners = RealTimeMinersInformation.Values
        .Where(m => m.ActualMiningTimes.Any())
        .ToList();
    
    var activeMinersInNewTerm = activeMiners
        .Select(m => m.ActualMiningTimes.Last())
        .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp, t, currentTermNumber, periodSeconds));
    
    // Compare against 2/3+1 of ACTIVE miners, not total miners
    var activeMinersConsent = activeMiners.Count.Mul(2).Div(3).Add(1);
    
    return activeMinersInNewTerm >= activeMinersConsent;
}
```

Alternatively, if the intention is to require 2/3+1 of total miners for Byzantine fault tolerance, the system should halt block production (including `NextRound`) when insufficient miners are active, rather than continuing block production while freezing governance.

## Proof of Concept

The vulnerability can be demonstrated by examining the execution flow when 6 out of 17 miners are offline:

1. **Setup:** 17 total miners, term period elapsed
2. **Condition:** 6 miners offline (no `ActualMiningTimes`), 11 miners active with timestamps in new term
3. **Calculation:** `MinersCountOfConsent = (17 * 2 / 3) + 1 = 12`
4. **Result:** `NeedToChangeTerm()` counts only 11 active miners, returns `false` (11 < 12)
5. **Consequence:** `GetConsensusBehaviourToTerminateCurrentRound()` returns `NextRound` instead of `NextTerm`
6. **Impact:** `ProcessNextRound` executes, skipping all term transition operations:
   - Miner list never updated (line 190 of ProcessConsensusInformation)
   - Election results never applied (line 201)
   - Treasury never released (line 205-208)
   - Mining rewards never donated (line 203)
   - Term number stays frozen (line 173)
   - Election snapshot never taken (line 213-218)

The bug is reproducible whenever `(total_miners - active_miners) > (total_miners - MinersCountOfConsent)`, which simplifies to approximately >1/3 of miners being offline during a term boundary.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L84-84)
```csharp
        SetMinerList(input.GetMinerList(), 1);
```
