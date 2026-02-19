# Audit Report

## Title
Malicious Block Producer Can Skip Term Changes by Using NextRound Instead of NextTerm Behavior

## Summary
The AEDPoS consensus validation logic fails to enforce that term changes occur when required. A malicious block producer can bypass mandatory term transitions by using `NextRound` behavior when `NextTerm` is required, skipping critical operations including miner list updates, treasury releases, and election snapshots.

## Finding Description

The vulnerability exists in the consensus validation flow where behavior choice is not enforced on-chain.

**Root Cause**: The `ValidationForNextRound` method validates only structural constraints (round number increment and null InValues) but does NOT verify whether a term change should have occurred. [1](#0-0) 

**Behavior Determination**: The system determines correct behavior off-chain in `MainChainConsensusBehaviourProvider` using `NeedToChangeTerm` logic, which checks if 2/3+ miners have timestamps indicating term period elapsed. [2](#0-1) [3](#0-2) 

However, this determination is advisory only. The node software generates trigger information with the behavior, but a malicious miner can modify their node to always use `NextRound`. [4](#0-3) 

**Attack Execution**: The contract receives trigger information and generates transactions based on the provided behavior without validating correctness. [5](#0-4) 

**Validation Failure**: The validation providers applied for `NextRound` do not include any term-related checks. [6](#0-5) 

**Impact Difference**: When `ProcessNextRound` executes instead of `ProcessNextTerm`, critical operations are skipped. `ProcessNextRound` only updates the round number and manages basic round information. [7](#0-6) 

In contrast, `ProcessNextTerm` performs essential term change operations: updates term number, fetches new miner list from election contract, releases treasury for the period, takes election snapshot, and updates miner information. [8](#0-7) 

## Impact Explanation

**High Severity** due to multiple critical system failures:

1. **Consensus Integrity Violation**: Term transitions are fundamental protocol requirements. Skipping them violates the consensus state machine, causing term/round desynchronization across the network.

2. **Economic Impact**: Treasury releases are period-based and tied to term changes. Skipping `Release.Send` prevents scheduled token distributions to profit schemes, disrupting the entire economic model. [9](#0-8) 

3. **Governance Disruption**: The miner list doesn't update from election results, preventing validator rotation. This breaks the democratic election system where token holders vote for validators. [10](#0-9) 

4. **Election State Corruption**: Election snapshots track voting weights and mined blocks per term. Skipping `TakeSnapshot` breaks historical records and vote calculations. [11](#0-10) 

5. **Reward Misallocation**: Mining rewards for the term are not donated to treasury, affecting reward distribution logic. [9](#0-8) 

## Likelihood Explanation

**Medium-High Likelihood** due to low attack barriers:

**Attacker Requirements**: Only requires being an active block producer in the miner list. This is achievable through the normal election process.

**Attack Complexity**: Very low. The attacker modifies their node's `MainChainConsensusBehaviourProvider` to always return `NextRound`, or modifies the trigger information generation logic. No cryptographic manipulation or complex state attacks required.

**Detection**: No on-chain detection exists. The validation logic accepts `NextRound` blocks as valid even when `NextTerm` should be used, so other nodes accept these blocks. [1](#0-0) 

**Opportunity**: The attacker must be scheduled to produce the extra block during term transition. Given rotating schedules, any malicious miner will eventually have this opportunity.

**Feasibility Confirmation**: A grep search confirms `NeedToChangeTerm` is ONLY used in off-chain behavior provider code and the `Round` type definition - it is never checked in contract validation or processing logic.

## Recommendation

Add term change validation to `RoundTerminateValidationProvider.ValidationForNextRound`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Verify term should not change
    var blockchainStartTimestamp = GetBlockchainStartTimestamp(); // Need access to this
    var periodSeconds = GetPeriodSeconds(); // Need access to this
    if (validationContext.BaseRound.NeedToChangeTerm(
            blockchainStartTimestamp, 
            validationContext.CurrentTermNumber, 
            periodSeconds))
    {
        return new ValidationResult { Message = "Term change required - must use NextTerm instead of NextRound." };
    }
    
    return new ValidationResult { Success = true };
}
```

Additionally, make `blockchainStartTimestamp` and `periodSeconds` accessible to validation providers through the `ConsensusValidationContext`.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MaliciousBlockProducer_CanSkipTermChange()
{
    // Setup: Initialize chain with term period of 7 days
    await InitializeAEDPoSContract(periodSeconds: 604800);
    
    // Advance time beyond term period threshold
    await AdvanceTimeToTermChangeRequired();
    
    // Verify NeedToChangeTerm returns true (term change required)
    var currentRound = await GetCurrentRound();
    var needsTermChange = currentRound.NeedToChangeTerm(
        blockchainStartTimestamp, currentTermNumber, periodSeconds);
    Assert.True(needsTermChange);
    
    // Malicious miner produces NextRound instead of NextTerm
    var nextRoundInput = GenerateNextRoundInput(currentRound);
    await AEDPoSContract.NextRound.SendAsync(nextRoundInput);
    
    // Verification: Attack succeeds - term not changed
    var newRound = await GetCurrentRound();
    Assert.Equal(currentTermNumber, newRound.TermNumber); // Term unchanged!
    Assert.Equal(currentRound.RoundNumber + 1, newRound.RoundNumber); // Round incremented
    
    // Critical operations skipped:
    var treasuryReleased = await VerifyTreasuryRelease(currentTermNumber);
    Assert.False(treasuryReleased); // Treasury NOT released
    
    var snapshotTaken = await VerifyElectionSnapshot(currentTermNumber);
    Assert.False(snapshotTaken); // Snapshot NOT taken
    
    var minerListUpdated = await VerifyMinerListFromElection();
    Assert.False(minerListUpdated); // Miner list NOT updated
}
```

## Notes

The vulnerability is particularly severe because:

1. **No on-chain enforcement**: The `NeedToChangeTerm` check exists only in off-chain node software, which malicious miners control
2. **Validation gap**: The validation explicitly checks term number increment for `NextTerm` but has no corresponding check that `NextRound` should NOT be used when term change is required
3. **Cascading failures**: Skipping one term change causes permanent state divergence - the system cannot self-correct as term numbers and round numbers become desynchronized
4. **Systemic impact**: Affects multiple subsystems (treasury, election, governance) simultaneously, making recovery complex

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L61-75)
```csharp
    public override TransactionList GenerateConsensusTransactions(BytesValue input)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);
        // Some basic checks.
        Assert(triggerInformation.Pubkey.Any(),
            "Data to request consensus information should contain pubkey.");

        var pubkey = triggerInformation.Pubkey;
        var randomNumber = triggerInformation.RandomNumber;
        var consensusInformation = new AElfConsensusHeaderInformation();
        consensusInformation.MergeFrom(GetConsensusBlockExtraData(input, true).Value);
        var transactionList = GenerateTransactionListByExtraData(consensusInformation, pubkey, randomNumber);
        return transactionList;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L164-179)
```csharp
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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
