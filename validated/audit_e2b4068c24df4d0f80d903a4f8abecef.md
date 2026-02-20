# Audit Report

## Title
Missing Term Duration Validation Allows Premature Term Transitions

## Summary
The AEDPoS consensus validation logic fails to enforce term duration constraints during NextTerm transaction validation. While time validation logic exists in `NeedToChangeTerm()`, it is only used for honest node behavior determination and not enforced during block validation. A malicious miner can exploit this gap to force premature term transitions, violating the fundamental consensus guarantee that terms last for `periodSeconds` duration and triggering incorrect economic distributions.

## Finding Description

The vulnerability stems from a critical architectural flaw where time validation exists but is not integrated into the validation pipeline.

**Root Cause - Structural-Only Validation:**

When a NextTerm transaction is validated, the system only adds `RoundTerminateValidationProvider` to the validation pipeline [1](#0-0) , which performs only structural checks: verifying that round number increments by 1 (via `ValidationForNextRound`) and term number increments by 1 [2](#0-1) . No temporal constraint validation occurs.

**Unused Time Protection:**

The codebase contains proper time validation in `NeedToChangeTerm()` which checks if 2/3 of miners have timestamps indicating the term period has elapsed [3](#0-2) , using the formula that compares elapsed time against `periodSeconds` [4](#0-3) . However, this check is only invoked in `MainChainConsensusBehaviourProvider` for honest command generation [5](#0-4) , not during validation.

**Attack Execution:**

1. A malicious miner modifies their node to bypass honest command generation logic
2. They construct a `NextTermInput` with properly incremented term/round numbers
3. They call the public `NextTerm()` method [6](#0-5)  during their mining time slot
4. `PreCheck()` passes because it only verifies miner list membership [7](#0-6) , not time constraints
5. Block validation runs `ValidateBeforeExecution()` which only checks structural correctness, allowing the premature term transition

## Impact Explanation

This vulnerability breaks a fundamental consensus invariant and causes cascading economic impacts:

**Mining Reward Manipulation:** The premature term change triggers `DonateMiningReward()` which calculates and distributes mining rewards for the previous term with incorrect timing [8](#0-7) . This distorts the intended reward economics.

**Treasury Release Manipulation:** Term transitions trigger treasury contract releases with incorrect period numbers [9](#0-8) , potentially releasing funds prematurely.

**Election Integrity:** Election snapshots are taken at term boundaries [10](#0-9) , and premature term changes allow manipulation of when election results take effect.

**Miner List Disruption:** New miner lists from elections are applied prematurely [11](#0-10) , disrupting the intended consensus schedule.

**Severity: HIGH** - This violates a critical consensus invariant affecting economic incentives, governance timing, and network integrity across all participants.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a current miner in the active miner list (achievable through normal election process)
- Must control their node software to modify consensus behavior (standard for any miner)
- No additional economic stake or collusion with other miners required

**Attack Simplicity:**
The attack is straightforward - modify the node to always return `NextTerm` behavior or directly call the public `NextTerm()` method [12](#0-11)  with crafted input during the miner's scheduled time slot. The validation provides no defense since only structural checks occur.

**Guaranteed Opportunity:**
Every miner has scheduled time slots in rotation, providing guaranteed attack windows. The validation logic's failure to check time constraints means the attack succeeds deterministically.

**Probability: HIGH** - Any miner can execute this attack during their time slot. The barrier is trivial (node software control), which miners inherently possess.

## Recommendation

Add time-based validation to the `RoundTerminateValidationProvider.ValidationForNextTerm()` method:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Existing term number check
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };

    // NEW: Validate term duration has elapsed
    var blockchainStartTimestamp = GetBlockchainStartTimestamp();
    var periodSeconds = State.PeriodSeconds.Value;
    if (!validationContext.BaseRound.NeedToChangeTerm(blockchainStartTimestamp, 
        validationContext.BaseRound.TermNumber, periodSeconds))
        return new ValidationResult { Message = "Term duration not elapsed, cannot change term." };

    return new ValidationResult { Success = true };
}
```

This ensures that the existing time validation logic (`NeedToChangeTerm`) is enforced during validation, not just during honest command generation.

## Proof of Concept

```csharp
[Fact]
public async Task Exploit_PrematureTermTransition()
{
    // Setup: Initialize consensus with 7-day term duration
    var periodSeconds = 604800; // 7 days
    await InitializeConsensus(periodSeconds);
    
    // Advance to round 2 of term 1 (term just started)
    await ProduceNormalBlocks(2);
    
    var currentRound = await GetCurrentRound();
    Assert.Equal(1, currentRound.TermNumber);
    
    // Malicious miner crafts NextTerm input immediately (no time elapsed)
    var maliciousMiner = InitialMiners[0];
    var nextTermInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber + 1,
        // Properly structured but premature
        RealTimeMinersInformation = GenerateNextTermMiners()
    };
    
    // Execute premature NextTerm - should fail but succeeds
    var result = await MinerKeyPair[maliciousMiner]
        .ExecuteConsensusContractMethodWithMiningAsync(
            nameof(AEDPoSContract.NextTerm), nextTermInput);
    
    // Vulnerability: Transaction succeeds despite insufficient time elapsed
    Assert.True(result.Status == TransactionResultStatus.Mined);
    
    var newRound = await GetCurrentRound();
    Assert.Equal(2, newRound.TermNumber); // Term prematurely advanced!
    
    // Verify economic impacts occurred prematurely
    var treasuryEvents = result.Logs.Where(l => l.Name == "Release").ToList();
    Assert.NotEmpty(treasuryEvents); // Treasury released prematurely
}
```

## Notes

The vulnerability exists because the consensus system separates behavior determination (command generation for honest nodes) from validation (verification of received transactions). The `NeedToChangeTerm()` time check was correctly placed in behavior determination but critically omitted from validation, creating an exploitable gap. This is a design flaw rather than an implementation bug - the time validation logic is correct but architecturally misplaced, enforcing honest behavior without preventing malicious behavior.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** protobuf/aedpos_contract.proto (L37-39)
```text
    // Update consensus information, create a new term.
    rpc NextTerm (NextTermInput) returns (google.protobuf.Empty) {
    }
```
