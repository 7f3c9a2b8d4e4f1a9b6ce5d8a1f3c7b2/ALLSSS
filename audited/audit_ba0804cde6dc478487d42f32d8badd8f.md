# Audit Report

## Title
Missing Temporal Validation Allows Premature Term Transitions

## Summary
The AEDPoS consensus validation logic fails to verify whether a term change is actually due when processing `NextTerm` behaviour. A malicious miner can trigger term transitions prematurely by providing `NextTerm` consensus extra data before the time-based conditions are met, bypassing the `NeedToChangeTerm()` check that governs term transitions. This results in premature treasury fund releases, corrupted election snapshots, and disrupted consensus timing.

## Finding Description

The vulnerability exists in the validation flow for `NextTerm` consensus behavior. While honest miners use `MainChainConsensusBehaviourProvider` to determine when to change terms based on temporal conditions, the validation logic does not enforce these same temporal requirements.

**Honest Path (what should happen):**
When honest miners request consensus commands, `MainChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` checks whether it's time to change terms: [1](#0-0) 

This method calls `CurrentRound.NeedToChangeTerm()` which verifies that 2/3 of miners who produced blocks have timestamps indicating the term period has elapsed: [2](#0-1) 

**Validation Path (the vulnerability):**
When a block with `NextTerm` behavior is validated, the `RoundTerminateValidationProvider` is used: [3](#0-2) 

However, `ValidationForNextTerm` only performs structural validation: [4](#0-3) 

This validation checks:
- Round number increments by 1
- Term number increments by 1  
- InValues are null

**Critical Missing Check:** It does NOT invoke `NeedToChangeTerm()` to verify the temporal condition is satisfied.

**Attack Execution:**
1. A malicious miner in the current miner list can query `State.ElectionContract.GetVictories.Call(new Empty())` to obtain next term's elected miners (this is a public view method)
2. Generate a valid next term round using the same logic as `GenerateFirstRoundOfNextTerm()`
3. Produce a block with `Behaviour = NextTerm` in consensus extra data during their time slot
4. Validation passes because only structural checks are performed
5. `ProcessNextTerm` executes prematurely, triggering all the harmful state transitions

## Impact Explanation

When `ProcessNextTerm` executes prematurely, it triggers multiple critical operations that should only occur at the end of a term: [5](#0-4) 

**Concrete Harms:**

1. **Treasury Fund Release (HIGH):** Premature release of treasury funds via `State.TreasuryContract.Release.Send(new ReleaseInput { PeriodNumber = termNumber })`. This releases funds allocated for a term that hasn't actually completed, causing fund misallocation.

2. **Election Snapshot Timing (HIGH):** Election snapshots taken via `State.ElectionContract.TakeSnapshot.Send()` at incorrect times. These snapshots determine voting rewards and miner selection for future terms - taking them prematurely corrupts the governance and election data.

3. **Miner Statistics Reset (MEDIUM):** Premature reset of `MissedTimeSlots` and `ProducedBlocks` counters for all miners. This corrupts performance tracking and can allow malicious miners to escape penalties for poor performance.

4. **Miner List Updates (HIGH):** Updating to newly elected miners before the term period completes, disrupting the consensus schedule and potentially excluding miners who were supposed to produce blocks.

5. **Mining Reward Miscalculation (MEDIUM):** Rewards donated based on incomplete term data via `DonateMiningReward(previousRound)`, leading to incorrect reward distribution.

**Severity: HIGH** - This vulnerability breaks the fundamental consensus timing mechanism, causes premature fund releases, and corrupts governance/election data integrity.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be in the current miner list (validated by `MiningPermissionValidationProvider`)
- Must be able to produce a block during their time slot

**Attack Complexity: LOW**
- The attacker simply needs to:
  1. Call the public `GetVictories()` method to get election results
  2. Generate next term round data using standard methods
  3. Set `Behaviour = NextTerm` in consensus extra data when producing a block
- All validation passes because only structural checks exist, not temporal checks

**Feasibility: HIGH**
- Any malicious miner in the miner list can execute this attack
- No special permissions required beyond being a current miner
- No economic cost beyond normal block production
- Election results needed for generating next term data are publicly queryable

**Detection:** The attack is observable on-chain through the term number advancing prematurely, but may initially be attributed to normal consensus operations. The premature treasury release and election snapshot would be the clearest indicators.

**Probability: MEDIUM-HIGH** - Requires a malicious miner position, but the attack is straightforward once in that position, requires no special resources, and the validation gap makes it trivially exploitable.

## Recommendation

Add temporal validation to `ValidationForNextTerm` by checking `NeedToChangeTerm()`:

```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Check term number increments correctly
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };
    
    // ADD THIS CHECK: Verify it's actually time to change terms
    if (!validationContext.BaseRound.NeedToChangeTerm(
        validationContext.BlockchainStartTimestamp,
        validationContext.CurrentTermNumber,
        validationContext.PeriodSeconds))
    {
        return new ValidationResult { Message = "Term change condition not met - period has not elapsed." };
    }

    return new ValidationResult { Success = true };
}
```

You'll need to add `BlockchainStartTimestamp` and `PeriodSeconds` to the `ConsensusValidationContext` structure:

```csharp
public class ConsensusValidationContext
{
    // ... existing fields ...
    public Timestamp BlockchainStartTimestamp { get; set; }
    public long PeriodSeconds { get; set; }
}
```

And populate these in `ValidateBeforeExecution`:

```csharp
var validationContext = new ConsensusValidationContext
{
    // ... existing assignments ...
    BlockchainStartTimestamp = GetBlockchainStartTimestamp(),
    PeriodSeconds = State.PeriodSeconds.Value
};
```

## Proof of Concept

A malicious miner can exploit this by:

1. During their time slot, query `State.ElectionContract.GetVictories.Call(new Empty())` to get next term miners
2. Generate a valid next term round with term number = current + 1, round number = current + 1
3. Create consensus extra data with `Behaviour = NextTerm` and the generated round
4. Produce a block with this extra data
5. Validation passes (only structural checks)
6. `ProcessNextTerm` executes prematurely, causing:
   - Immediate treasury fund release for incomplete term
   - Election snapshot at wrong time
   - Premature miner list rotation
   - Reset of miner performance statistics

The attack succeeds because `ValidationForNextTerm` never calls `NeedToChangeTerm()` to verify the temporal precondition is met.

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
