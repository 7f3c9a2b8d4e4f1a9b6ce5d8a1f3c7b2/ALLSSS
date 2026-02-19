### Title
Missing Two-Thirds Consensus Threshold Validation Allows Premature Term Changes

### Summary
While the negation logic in `GetConsensusBehaviourToTerminateCurrentRound()` is mathematically correct and edge cases are handled deterministically, the consensus contract lacks server-side validation to enforce the two-thirds threshold when processing `NextTerm` transactions. A single malicious miner can force a term change without achieving the required supermajority consensus, bypassing the intended Byzantine Fault Tolerant consensus mechanism.

### Finding Description

The `MainChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` method correctly implements the decision logic for term changes using `NeedToChangeTerm()`: [1](#0-0) 

The `NeedToChangeTerm()` method properly calculates whether the two-thirds threshold is met: [2](#0-1) 

The threshold calculation `MinersCountOfConsent` requires more than 2/3 consensus: [3](#0-2) 

**Root Cause:** The critical vulnerability is that `ValidateBeforeExecution()` does NOT verify the two-thirds threshold when processing `NextTerm` transactions: [4](#0-3) 

The `RoundTerminateValidationProvider` only validates round/term number increments and null InValues, but never checks whether `NeedToChangeTerm()` returns true: [5](#0-4) 

While honest miners use the behavior provider logic to determine when to submit `NextTerm`, a malicious miner can bypass this by directly calling `NextTerm()` with a crafted input that passes validation despite the threshold not being met. [6](#0-5) 

### Impact Explanation

**Consensus Integrity Violation:** The two-thirds threshold is a fundamental Byzantine Fault Tolerant consensus invariant. Bypassing this allows a single compromised miner to unilaterally force term transitions, violating the security assumption that the system can tolerate up to 1/3 malicious nodes.

**Concrete Impacts:**
1. **Premature Miner List Changes:** Term changes trigger new miner list updates, potentially disrupting the intended election cycle
2. **Reward Distribution Manipulation:** Mining rewards are donated and distributed during term changes, affecting timing and potentially causing financial impact
3. **Treasury Release Timing:** Treasury funds are released during term changes, allowing manipulation of release schedules
4. **Election Snapshot Manipulation:** Election snapshots are taken during term changes, potentially affecting governance decisions [7](#0-6) 

The protocol assumes honest consensus behavior, but this vulnerability allows a single miner to bypass the supermajority requirement, undermining the entire consensus security model.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Attacker must be an elected miner (have mining rights)
- Attacker must produce a block during their time slot
- No additional privileges beyond standard miner rights

**Attack Complexity:** Low
1. Craft a `NextTermInput` with correctly incremented round/term numbers
2. Include random number and valid signatures
3. Submit transaction during attacker's time slot
4. Validation passes (no threshold check)
5. Term changes without consensus

**Feasibility:** The attack is practical because:
- Miners regularly produce blocks and submit consensus transactions
- The validation logic is deterministic and can be analyzed
- Only requires one malicious miner to execute
- No complex timing or race conditions required

**Economic Rationality:** A malicious miner might exploit this to:
- Force favorable miner list changes
- Manipulate reward distribution timing
- Disrupt competitor mining schedules
- Affect governance outcomes through snapshot timing

**Detection:** Difficult to detect in real-time as the transaction appears valid to all validation checks. Post-facto analysis would reveal insufficient consensus, but the chain would have already accepted the invalid state transition.

### Recommendation

**Immediate Fix:** Add threshold validation in `ValidateBeforeExecution()` for `NextTerm` behavior:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new TermChangeThresholdValidationProvider()); // NEW
    break;
```

**Implement `TermChangeThresholdValidationProvider`:**
```csharp
public class TermChangeThresholdValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var baseRound = validationContext.BaseRound;
        
        // Get blockchain start timestamp and period from state
        var blockchainStartTimestamp = GetBlockchainStartTimestamp();
        var periodSeconds = GetPeriodSeconds();
        
        // Verify two-thirds threshold is actually met
        if (!baseRound.NeedToChangeTerm(blockchainStartTimestamp, 
            validationContext.CurrentTermNumber, periodSeconds))
        {
            return new ValidationResult 
            { 
                Message = "Two-thirds consensus threshold not met for term change." 
            };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

**Invariant Check:** Before any term transition, verify:
```
CountOfMinersReadyToChangeTerm >= MinersCountOfConsent
```

**Test Cases:**
1. Test with exactly (N*2/3) miners ready - should fail validation
2. Test with (N*2/3)+1 miners ready - should pass validation
3. Test with malicious miner submitting NextTerm prematurely - should fail validation
4. Test boundary conditions with 3, 6, 7, 9 miners to verify integer division handling

### Proof of Concept

**Initial State:**
- 7 miners in current term (MinersCountOfConsent = 5, requiring 71.4%)
- Current round: term 1, round 10
- Only 4 miners have ActualMiningTime indicating term change readiness (57%, below threshold)

**Attack Sequence:**

1. **Malicious miner crafts NextTermInput:**
   - RoundNumber: 11 (current + 1)
   - TermNumber: 2 (current + 1)  
   - RealTimeMinersInformation: populated with new term data
   - RandomNumber: valid VRF proof

2. **Malicious miner submits transaction:**
   - Calls `NextTerm(nextTermInput)` during their time slot
   - Transaction gets included in their block

3. **Validation executes:**
   - `PreCheck()` passes (miner is in list)
   - `ValidateBeforeExecution()` passes (only checks round/term increments)
   - No threshold validation performed
   - `ProcessNextTerm()` executes successfully

4. **Result:**
   - Term changes from 1 to 2 (premature)
   - New miner list installed
   - Mining rewards distributed
   - Treasury released
   - Election snapshot taken
   - All with only 57% consensus instead of required 71.4%

**Expected Behavior:** Transaction should be rejected with validation error: "Two-thirds consensus threshold not met for term change."

**Actual Behavior:** Transaction succeeds and term changes without proper consensus, violating the BFT consensus invariant.

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
