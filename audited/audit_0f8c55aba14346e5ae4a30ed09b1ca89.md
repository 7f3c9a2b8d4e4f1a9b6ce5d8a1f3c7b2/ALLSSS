### Title
TermNumber State Corruption via Unvalidated NextRound Allows Consensus Disruption

### Summary
The `ValidationForNextRound` method fails to validate that the proposed `TermNumber` matches the current term number, allowing malicious miners to inject arbitrary TermNumber values (including negative values) during NextRound transitions. This creates a critical state inconsistency between `BaseRound.TermNumber` and `State.CurrentTermNumber`, preventing all subsequent NextTerm transitions and causing permanent consensus disruption until manually remediated.

### Finding Description

**Root Cause:**
The validation logic in `RoundTerminateValidationProvider` contains an asymmetry: `ValidationForNextTerm` validates TermNumber increments correctly, but `ValidationForNextRound` completely omits TermNumber validation. [1](#0-0) 

The NextRound validation only checks round number increment and InValue nullity, with no validation that `extraData.Round.TermNumber` equals the current `BaseRound.TermNumber`.

**State Corruption Mechanism:**
When a NextRound block is processed, the Round object (including its TermNumber field) is saved directly to state storage without validation: [2](#0-1) 

The `AddRoundInformation` call at line 156 persists the entire Round object to `State.Rounds`, while `State.CurrentTermNumber` remains unchanged (only `State.CurrentRoundNumber` is updated at line 158). The `ToRound()` method copies all fields including the attacker-controlled TermNumber: [3](#0-2) 

**State Desynchronization:**
This creates a critical desync where:
- `State.CurrentTermNumber` remains at the legitimate value (fetched via `TryToGetTermNumber`)
- `BaseRound.TermNumber` (fetched from `State.Rounds` in validation) contains the malicious value [4](#0-3) 

**Subsequent NextTerm Failure:**
After state corruption, NextTerm transitions become impossible because they face contradictory requirements:
1. Validation requires: `extraData.Round.TermNumber == BaseRound.TermNumber + 1` (uses corrupted value from `State.Rounds`)
2. Execution requires: `termNumber == State.CurrentTermNumber + 1` OR `termNumber == 1` (uses legitimate value) [5](#0-4) [6](#0-5) 

No value can simultaneously satisfy both checks when the state is desynchronized.

### Impact Explanation

**Consensus Integrity Violation:**
- **Permanent DoS of Term Transitions**: Once BaseRound.TermNumber is corrupted, all NextTerm attempts fail validation because no TermNumber value can satisfy both the validation check (requiring `corrupted_value + 1`) and execution check (requiring `legitimate_value + 1`).
- **Election Mechanism Failure**: Term transitions trigger miner list updates, election snapshots, and reward distributions. Blocking term transitions halts the entire election cycle. [7](#0-6) 

- **Treasury/Reward Distribution Halt**: Mining rewards are donated and released per term. Without term progression, the economic model breaks down (lines 203-211 in ProcessNextTerm).
- **State Corruption Persistence**: The desync persists indefinitely because the only way to update `State.CurrentTermNumber` (via `TryToUpdateTermNumber`) is through NextTerm, which is now blocked.

**Severity Justification:**
This is a **High severity** vulnerability (not Medium as originally classified) because:
1. It completely disables the term transition mechanism
2. It affects the entire consensus and economic layer
3. Recovery requires out-of-band manual intervention
4. Impact persists indefinitely until fixed

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a current or previous miner (verified in PreCheck) [8](#0-7) 

- Can craft arbitrary NextRoundInput with malicious TermNumber
- Only needs to produce one malicious NextRound block

**Attack Complexity:**
- **Low**: Single transaction with modified TermNumber field
- **No special conditions required**: Works at any point during normal consensus operation
- **Undetectable during validation**: No validation checks flag the malicious TermNumber

**Feasibility Conditions:**
- Blockchain must be operational (attacker is an active miner)
- No special timing or state requirements
- Attack succeeds with 100% probability if attacker can mine a block

**Detection Constraints:**
- The corruption is NOT immediately visible in normal operations
- Only becomes apparent when the next term transition is attempted
- By then, state is already corrupted

**Probability Assessment:**
Given that miners have elevated privileges in the system and one compromised miner can execute this attack with a single transaction, the likelihood is **High** despite requiring miner privileges.

### Recommendation

**Immediate Fix:**
Add TermNumber validation to `ValidationForNextRound` to enforce the invariant that TermNumber must remain constant within a term:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD: Validate term number remains constant
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Term number must not change in NextRound." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

**Additional Safeguards:**
1. Add a consistency check in `AddRoundInformation` to verify `round.TermNumber == State.CurrentTermNumber.Value` for NextRound operations
2. Add defensive validation in `ProcessNextRound` before calling `AddRoundInformation`
3. Add monitoring/alerts for TermNumber desync detection

**Test Cases:**
1. Test NextRound with TermNumber != currentTermNumber (should fail validation)
2. Test NextRound with negative TermNumber (should fail validation)
3. Test NextRound with TermNumber + 1 (should fail validation)
4. Test that legitimate NextRound with correct TermNumber still succeeds

### Proof of Concept

**Initial State:**
- `State.CurrentTermNumber.Value = 5`
- `State.CurrentRoundNumber.Value = 100`
- `State.Rounds[100].TermNumber = 5`
- Attacker is a legitimate miner in current miner list

**Attack Steps:**

1. **Attacker crafts malicious NextRoundInput:**
   - Set `RoundNumber = 101` (correct increment)
   - Set `TermNumber = -1000000` (malicious negative value)
   - Set all other fields correctly (RealTimeMinersInformation, etc.)
   - Set all InValues to null (to pass validation)

2. **Attacker submits NextRound transaction:**
   - Transaction passes `PreCheck` (attacker is in miner list)
   - Validation runs:
     - `MiningPermissionValidationProvider`: ✓ PASS (attacker is miner)
     - `TimeSlotValidationProvider`: ✓ PASS (assuming correct timing)
     - `ContinuousBlocksValidationProvider`: ✓ PASS (assuming no continuous blocks issue)
     - `NextRoundMiningOrderValidationProvider`: ✓ PASS (assuming correct orders)
     - `RoundTerminateValidationProvider.ValidationForNextRound`: ✓ PASS (only checks RoundNumber and InValues)
   - Execution runs:
     - `ProcessNextRound` calls `AddRoundInformation(nextRound)`
     - `State.Rounds[101]` is set with `TermNumber = -1000000`
     - `State.CurrentRoundNumber.Value = 101` updated
     - `State.CurrentTermNumber.Value = 5` UNCHANGED

3. **State after attack:**
   - `State.CurrentTermNumber.Value = 5` (legitimate)
   - `State.Rounds[101].TermNumber = -1000000` (corrupted)
   - BaseRound fetched in next validation will have `TermNumber = -1000000`

4. **Subsequent NextTerm attempts fail:**
   - Honest miner attempts NextTerm when term should change
   - Validation: `BaseRound.TermNumber + 1 == extraData.Round.TermNumber`
     - Requires: `-1000000 + 1 == -999999`
   - Execution: `State.CurrentTermNumber + 1 == termNumber`
     - Requires: `5 + 1 == 6`
   - No value satisfies both: `-999999 ≠ 6`
   - NextTerm is permanently blocked

**Expected vs Actual Result:**
- **Expected**: NextRound validation rejects TermNumber changes
- **Actual**: NextRound with arbitrary TermNumber passes validation and corrupts state, permanently blocking term transitions

**Success Condition:**
Attack succeeds when `State.Rounds[n].TermNumber ≠ State.CurrentTermNumber.Value` after a NextRound transaction, making all subsequent NextTerm transitions impossible.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L98-105)
```csharp
    private bool TryToUpdateTermNumber(long termNumber)
    {
        var oldTermNumber = State.CurrentTermNumber.Value;
        if (termNumber != 1 && oldTermNumber + 1 != termNumber) return false;

        State.CurrentTermNumber.Value = termNumber;
        return true;
    }
```
