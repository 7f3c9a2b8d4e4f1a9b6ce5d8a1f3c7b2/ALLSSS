### Title
Term Number Inconsistency in NextRound Validation Allows Consensus State Corruption

### Summary
The `RoundTerminateValidationProvider.ValidationForNextRound()` validator does not verify that the term number remains unchanged during NextRound transitions, while no other validator in the pipeline performs this check. This coordination gap allows a malicious miner to include an incorrect term number in NextRound consensus data, which passes all validations but creates permanent state inconsistency between `State.CurrentTermNumber.Value` and the term number stored in the Round object, corrupting consensus state integrity.

### Finding Description

**Root Cause:**
The `ValidationForNextRound()` method only validates round number increment and InValue nullness, but completely omits term number validation for NextRound behavior. [1](#0-0) 

**Validation Pipeline Gap:**
For NextRound behavior, the validation pipeline assembles validators in a specific order, but none check term number consistency: [2](#0-1) 

The validators run sequentially with fail-fast semantics: [3](#0-2) 

**Execution Path Issue:**
When NextRound executes, it converts the input (containing the malicious term number) to a Round object and stores it directly without validating term number: [4](#0-3) 

The critical issue: `ProcessNextRound` updates `State.CurrentRoundNumber` but never calls `TryToUpdateTermNumber`, leaving `State.CurrentTermNumber.Value` at the old value while the stored Round object contains the malicious term number. [5](#0-4) 

**After-Execution Validation Bypass:**
The post-execution validation compares round hashes but both the header and current state contain the same malicious term number, so validation passes: [6](#0-5) 

The hash includes term number, but since both sides match (both have the wrong value), the check passes: [7](#0-6) 

**How Current Round is Retrieved:**
The validation retrieves the current round using `State.CurrentRoundNumber.Value` as the key, which returns the Round object with the malicious term number: [8](#0-7) 

### Impact Explanation

**Consensus State Corruption:**
After a successful attack, the consensus state becomes permanently inconsistent:
- `State.CurrentTermNumber.Value` remains at the correct old term number (e.g., 2)
- `State.Rounds[currentRound].TermNumber` contains the malicious incremented term number (e.g., 3)

**Cross-Contract Coordination Failure:**
The validation context passed to validators uses `State.CurrentTermNumber.Value`: [9](#0-8) 

This creates a mismatch where future validations and consensus logic receive inconsistent term information, potentially causing:
1. Incorrect term transition detection
2. Election contract synchronization issues (uses `State.CurrentTermNumber.Value`)
3. Reward distribution errors tied to term boundaries
4. Treasury release timing problems [10](#0-9) 

**Severity Justification:**
Medium severity - while this doesn't directly steal funds, it corrupts critical consensus state that governs:
- Miner election transitions
- Reward distribution timing  
- Cross-contract consensus synchronization
- Round/term boundary integrity

The inconsistency persists permanently and can cascade into more serious consensus failures.

### Likelihood Explanation

**Attacker Capabilities:**
Any miner scheduled to produce the extra block (NextRound behavior) can execute this attack. The consensus extra data is included in the block header by the block producer, who can modify it arbitrarily before broadcasting.

**Attack Complexity:**
Low complexity:
1. Wait for turn to produce NextRound extra block
2. Obtain legitimate NextRound consensus data via `GetConsensusExtraData`
3. Modify the `TermNumber` field in the returned Round structure
4. Include modified data in block header
5. Broadcast block [11](#0-10) 

**Feasibility Conditions:**
- Attacker must be a valid miner (but validation doesn't prevent this since they check mining permission first)
- No special permissions beyond normal miner status required
- Attack is deterministic and always succeeds
- No economic cost beyond normal block production

**Detection Constraints:**
The attack is difficult to detect because:
- Both before and after execution validations pass
- The inconsistency is between two different state variables
- No validation explicitly compares `State.CurrentTermNumber.Value` with `Round.TermNumber`
- Monitoring tools would need to specifically check for this state divergence

### Recommendation

**Immediate Fix:**
Add term number validation to `ValidationForNextRound()`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // NEW: Validate term number remains unchanged for NextRound
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Term number must not change during NextRound." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

**Invariant Check:**
Add assertion in `ProcessNextRound` to detect inconsistency:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // Assert term number consistency
    Assert(nextRound.TermNumber == currentRound.TermNumber, 
        "Term number must not change during NextRound.");
    
    // ... rest of processing
}
```

**Test Cases:**
1. Test NextRound with incremented term number - should fail validation
2. Test NextRound with decremented term number - should fail validation
3. Test NextRound with correct term number - should pass
4. Integration test verifying `State.CurrentTermNumber.Value` matches `State.Rounds[x].TermNumber` after NextRound execution

### Proof of Concept

**Initial State:**
- Current Round: 100, Term: 5
- `State.CurrentRoundNumber.Value = 100`
- `State.CurrentTermNumber.Value = 5`
- `State.Rounds[100].TermNumber = 5`
- Malicious miner scheduled for NextRound extra block

**Attack Steps:**
1. Malicious miner calls `GetConsensusExtraData` to obtain legitimate NextRound data
2. Modify returned `AElfConsensusHeaderInformation.Round.TermNumber` from 5 to 6
3. Create block with modified consensus extra data
4. Broadcast block to network

**Validation Flow:**
1. `ValidateConsensusBeforeExecution` called with modified extra data
2. `MiningPermissionValidationProvider` - PASS (attacker is valid miner)
3. `TimeSlotValidationProvider` - PASS (timing is correct)
4. `ContinuousBlocksValidationProvider` - PASS (block count OK)
5. `NextRoundMiningOrderValidationProvider` - PASS (mining order OK)
6. `RoundTerminateValidationProvider.ValidationForNextRound` - PASS (only checks round number and InValues, ignores term number)
7. All validations pass, transaction executes

**Execution Result:**
1. `ProcessNextRound` called with malicious input
2. `AddRoundInformation(nextRound)` stores Round 101 with TermNumber = 6
3. `TryToUpdateRoundNumber(101)` updates `State.CurrentRoundNumber.Value = 101`
4. `TryToUpdateTermNumber` is never called
5. `State.CurrentTermNumber.Value` remains at 5

**Post-Execution Validation:**
1. `ValidateConsensusAfterExecution` called
2. `TryToGetCurrentRoundInformation` returns `State.Rounds[101]` with TermNumber = 6
3. Compares hash of header round (TermNumber = 6) vs current round (TermNumber = 6)
4. Hashes match - validation passes

**Final State (Inconsistent):**
- `State.CurrentRoundNumber.Value = 101`
- `State.CurrentTermNumber.Value = 5` (INCORRECT - should be 5)
- `State.Rounds[101].TermNumber = 6` (INCORRECT - should be 5)
- **State corruption achieved**

**Success Condition:**
Query both values:
- `GetCurrentTermNumber()` returns 5 (from `State.CurrentTermNumber.Value`)
- `GetCurrentRoundInformation().TermNumber` returns 6 (from stored Round)
- Inconsistency proves successful attack

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L16-26)
```csharp
    public ValidationResult ValidateInformation(ConsensusValidationContext validationContext)
    {
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
        }

        return new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L91-97)
```csharp
    private bool TryToUpdateRoundNumber(long roundNumber)
    {
        var oldRoundNumber = State.CurrentRoundNumber.Value;
        if (roundNumber != 1 && oldRoundNumber + 1 != roundNumber) return false;
        State.CurrentRoundNumber.Value = roundNumber;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L420-435)
```csharp

        // Update snapshot of corresponding voting record by the way.
        State.VoteContract.TakeSnapshot.Send(new TakeSnapshotInput
        {
            SnapshotNumber = input.TermNumber,
            VotingItemId = State.MinerElectionVotingItemId.Value
        });

        State.CurrentTermNumber.Value = input.TermNumber.Add(1);

        var previousTermMinerList =
            State.AEDPoSContract.GetPreviousTermMinerPubkeyList.Call(new Empty()).Pubkeys.ToList();

        foreach (var pubkey in previousTermMinerList)
            UpdateCandidateInformation(pubkey, input.TermNumber, previousTermMinerList);

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
