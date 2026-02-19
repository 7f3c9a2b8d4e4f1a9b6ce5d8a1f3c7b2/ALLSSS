### Title
Missing Miner List Validation in NextRound Allows Consensus Schedule Corruption

### Summary
The `ValidationForNextRound()` function only validates that the round number is correctly incremented and that all InValues are null, but completely fails to validate that the miner list in the provided next round matches the current round's miner list. This allows any current miner to craft a malicious NextRound with an arbitrary miner list (adding/removing miners or changing identities), pass all validations, and corrupt the consensus miner schedule.

### Finding Description

The vulnerability exists in the `RoundTerminateValidationProvider.ValidationForNextRound()` function which performs incomplete validation for NextRound behavior: [1](#0-0) 

The validation only checks two conditions:
1. Round number is incremented by exactly 1
2. All miners' InValues are null

**Critical Missing Check:** The function does NOT validate that the miner list (the keys in `RealTimeMinersInformation`) in the provided next round matches the current round's miner list.

For NextRound behavior (as opposed to NextTerm), the miner list should remain IDENTICAL to the current round - only the order should change based on `FinalOrderOfNextRound`. However, no validation enforces this invariant.

The validation provider list for NextRound behavior shows the other validators also fail to check miner list integrity: [2](#0-1) 

- `NextRoundMiningOrderValidationProvider` only validates internal consistency of FinalOrderOfNextRound within the provided round: [3](#0-2) 

- `MiningPermissionValidationProvider` only checks if the sender is in the BaseRound (current round), not whether the provided round's miner list is valid: [4](#0-3) 

Once validation passes, `ProcessNextRound` blindly accepts the malicious miner list and saves it to state: [5](#0-4) 

The `NextRoundInput.ToRound()` conversion performs no validation: [6](#0-5) 

The legitimate next round generation shows that the miner list should be derived from the CURRENT round's miners: [7](#0-6) 

Post-execution validation in `ValidateConsensusAfterExecution` does NOT protect against this because it only validates AFTER the malicious round is already saved to state, and it compares the saved state with the header (which now match): [8](#0-7) 

### Impact Explanation

**Consensus/Cross-Chain Integrity Impact:**
- Complete corruption of the consensus miner schedule for all subsequent rounds
- Unauthorized miners can be added to produce blocks and receive rewards
- Legitimate miners can be removed, breaking consensus participation
- Attacker can dominate consensus by adding multiple controlled keys
- Could lead to chain fork, halt, or 51% attack scenario

**Who is Affected:**
- All network participants relying on consensus integrity
- Legitimate miners who could be excluded
- Token holders whose assets depend on chain security
- Cross-chain operations relying on accurate miner information

**Severity Justification:**
This is a CRITICAL vulnerability because:
1. It breaks the fundamental consensus invariant of miner schedule integrity
2. It requires only a single malicious miner (already in the current round) to execute
3. The corruption persists across all future rounds until a NextTerm occurs
4. It enables complete consensus takeover by a single compromised miner

### Likelihood Explanation

**Reachable Entry Point:**
The `NextRound` method is a public entry point callable by any current miner: [9](#0-8) 

**Attacker Capabilities:**
- Must be an existing miner in the current round (realistic - could be a compromised node)
- Must wait for their designated time slot (always occurs during normal operation)
- Must craft a valid `NextRoundInput` with correct round number and null InValues (trivial)

**Execution Practicality:**
1. Attacker waits for their time slot in current round
2. Crafts `NextRoundInput` with:
   - `RoundNumber = CurrentRound + 1` ✓
   - All `InValue` fields = null ✓
   - `RealTimeMinersInformation` = arbitrary miner list (attacker's keys, removed competitors, etc.)
3. Calls `NextRound(maliciousInput)`
4. Passes all validation checks
5. Malicious round saved to state

**Detection/Operational Constraints:**
- Attack is instant and irreversible once executed
- No alerts or protections in place to detect miner list manipulation
- Other honest miners would see corrupted round but cannot revert it
- Would require chain reorganization or emergency intervention to fix

**Probability:** HIGH - Any single compromised or malicious miner can execute this attack during their normal time slot with near certainty of success.

### Recommendation

Add explicit validation to ensure the miner list in NextRound matches the current round's miner list:

1. **In `RoundTerminateValidationProvider.ValidationForNextRound()`**, add validation after line 34:
   - Verify that `validationContext.ProvidedRound.RealTimeMinersInformation.Keys` contains exactly the same public keys as `validationContext.BaseRound.RealTimeMinersInformation.Keys`
   - Check that counts match: `providedKeys.Count == baseKeys.Count`
   - Check that all keys exist: `providedKeys.All(k => baseKeys.Contains(k))`

2. **Create a new validation provider** `NextRoundMinerListValidationProvider` that validates:
   ```
   - Miner count unchanged
   - All current round miners present in next round
   - No new miners added
   - Only Order and timing fields changed
   ```

3. **Add to validation provider list** in `ValidateBeforeExecution` for NextRound behavior

4. **Add test cases** to verify:
   - NextRound with added miner fails validation
   - NextRound with removed miner fails validation
   - NextRound with replaced miner fails validation
   - NextRound with correct miner list (just reordered) succeeds

5. **For NextTerm**, ensure miner list changes are validated against Election Contract results: [10](#0-9) 

### Proof of Concept

**Required Initial State:**
- Blockchain running with N miners in current round R
- Attacker controls Miner M (one of the N miners)
- Current round has round number R_num

**Attack Steps:**
1. Attacker M waits for their time slot in round R
2. Attacker crafts malicious `NextRoundInput`:
   ```
   RoundNumber = R_num + 1
   RealTimeMinersInformation = {
     "AttackerKey1": MinerInRound { Order: 1, InValue: null, ... },
     "AttackerKey2": MinerInRound { Order: 2, InValue: null, ... },
     "AttackerKey3": MinerInRound { Order: 3, InValue: null, ... }
   }
   // Original N miners replaced with attacker's 3 keys
   ```
3. Attacker calls `NextRound(maliciousInput)` during their time slot
4. Validation checks pass:
   - `MiningPermissionValidationProvider`: M is in current round ✓
   - `TimeSlotValidationProvider`: Within M's time slot ✓
   - `RoundTerminateValidationProvider`: Round number = R_num + 1 ✓, all InValues null ✓
   - `NextRoundMiningOrderValidationProvider`: FinalOrderOfNextRound internally consistent ✓
5. `ProcessNextRound` saves malicious round to `State.Rounds[R_num + 1]`
6. Next round now has only attacker's 3 keys as miners

**Expected Result (Secure):** 
Validation should FAIL with "Miner list in next round does not match current round"

**Actual Result (Vulnerable):**
Validation PASSES and malicious round is saved, corrupting consensus schedule for all future rounds until NextTerm

**Success Condition:**
After attack, querying `State.Rounds[R_num + 1].RealTimeMinersInformation.Keys` returns only attacker's keys instead of the original N miners, proving consensus corruption.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-37)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
