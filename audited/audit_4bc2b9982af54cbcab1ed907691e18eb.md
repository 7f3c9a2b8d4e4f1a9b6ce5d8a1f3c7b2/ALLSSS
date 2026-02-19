### Title
ActualMiningTimes Manipulation Enables Unauthorized Extra Block Production Rights

### Summary
A miner who terminated the previous round (ExtraBlockProducerOfPreviousRound) can inject forged timestamps into the ActualMiningTimes list to artificially inflate the `blocksBeforeCurrentRound` calculation. This manipulation bypasses production limits and grants unauthorized additional tiny block production rights, violating consensus fairness and enabling reward theft.

### Finding Description

The vulnerability exists in the consensus behaviour determination logic where `blocksBeforeCurrentRound` is calculated by counting ActualMiningTimes timestamps that occurred before the current round start time: [1](#0-0) 

This count is used to grant extra production rights to the miner who terminated the previous round: [2](#0-1) 

**Root Cause #1**: ActualMiningTimes are populated directly from user-provided input without validation that they equal Context.CurrentBlockTime: [3](#0-2) [4](#0-3) 

**Root Cause #2**: During validation, the provided Round object's ActualMiningTimes are blindly trusted and merged into the base round before validation occurs: [5](#0-4) [6](#0-5) 

**Root Cause #3**: ActualMiningTimes is intentionally excluded from Round hash validation, preventing detection of manipulation: [7](#0-6) [8](#0-7) 

**Why Existing Protections Fail**:
- `TimeSlotValidationProvider` only validates the latest ActualMiningTime against time slot boundaries, not whether it matches Context.CurrentBlockTime
- `UpdateValueValidationProvider` only checks OutValue/Signature/PreviousInValue fields, ignoring ActualMiningTime completely [9](#0-8) [10](#0-9) 

**Execution Path**:
1. Miner calls `GetConsensusExtraData` which legitimately adds Context.CurrentBlockTime to ActualMiningTimes
2. Miner modifies the returned Round object to inject additional forged timestamps from previous rounds
3. The simplified Round includes all ActualMiningTimes via `GetUpdateValueRound`/`GetTinyBlockRound`
4. During validation, `RecoverFromUpdateValue`/`RecoverFromTinyBlock` adds forged timestamps to base round
5. No validation detects the forgery because ActualMiningTimes is excluded from hash comparison
6. `ProcessUpdateValue`/`ProcessTinyBlock` persists the forged timestamp to state
7. On subsequent block production, `GetConsensusBehaviour` calculates inflated `blocksBeforeCurrentRound`
8. Miner receives unauthorized additional tiny block production rights [11](#0-10) [12](#0-11) 

### Impact Explanation

**Direct Harm**: A malicious miner gains unauthorized block production rights beyond their legitimate allocation, allowing them to:
- Produce additional tiny blocks and collect undeserved block rewards
- Dominate block production by extending their time slot artificially
- Control transaction ordering and inclusion for more blocks than permitted
- Potentially squeeze out legitimate blocks from other miners

**Quantified Impact**: If `_maximumBlocksCount` is 8 and a miner forges 3 timestamps before CurrentRound.GetRoundStartTime(), they gain `3 + 8 = 11` production rights instead of the legitimate 8, representing a 37.5% increase in block production and rewards.

**Affected Parties**: 
- Honest miners lose proportional block rewards and production opportunities
- Network consensus fairness is compromised
- Token economics are distorted through unfair reward distribution

**Severity Justification**: HIGH - This breaks a critical consensus invariant (miner schedule integrity and production limits), enables direct reward theft, and undermines the fairness guarantees of the AEDPoS consensus mechanism.

### Likelihood Explanation

**Attacker Capabilities**: Any miner who becomes ExtraBlockProducerOfPreviousRound (rotates among all miners) can execute this attack. The attacker only needs to:
- Modify the Round object in consensus extra data before block inclusion
- No special privileges or governance control required

**Attack Complexity**: LOW - The attack is straightforward:
1. Intercept the Round object returned by GetConsensusExtraData
2. Add forged Timestamp entries to ActualMiningTimes list
3. Include modified consensus extra data in block header

**Feasibility Conditions**: 
- Attacker must be selected as ExtraBlockProducerOfPreviousRound (happens regularly in round-robin fashion)
- Current round must not be first round of term (IsMinerListJustChanged check)
- Attacker has not yet exceeded modified limit

**Detection Constraints**: The attack is difficult to detect because:
- ActualMiningTimes is excluded from hash validation by design
- No cryptographic commitment binds ActualMiningTime to Context.CurrentBlockTime
- Validation occurs after forged data is merged into base round

**Probability**: MEDIUM-HIGH - The precondition (being ExtraBlockProducerOfPreviousRound) occurs naturally for all miners, and the attack is technically simple with minimal cost and high reward.

### Recommendation

**Code-Level Mitigation**:

1. Add strict validation in `ProcessUpdateValue` and `ProcessTinyBlock` to enforce ActualMiningTime equals Context.CurrentBlockTime:

```csharp
// In ProcessUpdateValue (line 243)
Assert(updateValueInput.ActualMiningTime == Context.CurrentBlockTime, 
    "ActualMiningTime must equal current block time");
minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);

// In ProcessTinyBlock (line 304)
Assert(tinyBlockInput.ActualMiningTime == Context.CurrentBlockTime,
    "ActualMiningTime must equal current block time");
minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
```

2. Alternatively, ignore user-provided ActualMiningTime and use Context.CurrentBlockTime directly:

```csharp
// In ProcessUpdateValue
minerInRound.ActualMiningTimes.Add(Context.CurrentBlockTime);

// In ProcessTinyBlock
minerInRound.ActualMiningTimes.Add(Context.CurrentBlockTime);
```

3. Add validation in `RecoverFromUpdateValue`/`RecoverFromTinyBlock` to verify only a single new timestamp is added and it's reasonable:

```csharp
// Verify only one new ActualMiningTime entry is provided
Assert(providedInformation.ActualMiningTimes.Count == minerInRound.ActualMiningTimes.Count + 1,
    "Exactly one new ActualMiningTime expected");
```

**Invariant Checks to Add**:
- ActualMiningTime in input MUST equal Context.CurrentBlockTime
- ActualMiningTimes list can only grow by 1 per block
- New ActualMiningTime must be >= latest existing ActualMiningTime (monotonic)

**Test Cases**:
- Test that UpdateValue/TinyBlock with ActualMiningTime != Context.CurrentBlockTime fails
- Test that providing multiple ActualMiningTimes in recovery fails  
- Test that blocksBeforeCurrentRound calculation with forged timestamps doesn't grant extra rights
- Test that a miner cannot exceed _maximumBlocksCount + legitimate blocksBeforeCurrentRound

### Proof of Concept

**Initial State**:
- Current round N+1, miners A, B, C with _maximumBlocksCount = 8
- Miner A was ExtraBlockProducerOfPreviousRound (terminated round N)
- Round N start time: 1000 seconds
- Round N+1 start time: 1100 seconds
- Current block time: 1110 seconds
- Miner A has 0 ActualMiningTimes in round N+1 currently

**Attack Steps**:
1. Miner A calls GetConsensusExtraData for UpdateValue behavior
2. GetConsensusExtraData returns Round object with ActualMiningTimes = [1110]
3. Miner A modifies Round object to inject forged timestamps:
   - ActualMiningTimes = [990, 995, 1000, 1110]
   - 990, 995, 1000 are from previous round (< 1100)
4. Miner A includes modified consensus extra data in block and produces block
5. ValidateBeforeExecution: RecoverFromUpdateValue adds all 4 timestamps to base round
6. TimeSlotValidationProvider: Validates latest timestamp (1110) is in time slot - PASSES
7. UpdateValueValidationProvider: Doesn't check ActualMiningTime - PASSES
8. Hash comparison: ActualMiningTimes excluded from hash - PASSES
9. ProcessUpdateValue: Adds ActualMiningTime (1110) to state - forged data now in state
10. Miner A produces next block:
    - GetConsensusBehaviour calculates: blocksBeforeCurrentRound = 3 (count of 990, 995, 1000)
    - Condition check: ActualMiningTimes.Count (4) + 1 < _maximumBlocksCount (8) + blocksBeforeCurrentRound (3)
    - 5 < 11 = TRUE
    - Returns AElfConsensusBehaviour.TinyBlock - Miner A can produce more blocks

**Expected Result**: Miner A should be limited to 8 tiny blocks total in current round

**Actual Result**: Miner A can produce 11 tiny blocks (8 + 3 forged), gaining 3 unauthorized additional production rights

**Success Condition**: Miner A successfully produces blocks 9, 10, 11 in the same round when they should have been blocked after block 8, demonstrating unauthorized extra production rights obtained through ActualMiningTimes manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L64-65)
```csharp
                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-243)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L303-304)
```csharp
        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-20)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-193)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L27-28)
```csharp
                    PreviousInValue = minerInRound.PreviousInValue,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
```
