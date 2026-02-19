### Title
Missing RoundId Validation Allows Bypass of Time Slot Checks for UpdateValue and TinyBlock Behaviors

### Summary
The `ValidateBeforeExecution` function fails to explicitly validate that `ProvidedRound.RoundId` matches `BaseRound.RoundId` for UpdateValue and TinyBlock consensus behaviors. This allows malicious miners to craft blocks with mismatched RoundIds, causing `TimeSlotValidationProvider` to skip critical time slot enforcement checks and only perform structural validation, enabling miners to produce blocks outside their assigned time slots.

### Finding Description

The vulnerability exists in the consensus validation flow across multiple files:

**Root Cause Location:** [1](#0-0) 

When processing UpdateValue or TinyBlock behaviors, the code calls `RecoverFromUpdateValue` or `RecoverFromTinyBlock` to update `baseRound` with data from `extraData.Round`, then creates a validation context. However, there is no explicit check that `ProvidedRound.RoundId` (from the block header's `extraData.Round`) must equal `BaseRound.RoundId` (from chain state).

**Critical Validation Bypass:** [2](#0-1) 

The `TimeSlotValidationProvider` compares RoundIds at line 14. When RoundIds don't match, it treats the block as a "new round" and only calls `CheckRoundTimeSlots()` instead of `CheckMinerTimeSlot()`. This is the critical bypass:

- **CheckMinerTimeSlot()** (lines 37-51) validates that the miner's `ActualMiningTimes` fall within their assigned time slot window
- **CheckRoundTimeSlots()** only validates structural properties (evenly spaced time slots) [3](#0-2) 

The `CheckRoundTimeSlots()` method only validates that mining intervals are positive and relatively equal—it does NOT validate whether the current block time falls within the miner's assigned time slot.

**RoundId Calculation:** [4](#0-3) 

RoundId is calculated as the sum of ExpectedMiningTime.Seconds or falls back to `RoundIdForValidation`. The `RecoverFrom` methods don't modify ExpectedMiningTimes, so `BaseRound.RoundId` remains correct while an attacker can provide any `RoundIdForValidation` value in their crafted Round.

**Missing Validation in Processing:** [5](#0-4) 

The `ProcessUpdateValue` method never validates that the input's round_id field matches the current round's RoundId. [6](#0-5) 

Similarly, `ProcessTinyBlock` has no RoundId validation.

**Documentation vs Implementation Gap:** [7](#0-6) 

The protobuf documentation explicitly states the round_id field is "To ensure the values to update will be apply to correct round by comparing round id," but no such comparison exists in the code.

### Impact Explanation

**Consensus Integrity Compromise:**
- Malicious miners can produce blocks outside their assigned time slots, breaking the fundamental AEDPoS time slot mechanism
- This allows miners to produce blocks when other miners should have exclusive mining rights
- Can lead to unfair block production where attackers produce more blocks than their allocated share

**Denial of Service:**
- Attackers can continuously produce blocks during other miners' time slots
- Legitimate miners may be blocked from producing blocks during their assigned windows
- Can disrupt the orderly round progression and consensus liveness

**Chain Stability:**
- Multiple miners producing blocks simultaneously (outside time slot constraints) can cause chain forks
- Break the assumption that only one miner mines at a given time
- Potential for consensus deadlocks or chain reorganizations

**Severity: HIGH** - This directly violates the "Correct round transitions and time-slot validation" invariant and compromises the core consensus mechanism's integrity.

### Likelihood Explanation

**Attacker Requirements:**
- Must be a valid miner in the current round (validated by PreCheck)
- This is a realistic constraint as any current miner can exploit this

**Attack Complexity: LOW**
1. Craft a Round object with all fields identical to current round except `RoundIdForValidation` set to `current_roundid + 1` or any other value
2. Create evenly-spaced ExpectedMiningTime values to pass `CheckRoundTimeSlots()`
3. Generate valid OutValue/Signature for UpdateValue behavior
4. Sign and submit the block

**Detection Difficulty:**
- The block appears valid from external perspective (signed by legitimate miner)
- Only detailed round validation logic analysis reveals the bypass
- No obvious anomalies in block structure

**Economic Cost:**
- Only requires standard block production resources
- No special infrastructure or tokens needed beyond being a miner
- High reward potential (additional block rewards, MEV opportunities)

**Execution Practicality:** [8](#0-7) 

The `ExtractConsensusExtraData` only validates that `SenderPubkey` matches the block signer—it does NOT validate Round contents, enabling attackers to inject arbitrary Round data.

**Probability: HIGH** - The vulnerability is easily exploitable by any current miner with standard capabilities.

### Recommendation

**1. Add Explicit RoundId Validation:**
Add validation in `ValidateBeforeExecution` before creating the validation context:

```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue || 
    extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
{
    if (extraData.Round.RoundId != baseRound.RoundId)
        return new ValidationResult { 
            Success = false, 
            Message = $"Round ID mismatch: provided {extraData.Round.RoundId}, expected {baseRound.RoundId}" 
        };
}
```

**2. Add Behavior-Specific Validation Provider:**
Create a new `RoundIdValidationProvider` that explicitly checks RoundId matches for UpdateValue/TinyBlock behaviors and add it to the validation provider list at line 65-75.

**3. Validate in ProcessConsensusInformation:**
Add defensive checks in `ProcessUpdateValue` and `ProcessTinyBlock` to validate the input's round_id field (even though validation should catch it earlier):

```csharp
Assert(updateValueInput.RoundId == currentRound.RoundId, 
       "Round ID mismatch in UpdateValue input");
```

**4. Add Test Cases:**
- Test that UpdateValue with wrong RoundId is rejected
- Test that TinyBlock with wrong RoundId is rejected  
- Test that time slot validation still works with correct RoundId
- Test edge cases with RoundId = 0, negative values, very large values

### Proof of Concept

**Initial State:**
- Current round in state: RoundNumber = 10, RoundId = 5000 (sum of all miners' ExpectedMiningTime.Seconds)
- Attacker is miner at position 3 with time slot 12:00:00 - 12:00:04
- Current block time: 12:00:08 (AFTER attacker's time slot expired)

**Attack Steps:**

1. **Craft Malicious Round:**
   - Copy current round structure
   - Set `RoundIdForValidation = 5001` (wrong value)
   - Keep all other fields including RoundNumber = 10
   - Create valid OutValue and Signature for UpdateValue

2. **Create Block:**
   - Set `extraData.Behaviour = AElfConsensusBehaviour.UpdateValue`
   - Set `extraData.Round = malicious_round`
   - Set `extraData.SenderPubkey = attacker_pubkey`
   - Sign block with attacker's key

3. **Validation Flow:**
   - `ValidateBeforeExecution` retrieves baseRound (RoundId = 5000)
   - Calls `baseRound.RecoverFromUpdateValue(extraData.Round, attacker_pubkey)`
   - Creates validation context with BaseRound.RoundId = 5000, ProvidedRound.RoundId = 5001
   - `TimeSlotValidationProvider` sees mismatch: 5001 ≠ 5000
   - Calls `ProvidedRound.CheckRoundTimeSlots()` instead of `CheckMinerTimeSlot()`
   - `CheckRoundTimeSlots()` only validates time slots are evenly spaced → PASS
   - Other validators pass (miner is in list, OutValue/Signature valid)

4. **Result:**
   - Block is accepted despite being produced at 12:00:08 (outside attacker's 12:00:00-12:00:04 slot)
   - `ProcessUpdateValue` updates the round state
   - Attacker successfully mined outside their time slot

**Expected Behavior:**
Block should be rejected with "Time slot already passed before execution" message.

**Actual Behavior:**
Block is accepted and processed, bypassing time slot enforcement.

**Success Condition:**
Attacker produces blocks outside assigned time slots without validation rejection, verified by checking ActualMiningTimes includes timestamps outside the miner's ExpectedMiningTime window.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-60)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-35)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L15-24)
```csharp
    public long RoundId
    {
        get
        {
            if (RealTimeMinersInformation.Values.All(bpInfo => bpInfo.ExpectedMiningTime != null))
                return RealTimeMinersInformation.Values.Select(bpInfo => bpInfo.ExpectedMiningTime.Seconds).Sum();

            return RoundIdForValidation;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** protobuf/aedpos_contract.proto (L194-201)
```text
message UpdateValueInput {
    // Calculated from current in value.
    aelf.Hash out_value = 1;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
    // Publish previous in value for validation previous signature and previous out value.
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```
