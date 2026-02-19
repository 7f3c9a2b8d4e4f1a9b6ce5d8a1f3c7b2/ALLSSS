### Title
Consensus Behavior Manipulation Allows Bypass of Critical Validators and Disruption of Consensus Integrity

### Summary
A malicious miner can manipulate the `Behaviour` field in consensus header information to switch from `UpdateValue` to `TinyBlock` behavior, bypassing critical validators (`UpdateValueValidationProvider` and `LibInformationValidationProvider`) and causing wrong consensus transaction execution. This breaks consensus random number generation, prevents LIB (Last Irreversible Block) height calculation, and can halt chain finality progression.

### Finding Description

**Root Cause:**
The `ValidateBeforeExecution` method in the consensus validation logic uses the `Behaviour` field from the deserialized `AElfConsensusHeaderInformation` to determine which validators to apply, but there is no validation that verifies the provided `Behaviour` matches what the consensus rules dictate. [1](#0-0) 

The `Behaviour` field is directly extracted from the block header's consensus extra data during deserialization: [2](#0-1) 

The consensus extra data comes from the block header, which is controlled by the block producer: [3](#0-2) 

**Why Protections Fail:**

1. **No Behavior Correctness Check:** The system never validates that the `Behaviour` value matches what `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` would return based on consensus rules: [4](#0-3) 

2. **Validator Selection Based on Untrusted Input:** When `Behaviour=TinyBlock`, the critical validators are never added: [1](#0-0) 

3. **Wrong Transaction Generated:** The manipulated `Behaviour` causes generation of `UpdateTinyBlockInformation` transaction instead of `UpdateValue`: [5](#0-4) 

4. **Different State Updates:** `ProcessTinyBlock` only updates minimal fields, skipping critical consensus data: [6](#0-5) 

Whereas `ProcessUpdateValue` updates `OutValue`, `Signature`, `PreviousInValue`, and calculates LIB height: [7](#0-6) 

### Impact Explanation

**Consensus Integrity Broken:**
- **OutValue and Signature never published:** These are critical for the consensus random number generation and verifiable delay function. Without them, the consensus random hash chain breaks.
- **Secret sharing disrupted:** The secret sharing mechanism for random number generation is bypassed.

**Chain Finality Stalled:**
- **LIB calculation skipped:** The Last Irreversible Block height calculation never executes (lines 268-282 of ProcessUpdateValue), preventing finality from advancing.
- **IrreversibleBlockFound event never fired:** Dependent systems waiting for finality confirmations are blocked.

**Validation Bypasses:**
The `UpdateValueValidationProvider` checks that would be bypassed: [8](#0-7) 

The `LibInformationValidationProvider` checks that would be bypassed: [9](#0-8) 

**Severity:** HIGH - This breaks fundamental consensus invariants, halts finality progression, and can lead to chain instability.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a valid miner in the current round (realistic for compromised miner)
- Must be in their designated time slot
- Has full control over block creation and consensus extra data

**Attack Complexity:** LOW
1. Miner receives proper consensus command with `Behaviour=UpdateValue`
2. Miner manually crafts trigger information with `Behaviour=TinyBlock`
3. Calls `GetConsensusExtraData` with manipulated trigger
4. Creates block with manipulated consensus extra data
5. Signs and broadcasts block

**Feasibility:** HIGH
- The attack requires only manipulation of a single enum field in the trigger information
- No cryptographic breaks required
- No timing constraints beyond normal mining
- Block passes all existing validations

**Detection Difficulty:** MEDIUM
- The block appears valid to all validators
- Monitoring systems would need to independently compute expected `Behaviour` and compare
- Symptoms (missing OutValue, stalled LIB) would appear but root cause may not be immediately obvious

**Economic Rationality:**
- Attacker pays only normal block production costs
- Can repeatedly exploit in their time slots
- High impact on chain operation with minimal cost

### Recommendation

**Immediate Fix:**
Add behavior correctness validation in `ValidateBeforeExecution` after line 60:

```csharp
// Validate that the provided Behaviour matches consensus rules
var expectedBehaviour = IsMainChain
    ? new MainChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
            GetMaximumBlocksCount(), Context.CurrentBlockTime, 
            GetBlockchainStartTimestamp(), State.PeriodSeconds.Value)
        .GetConsensusBehaviour()
    : new SideChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
            GetMaximumBlocksCount(), Context.CurrentBlockTime)
        .GetConsensusBehaviour();

if (extraData.Behaviour != expectedBehaviour && expectedBehaviour != AElfConsensusBehaviour.Nothing)
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = $"Behaviour mismatch: expected {expectedBehaviour}, got {extraData.Behaviour}" 
    };
}
```

**Invariant to Enforce:**
The `Behaviour` field in consensus extra data MUST match the behavior determined by consensus rules based on current round state, miner status, time slot, and block production counts.

**Test Cases:**
1. Test that UpdateValue blocks with Behaviour=TinyBlock are rejected
2. Test that TinyBlock blocks with Behaviour=UpdateValue are rejected  
3. Test behavior validation with edge cases (round transitions, extra block producer)
4. Verify LIB calculation always occurs for UpdateValue behaviors
5. Verify OutValue/Signature always present for UpdateValue behaviors

### Proof of Concept

**Initial State:**
- Chain running with multiple miners in current round
- Attacker is a valid miner with pubkey `ATTACKER_KEY`
- Current round number: 100
- Attacker's miner info: `OutValue == null` (hasn't mined this round)
- Current time is within attacker's time slot
- According to consensus rules, attacker should produce `UpdateValue` block

**Attack Steps:**

1. **Attacker receives consensus command:**
   - Calls `GetConsensusCommand` with their pubkey
   - Returns `ConsensusCommand` with `Behaviour=UpdateValue`

2. **Attacker crafts malicious trigger:**
   ```protobuf
   AElfConsensusTriggerInformation {
     pubkey: ATTACKER_KEY
     in_value: <valid hash>
     behaviour: TINY_BLOCK  // Manipulated!
   }
   ```

3. **Attacker generates manipulated extra data:**
   - Calls `GetConsensusExtraData` with malicious trigger
   - Returns `AElfConsensusHeaderInformation` with `Behaviour=TinyBlock`
   - Round data from `GetTinyBlockRound` (no OutValue/Signature)

4. **Attacker creates and broadcasts block:**
   - Block header includes manipulated consensus extra data
   - Signs with their key
   - Broadcasts to network

**Validation Results:**

*Expected (with fix):*
- `ValidateBeforeExecution` computes expected Behaviour=UpdateValue
- Compares with provided Behaviour=TinyBlock
- **Validation fails:** "Behaviour mismatch: expected UpdateValue, got TinyBlock"
- Block rejected

*Actual (without fix):*
- `ValidateBeforeExecution` uses Behaviour=TinyBlock
- Adds only basic validators (no UpdateValueValidationProvider, no LibInformationValidationProvider)
- **Validation passes**
- `UpdateTinyBlockInformation` transaction generated and executed
- Consensus state updated WITHOUT OutValue, Signature, or LIB calculation
- Chain finality stalled

**Success Condition:**
After attack, query consensus state:
- Attacker's `OutValue` remains `null` (should be filled)
- Attacker's `Signature` remains `null` (should be filled)  
- `ConfirmedIrreversibleBlockHeight` unchanged (should increase)
- Chain cannot progress consensus properly

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L135-163)
```csharp
        switch (behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                Context.LogDebug(() =>
                    $"Previous in value in extra data:{round.RealTimeMinersInformation[pubkey.ToHex()].PreviousInValue}");
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
                };
            case AElfConsensusBehaviour.TinyBlock:
                var minerInRound = round.RealTimeMinersInformation[pubkey.ToHex()];
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateTinyBlockInformation),
                            new TinyBlockInput
                            {
                                ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
                                ProducedBlocks = minerInRound.ProducedBlocks,
                                RoundId = round.RoundIdForValidation,
                                RandomNumber = randomNumber
                            })
                    }
                };
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L58-78)
```csharp
    public async Task<bool> ValidateBlockBeforeExecuteAsync(IBlock block)
    {
        if (block.Header.Height == AElfConstants.GenesisBlockHeight)
            return true;

        var consensusExtraData = _consensusExtraDataExtractor.ExtractConsensusExtraData(block.Header);
        if (consensusExtraData == null || consensusExtraData.IsEmpty)
        {
            Logger.LogDebug($"Invalid consensus extra data {block}");
            return false;
        }

        var isValid = await _consensusService.ValidateConsensusBeforeExecutionAsync(new ChainContext
        {
            BlockHash = block.Header.PreviousBlockHash,
            BlockHeight = block.Header.Height - 1
        }, consensusExtraData.ToByteArray());
        if (!isValid) return false;

        return ValidateTransactionCount(block);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L39-83)
```csharp
        public AElfConsensusBehaviour GetConsensusBehaviour()
        {
            // The most simple situation: provided pubkey isn't a miner.
            // Already checked in GetConsensusCommand.
//                if (!CurrentRound.IsInMinerList(_pubkey))
//                {
//                    return AElfConsensusBehaviour.Nothing;
//                }

            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
            }

            return GetConsensusBehaviourToTerminateCurrentRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```
