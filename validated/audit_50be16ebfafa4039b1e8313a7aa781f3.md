# Audit Report

## Title
Missing Extra Block Producer Validation Allows Unauthorized Round Termination

## Summary
The AEDPoS consensus contract fails to validate that only the designated Extra Block Producer (EBP) can execute round/term termination transactions. Any miner whose time slot has passed can submit NextRound or NextTerm blocks that will pass all validation checks, allowing them to usurp the EBP role and gain special mining privileges in subsequent rounds.

## Finding Description

The AEDPoS consensus mechanism designates one miner per round as the Extra Block Producer, responsible for producing the final block that terminates the round. However, the validation logic does not enforce this invariant.

**Root Cause - Missing EBP Authorization Check:**

When generating consensus behavior, any miner whose time slot has passed receives NextRound/NextTerm behavior without EBP verification: [1](#0-0) 

**Unauthorized EBP Assignment:**

When generating consensus extra data for round termination, the requesting miner is unconditionally assigned as the previous round's EBP without validating they hold this role: [2](#0-1) 

**Validation Gaps:**

The validation providers check various consensus rules but never verify EBP authorization:

1. `MiningPermissionValidationProvider` only verifies the sender is in the miner list: [3](#0-2) 

2. `RoundTerminateValidationProvider` only validates round/term number increments: [4](#0-3) 

3. `TimeSlotValidationProvider` for NextRound behavior only validates the new round's internal structure: [5](#0-4) 

4. `PreCheck()` only verifies the sender is in current or previous miner lists: [6](#0-5) 

**Designated EBP Determination:**

The legitimate EBP is deterministically calculated per round and marked with `IsExtraBlockProducer = true`, but this flag is never checked during validation: [7](#0-6) 

## Impact Explanation

**Consensus Invariant Violation:**
The fundamental consensus rule that only the designated EBP can terminate rounds is broken. The wrong miner is permanently recorded as `ExtraBlockProducerOfPreviousRound` in the blockchain state.

**Privilege Escalation:**
The miner who produces the unauthorized termination block gains EBP privileges in the next round, specifically:
- Ability to produce additional tiny blocks beyond normal limits [8](#0-7) 

- Permission to mine before the next round officially starts [9](#0-8) 

**Consensus Determinism Compromise:**
The designated EBP loses their role, and multiple miners could simultaneously attempt round termination, potentially causing consensus confusion or chain forks.

## Likelihood Explanation

**Attack Feasibility:**
Any active miner can exploit this vulnerability once their time slot passes. No special privileges, compromised keys, or complex attack setup is required.

**Triggering Conditions:**
- Attacker is an active miner (normal operational state)
- Attacker's time slot has passed
- Designated EBP is delayed, offline, or experiencing network issues

**Practical Execution:**
The exploit occurs through standard consensus operations. When the designated EBP is unavailable or delayed, any other miner can:
1. Request consensus command and receive NextRound/NextTerm behavior
2. Generate and sign the round termination block
3. Have their block accepted by all validation checks
4. Be recorded as the EBP despite not being designated

**Detection Difficulty:**
The unauthorized termination appears legitimate since all validation passes. Detection requires comparing who SHOULD have been the EBP (via the deterministic calculation) versus who actually produced the termination block.

## Recommendation

Add EBP authorization validation before accepting round/term termination blocks. The validation should verify that the block producer matches the designated EBP for the current round.

Implement a new validation provider or extend existing ones:

```csharp
// In ValidateBeforeExecution for NextRound/NextTerm behaviors
if (extraData.Behaviour == AElfConsensusBehaviour.NextRound || 
    extraData.Behaviour == AElfConsensusBehaviour.NextTerm)
{
    var designatedEBP = baseRound.RealTimeMinersInformation.Values
        .FirstOrDefault(m => m.IsExtraBlockProducer)?.Pubkey;
    
    if (designatedEBP != validationContext.SenderPubkey)
    {
        return new ValidationResult 
        { 
            Message = "Only the designated extra block producer can terminate the round." 
        };
    }
}
```

Additionally, validate that the block timestamp aligns with the expected extra block mining time: [10](#0-9) 

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a round with multiple miners where Miner A is the designated EBP
2. Advance time past Miner B's time slot (but Miner B is NOT the EBP)
3. Have Miner B request consensus command → receives NextRound behavior
4. Have Miner B generate and submit NextRound transaction
5. Verify the transaction passes all validation checks
6. Verify Miner B is recorded as `ExtraBlockProducerOfPreviousRound` despite not being designated
7. Verify Miner B gains EBP privileges in the next round

The test would confirm that no validation prevents non-EBP miners from terminating rounds when the conditions allow.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-47)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L59-66)
```csharp
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```
