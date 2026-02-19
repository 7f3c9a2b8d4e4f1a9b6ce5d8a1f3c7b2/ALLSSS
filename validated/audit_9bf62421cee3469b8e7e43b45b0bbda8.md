# Audit Report

## Title
Unauthorized Round Termination Allows Miners to Steal Extra Block Producer Privileges

## Summary
The AEDPoS consensus contract fails to validate that the miner producing a `NextRound` block is the designated extra block producer. When `TinyBlockCommandStrategy` switches behavior to `NextRound`, any miner whose time slot has passed can terminate the round and automatically gain `ExtraBlockProducerOfPreviousRound` status, granting unfair block production privileges including the ability to mine additional blocks and produce blocks before the next round officially starts.

## Finding Description

The vulnerability exists in the consensus command generation and validation flow where the designated extra block producer role is not enforced during round termination.

**Behavior Switch Without Authorization Check:**
When a miner's arranged mining time exceeds their time slot, `TinyBlockCommandStrategy` automatically switches to `TerminateRoundCommandStrategy` and returns a `NextRound` command: [1](#0-0) 

Any miner whose time slot has passed receives `NextRound` behavior from the consensus behavior provider: [2](#0-1) 

**Unchecked Privilege Assignment:**
When generating `NextRound` extra data, the contract automatically assigns `ExtraBlockProducerOfPreviousRound` to whoever produces the NextRound block, without verifying they are authorized: [3](#0-2) 

**Inadequate Validation:**
The validation providers for `NextRound` behavior do not verify the miner is the designated extra block producer:

- `MiningPermissionValidationProvider` only checks if sender is in the miner list: [4](#0-3) 

- `RoundTerminateValidationProvider` only validates round number increment and data structure: [5](#0-4) 

- `PreCheck()` only verifies the miner is in current or previous round: [6](#0-5) 

**Stolen Privileges:**
Miners with `ExtraBlockProducerOfPreviousRound` status gain unfair advantages including the ability to mine `_maximumBlocksCount + blocksBeforeCurrentRound` blocks instead of just `_maximumBlocksCount`: [7](#0-6) 

They can also produce tiny blocks before the current round officially starts: [8](#0-7) 

**Bypassed Designation:**
The extra block producer is properly calculated during round generation using signature-based randomness to ensure fair rotation: [9](#0-8) [10](#0-9) 

However, this designation is completely bypassed as any miner can claim the privileges by producing a NextRound block first.

## Impact Explanation

**Consensus Integrity Violation:**
This vulnerability breaks the core consensus invariant of fair miner rotation and proper round transitions. The designated extra block producer role exists specifically to ensure fair distribution of the privilege to terminate rounds and gain additional mining capacity. By allowing any miner to claim these privileges, the consensus mechanism's fairness is compromised.

**Unfair Block Production Distribution:**
Attackers can systematically gain the ability to mine more blocks than intended (`_maximumBlocksCount + blocksBeforeCurrentRound` instead of `_maximumBlocksCount`), giving them disproportionate block rewards and influence over the blockchain state. This timing advantage allows them to produce blocks before rounds officially start, further increasing their unfair advantage.

**Repeated Exploitation:**
The vulnerability is repeatable across multiple rounds. A miner can monitor their consensus commands and exploit the behavior switch whenever their time slot passes, repeatedly claiming extra block producer privileges that should rotate fairly among all miners.

## Likelihood Explanation

**High Probability:**
The vulnerability has a high likelihood of exploitation because:

1. **Automatic Trigger:** The behavior switch from `TinyBlock` to `NextRound` occurs automatically in the command strategy logic when timing conditions are met. No manual manipulation is needed.

2. **Minimal Requirements:** Any valid miner in the current round can exploit this. No special governance permissions or elevated privileges are required.

3. **Natural Occurrence:** The condition where a miner's arranged mining time exceeds their time slot happens naturally during normal consensus operations, making the exploit opportunity frequent.

4. **Undetectable:** The produced `NextRound` blocks appear legitimate since they pass all validation checks. Only detailed analysis comparing who SHOULD have terminated the round versus who actually did would reveal the issue.

5. **Race Condition Advantage:** When multiple miners' time slots have passed, they can race to produce the NextRound block, with the winner claiming the extra privileges.

## Recommendation

Add validation to enforce that only the designated extra block producer can produce `NextRound` blocks:

1. **Add Extra Block Producer Validation Provider:**
Create a new validation provider specifically for `NextRound` and `NextTerm` behaviors that checks if the sender is the designated extra block producer:

```csharp
public class ExtraBlockProducerValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var extraData = validationContext.ExtraData;
        
        if (extraData.Behaviour != AElfConsensusBehaviour.NextRound && 
            extraData.Behaviour != AElfConsensusBehaviour.NextTerm)
        {
            validationResult.Success = true;
            return validationResult;
        }
        
        // Get the designated extra block producer from current round
        var supposedExtraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation
            .FirstOrDefault(m => m.Value.IsExtraBlockProducer).Key;
            
        if (string.IsNullOrEmpty(supposedExtraBlockProducer))
        {
            validationResult.Message = "No extra block producer designated in current round.";
            return validationResult;
        }
        
        if (validationContext.SenderPubkey != supposedExtraBlockProducer)
        {
            validationResult.Message = $"Only designated extra block producer {supposedExtraBlockProducer} can terminate the round.";
            return validationResult;
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

2. **Register the Validation Provider:**
Add the new provider to the validation chain in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new ExtraBlockProducerValidationProvider()); // Add this
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new ExtraBlockProducerValidationProvider()); // Add this
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

## Proof of Concept

A proof of concept would require a full AElf test environment with multiple miners. The test would:

1. Set up a round with multiple miners and designate a specific extra block producer
2. Advance time so that a different miner's time slot passes
3. Have that unauthorized miner produce a NextRound block
4. Verify that the unauthorized miner gains `ExtraBlockProducerOfPreviousRound` status
5. Verify that the unauthorized miner can mine additional blocks in the next round
6. Confirm that the designated extra block producer loses their intended privileges

The vulnerability is confirmed through code analysis showing that no validation prevents unauthorized miners from producing NextRound blocks and claiming extra block producer privileges.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L40-42)
```csharp
            return arrangedMiningTime > currentTimeSlotEndTime
                ? new TerminateRoundCommandStrategy(CurrentRound, Pubkey, CurrentBlockTime, false)
                    .GetAEDPoSConsensusCommand() // The arranged mining time already beyond the time slot.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-82)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L178-178)
```csharp
        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-34)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-65)
```csharp
        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```
