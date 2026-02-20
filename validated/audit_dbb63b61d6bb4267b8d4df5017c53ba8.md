# Audit Report

## Title
Missing Authorization Check for Extra Block Slot Tiny Block Production

## Summary
The `TimeSlotValidationProvider.CheckMinerTimeSlot()` method fails to verify that a miner producing tiny blocks before their expected mining time is actually authorized as the `ExtraBlockProducerOfPreviousRound`. This allows any miner in the current round to produce blocks claiming extra block slot privileges, bypassing the consensus invariant that only the designated extra block producer can mine during this time slot.

## Finding Description

The vulnerability exists in the time slot validation logic. When a miner's actual mining time is before their expected mining time, the code assumes the miner is producing tiny blocks for the previous extra block slot and only validates the timing. [1](#0-0) 

However, it never checks if the sender is actually the authorized extra block producer for the previous round. The proper authorization check exists in the `IsCurrentMiner()` view method: [2](#0-1) 

The consensus command generation also enforces this authorization correctly before allowing TinyBlock behavior: [3](#0-2) 

However, during block validation, only basic validation providers are applied to all consensus behaviors: [4](#0-3) 

Critically, for `TinyBlock` behavior, no additional authorization validation provider is added beyond the basic ones: [5](#0-4) 

The `MiningPermissionValidationProvider` only checks if the miner is in the miner list, not if they're authorized for the specific time slot: [6](#0-5) 

Similarly, the `PreCheck()` method only validates miner list membership: [7](#0-6) 

Finally, `ProcessTinyBlock()` processes the block without any authorization check: [8](#0-7) 

The attack path: when generating consensus extra data for a tiny block, the miner's actual mining time is set to the current block time: [9](#0-8) 

During validation, the provided actual mining times are added to the base round: [10](#0-9) 

This allows an unauthorized miner to:
1. Produce a block before their expected time slot (before round start)
2. Set `Behaviour = TinyBlock` in consensus header
3. Pass validation because `TimeSlotValidationProvider` checks timing but not authorization
4. Mine outside their designated time slot and earn extra block rewards

## Impact Explanation

This vulnerability has **HIGH** impact on consensus integrity:

1. **Consensus Invariant Violation**: The fundamental consensus rule that only `ExtraBlockProducerOfPreviousRound` can mine during the previous extra block slot period is violated. This breaks the predictable mining schedule that AEDPoS consensus relies on.

2. **Unfair Reward Allocation**: Unauthorized miners can earn additional block production rewards by mining more blocks than their fair share, directly impacting the economic incentives of the consensus mechanism.

3. **Potential Consensus Disruption**: If multiple miners simultaneously attempt to produce blocks in the extra block slot, it could cause forks or consensus delays, affecting finality and cross-chain operations.

4. **Mining Schedule Corruption**: The violation disrupts LIB (Last Irreversible Block) calculations which depend on predictable mining patterns, potentially affecting cross-chain merkle proof validations.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood:

**Exploitability**: Any miner in the current validator set can exploit this. The attacker only needs:
- Valid miner credentials (already a consensus participant)
- Ability to control block production timing
- No special privileges beyond normal miner capabilities

**Attack Complexity**: LOW - The attacker simply:
1. Produces a block before their expected mining time
2. Sets `Behaviour = TinyBlock` in consensus data
3. Times the block before the round start time

**Feasibility**: The conditions are always present during normal operations:
- Current round is active (normal state)
- Attacker is an active miner (realistic)
- Timing window exists between rounds (by design)

**Economic Rationality**: Block production rewards make this economically attractive with minimal cost beyond normal mining operations.

## Recommendation

Add an authorization check in the `TimeSlotValidationProvider.CheckMinerTimeSlot()` method when a miner is producing tiny blocks before their expected time (when `latestActualMiningTime < expectedMiningTime`):

```csharp
if (latestActualMiningTime < expectedMiningTime)
{
    // Which means this miner is producing tiny blocks for previous extra block slot.
    // Must verify the miner is authorized as ExtraBlockProducerOfPreviousRound
    if (validationContext.BaseRound.ExtraBlockProducerOfPreviousRound != validationContext.SenderPubkey)
        return false;
    
    return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
}
```

This ensures only the designated extra block producer can mine during the extra block time slot, maintaining the consensus invariant.

## Proof of Concept

A malicious miner not designated as `ExtraBlockProducerOfPreviousRound` can exploit this by:

1. Monitoring the current round information to identify when a new round starts
2. Before their own expected mining time and before the round start time, producing a block
3. Setting the consensus behavior to `TinyBlock` in the block header
4. The block passes all validation checks despite the miner not being authorized for the extra block slot
5. The miner's `ProducedBlocks` and `ProducedTinyBlocks` counters are incremented, earning them additional rewards

The vulnerability can be verified by reviewing the validation flow where no authorization check exists for TinyBlock behavior against the `ExtraBlockProducerOfPreviousRound` field, while command generation and view methods correctly enforce this restriction.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L46-48)
```csharp
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L162-163)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L44-44)
```csharp
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```
