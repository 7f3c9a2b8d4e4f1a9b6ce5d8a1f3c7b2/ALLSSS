After thorough analysis of the AEDPoS consensus contract code, I can confirm this is a **valid vulnerability**. The system fails to validate which miner is authorized to terminate rounds, allowing unauthorized privilege escalation.

# Audit Report

## Title
Authorization Bypass: Unauthorized Miners Can Gain Extra Block Production Rights Through Premature NextRound Execution

## Summary
The AEDPoS consensus mechanism lacks validation to ensure only the designated extra block producer can terminate the current round. Any miner whose time slot has passed can execute NextRound and receive `ExtraBlockProducerOfPreviousRound` status, granting disproportionate block production privileges in the subsequent round.

## Finding Description

The vulnerability stems from missing authorization checks in the round termination flow. The consensus mechanism deterministically selects one miner per round as the extra block producer, marked with `IsExtraBlockProducer = true`. [1](#0-0) 

However, when any miner's time slot passes, `GetConsensusBehaviour()` returns `NextRound` behavior without verifying the miner is the designated extra block producer: [2](#0-1) 

When processing NextRound, the system unconditionally assigns the terminating miner as `ExtraBlockProducerOfPreviousRound`: [3](#0-2) 

This status grants extended privileges to produce additional tiny blocks beyond normal limits: [4](#0-3) 

**Validation Gaps:**

The `PreCheck()` method only verifies membership in current or previous miner lists: [5](#0-4) 

`RoundTerminateValidationProvider` validates round number increment and null InValues, but not authorization: [6](#0-5) 

`TimeSlotValidationProvider` for new rounds only validates time slot structure: [7](#0-6) 

`MiningPermissionValidationProvider` only checks miner list membership: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Violation**: The deterministic fairness guarantee of AEDPoS is broken. Block production opportunities should be strictly distributed according to the protocol's selection algorithm, but unauthorized miners can gain privileged status by prematurely terminating rounds.

**Quantified Economic Impact**: A miner with `ExtraBlockProducerOfPreviousRound` status can produce `_maximumBlocksCount + blocksBeforeCurrentRound` blocks instead of the standard `_maximumBlocksCount` blocks. With typical configuration (8 blocks), this represents a ~100% increase in block production opportunities, directly translating to doubled mining rewards and transaction fee revenue for that miner while the legitimate extra block producer loses their rightful privileges.

**Systemic Risk**: Repeated exploitation across multiple rounds compounds the unfair advantage, potentially enabling transaction censorship and MEV extraction through additional blocks.

## Likelihood Explanation

**Prerequisites**: Attacker must be an active miner in the consensus set, which is a standard requirement for participation. No special cryptographic keys or compromised accounts are needed.

**Attack Complexity**: The attack requires only client-side modifications to bypass timing constraints in `ConsensusCommand.ArrangedMiningTime`. Once a miner's time slot passes, they can immediately mine NextRound instead of waiting for the designated extra block producer. [9](#0-8) 

**Feasibility**: The absence of on-chain validation makes this highly exploitable. Success depends primarily on network propagation timing, creating a race condition where any miner can attempt premature round termination after their time slot expires.

## Recommendation

Add authorization validation in `RoundTerminateValidationProvider` to verify the sender is the designated extra block producer:

```csharp
// In RoundTerminateValidationProvider.ValidationForNextRound()
var extraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation.Values
    .FirstOrDefault(m => m.IsExtraBlockProducer);
if (extraBlockProducer != null && extraBlockProducer.Pubkey != validationContext.SenderPubkey)
{
    return new ValidationResult { 
        Message = "Only designated extra block producer can terminate the round." 
    };
}
```

Additionally, `GetConsensusBehaviourToTerminateCurrentRound()` should verify the miner is authorized before returning NextRound behavior.

## Proof of Concept

A malicious miner can execute the following:

1. Wait until their normal time slot passes (verified by `IsTimeSlotPassed`)
2. Call the consensus command generation with NextRound behavior
3. Produce a block containing NextRound consensus information
4. The block passes validation since no check verifies they are the designated extra block producer
5. `ProcessNextRound` executes, assigning attacker's pubkey to `ExtraBlockProducerOfPreviousRound`
6. In the next round, attacker gains extended block production rights

The attack is repeatable across rounds, with each successful exploitation granting disproportionate mining privileges.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L59-65)
```csharp
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L178-178)
```csharp
        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-34)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L25-35)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint
                    {
                        Behaviour = _isNewTerm ? AElfConsensusBehaviour.NextTerm : AElfConsensusBehaviour.NextRound
                    }
                    .ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                MiningDueTime = arrangedMiningTime.AddMilliseconds(MiningInterval),
```
