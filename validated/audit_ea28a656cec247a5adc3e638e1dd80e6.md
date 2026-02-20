# Audit Report

## Title
Unauthorized Round Termination Due to Missing Extra Block Producer Validation in Side Chain Consensus

## Summary
The AEDPoS side chain consensus allows any miner whose time slot has passed to produce `NextRound` blocks that terminate the current round, instead of restricting this privilege to the designated extra block producer. This violates the documented protocol design and creates consensus integrity risks.

## Finding Description

The AEDPoS consensus protocol explicitly documents that "each miner produce his block in one time slot, then the extra block producer produce a block to terminate current round and confirm the mining order of next round." [1](#0-0) 

Each round deterministically assigns one miner as the extra block producer with the `IsExtraBlockProducer` flag. [2](#0-1) 

The extra block mining time is calculated to occur after all normal miners complete their time slots. [3](#0-2) 

**Vulnerability Part 1: Unconditional Behavior Assignment**

When any miner's time slot passes, `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` returns termination behavior without checking extra block producer status. [4](#0-3) 

For side chains, `SideChainConsensusBehaviourProvider` unconditionally returns `NextRound` behavior for any miner whose time slot passed. [5](#0-4) 

This behavior generates a `TerminateRoundCommandStrategy` that allows the miner to produce round-terminating blocks. [6](#0-5) 

**Vulnerability Part 2: Missing Validation**

The contract includes an `IsCurrentMiner()` method that correctly validates extra block producer status during the extra block time slot. [7](#0-6) 

However, this method is never invoked during consensus validation. The `ValidateBeforeExecution` method for `NextRound` behavior only adds structural validators that check miner list membership, not extra block producer authority. [8](#0-7) 

The `MiningPermissionValidationProvider` only verifies miner list membership, not extra block producer status. [9](#0-8) 

The `RoundTerminateValidationProvider` only checks round number correctness and InValue constraints. [10](#0-9) 

The `PreCheck()` method in execution only verifies miner list membership. [11](#0-10) 

## Impact Explanation

This vulnerability breaks a fundamental consensus invariant documented in the protocol design. The extra block producer is deterministically selected per round to ensure predictable round termination.

**Concrete Impacts:**

1. **Consensus Integrity Violation**: Multiple miners can simultaneously produce valid `NextRound` blocks once their time slots pass, even though the protocol specifies only the designated extra block producer should terminate rounds.

2. **Fork Risk**: If multiple miners produce competing `NextRound` blocks, different nodes may accept different blocks, causing temporary chain inconsistency or forks that must be resolved by the consensus layer.

3. **Loss of Determinism**: The designated extra block producer mechanism exists to provide deterministic, predictable round transitions. Allowing any miner to terminate rounds undermines this design goal.

4. **Premature Round Termination**: Miners whose time slots pass early can terminate the round before the designated extra block time, disrupting the intended timing and mining schedule.

## Likelihood Explanation

**Extremely High Likelihood** - This occurs naturally during normal side chain operations without requiring any malicious action:

1. **Attacker Prerequisites**: Only requires being a current miner in the side chain, which is normal operational status.

2. **Trigger Mechanism**: When a miner's time slot passes, they query for their next consensus command and automatically receive `NextRound` behavior.

3. **No Barriers**: No economic cost, special privileges, or attack-specific actions required. Uses standard consensus methods.

4. **Frequent Occurrence**: In a typical round with 4+ miners, 75%+ of miners (all except the final position) will have their time slots pass before the extra block time, causing them all to receive round-termination behavior.

## Recommendation

Add validation in `ValidateBeforeExecution` or `PreCheck` to verify that the sender is the designated extra block producer when processing `NextRound` behavior during the extra block time slot:

```csharp
// In ValidateBeforeExecution for NextRound behavior
if (extraData.Behaviour == AElfConsensusBehaviour.NextRound)
{
    // Check if current time is in extra block time slot
    if (Context.CurrentBlockTime >= validationContext.BaseRound.GetExtraBlockMiningTime())
    {
        // Verify sender is the designated extra block producer
        var extraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation
            .Single(m => m.Value.IsExtraBlockProducer).Key;
        
        if (validationContext.SenderPubkey != extraBlockProducer)
        {
            return new ValidationResult 
            { 
                Message = "Only the designated extra block producer can terminate the round." 
            };
        }
    }
}
```

Alternatively, modify `SideChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` to check if the calling miner is the designated extra block producer before returning `NextRound` behavior.

## Proof of Concept

The vulnerability can be demonstrated by setting up a side chain with multiple miners and observing that any miner whose time slot has passed can produce `NextRound` blocks:

1. Deploy side chain with 4 miners (A, B, C, D with D as extra block producer)
2. Wait for Miner A's time slot to pass
3. Miner A calls consensus command generation
4. Observe Miner A receives `NextRound` behavior despite not being the designated extra block producer
5. Miner A successfully produces a round-terminating block before Miner D (the designated extra block producer) has their extra block time slot
6. Validation passes even though Miner A should not have authority to terminate the round

**Notes:**

The missing validation is consistent across both main chain and side chain implementations, but the claim specifically focuses on side chains. The root cause is that the behavior provider and validation pipeline do not enforce the documented protocol requirement that only the designated extra block producer should terminate rounds. While the blockchain consensus layer may handle competing blocks, the lack of validation allows protocol-violating blocks to be considered valid, which undermines the deterministic design of the extra block producer mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L61-64)
```csharp
    ///     In current AElf Consensus design, each miner produce his block in one time slot, then the extra block producer
    ///     produce a block to terminate current round and confirm the mining order of next round.
    ///     So totally, the time of one round is:
    ///     MiningInterval * MinersCount + MiningInterval.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-82)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L20-23)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L39-44)
```csharp
            case AElfConsensusBehaviour.NextRound:
            case AElfConsensusBehaviour.NextTerm:
                return new ConsensusCommandProvider(
                        new TerminateRoundCommandStrategy(currentRound, pubkey, currentBlockTime,
                            behaviour == AElfConsensusBehaviour.NextTerm))
                    .GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L169-178)
```csharp
        var supposedExtraBlockProducer =
            currentRound.RealTimeMinersInformation.Single(m => m.Value.IsExtraBlockProducer).Key;

        // Check extra block time slot.
        if (Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime() &&
            supposedExtraBlockProducer == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]EXTRA");
            return true;
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
