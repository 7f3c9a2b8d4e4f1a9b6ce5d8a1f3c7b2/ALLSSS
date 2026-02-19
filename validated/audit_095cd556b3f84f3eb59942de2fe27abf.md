# Audit Report

## Title
Missing Authorization Check Allows Multiple Miners to Concurrently Trigger Round Transitions

## Summary
The AEDPoS consensus contract lacks authorization validation to ensure only the designated extra block producer can trigger `NextRound` transitions. Any miner in the current round can produce a block with a `NextRound` transaction once their time slot has passed, creating a race condition where multiple miners can simultaneously produce competing round transition blocks, leading to consensus forks and chain instability.

## Finding Description

The vulnerability exists in the consensus validation flow where round transitions are not properly authorized.

The `ValidateBeforeExecution` method applies multiple validation providers for `NextRound` behavior, but none verify that the block producer is the designated extra block producer authorized to terminate the current round: [1](#0-0) 

The validation providers used include:

**MiningPermissionValidationProvider** - only checks if sender is in the miner list, not their specific authorization as extra block producer: [2](#0-1) 

**TimeSlotValidationProvider** - for `NextRound` (new round), only validates the new round's time slot structure, but does not check WHO can trigger it: [3](#0-2) 

**RoundTerminateValidationProvider** - only checks that the round number increments by exactly 1, not authorization: [4](#0-3) 

While an `IsCurrentMiner()` method exists that properly checks extra block producer authorization during the extra block time slot: [5](#0-4) 

This check is never invoked during the validation flow before block execution. The `IsCurrentMiner` method is only used in other contracts (TokenContract, CrossChainContract) for fee-related authorization, not for consensus validation.

The consensus behavior provider determines that ANY miner whose time slot has passed can trigger round termination: [6](#0-5) [7](#0-6) 

When `NextRound` transactions execute, the only protections are:

1. `EnsureTransactionOnlyExecutedOnceInOneBlock()` - prevents multiple consensus transactions in the SAME block, not across competing blocks at the same height: [8](#0-7) 

2. `TryToUpdateRoundNumber()` - only checks round number increments by 1, which all competing blocks at the same height satisfy when reading from the same parent state: [9](#0-8) 

The extra block producer role is deterministically calculated using `CalculateNextExtraBlockProducerOrder()` and marked with the `IsExtraBlockProducer` flag: [10](#0-9) 

However, this designation is never enforced during validation, making it meaningless for authorization purposes.

## Impact Explanation

**Consensus Integrity Violation**: Multiple miners can simultaneously trigger round transitions, creating competing forks where each fork successfully transitions to the next round number but with potentially different internal state (different `ExtraBlockProducerOfPreviousRound`, different miner orders, different timestamps).

**Affected Parties**:
- All network participants face consensus instability and potential chain reorganizations
- Miners lose deterministic round transition leadership, undermining the consensus protocol design
- Cross-chain bridges may receive conflicting state proofs from competing forks
- Applications experience delayed finality and unpredictable state

**Severity Justification**: This violates the critical consensus invariant of "correct round transitions and time-slot validation, miner schedule integrity" by allowing unauthorized miners to trigger round transitions. The designated extra block producer role, determined by `CalculateNextExtraBlockProducerOrder()`, becomes meaningless if any miner whose time slot has passed can trigger the transition. This creates a fundamental race condition in the consensus mechanism at every round boundary.

## Likelihood Explanation

**Reachable Entry Point**: Any miner can call the consensus methods through block production via the ACS4 interface.

**Feasible Preconditions**:
1. Round in progress where all regular time slots have completed
2. Multiple miners simultaneously request their consensus commands via `GetConsensusCommand`
3. Network conditions (latency, partitions) allow multiple miners to produce blocks before one becomes dominant

**Attack Complexity**: Low - this occurs naturally without malicious intent when:
- Network latency causes miners to not immediately see each other's blocks
- Multiple miners reach the end of round simultaneously
- No coordinator explicitly designates the next block producer beyond the theoretical designation

**Probability**: High during normal operation at round boundaries, especially in geographically distributed networks or under network stress. Each round termination (which happens regularly throughout blockchain operation) is a potential race condition opportunity where multiple miners can validly produce competing NextRound blocks.

## Recommendation

Add an authorization validation provider for `NextRound` behavior that checks if the sender is the designated extra block producer. Create a new validation provider:

```csharp
public class ExtraBlockProducerAuthorizationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var extraData = validationContext.ExtraData;
        
        // Only apply this check for NextRound and NextTerm behaviors
        if (extraData.Behaviour != AElfConsensusBehaviour.NextRound && 
            extraData.Behaviour != AElfConsensusBehaviour.NextTerm)
        {
            validationResult.Success = true;
            return validationResult;
        }
        
        // Get the designated extra block producer from current round
        var extraBlockProducerInfo = validationContext.BaseRound.RealTimeMinersInformation.Values
            .FirstOrDefault(m => m.IsExtraBlockProducer);
            
        if (extraBlockProducerInfo == null || extraBlockProducerInfo.Pubkey != validationContext.SenderPubkey)
        {
            validationResult.Message = $"Only designated extra block producer can trigger round transition. Expected: {extraBlockProducerInfo?.Pubkey}, Got: {validationContext.SenderPubkey}";
            return validationResult;
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

Then add this provider to the validation chain in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextRound:
    validationProviders.Add(new ExtraBlockProducerAuthorizationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new ExtraBlockProducerAuthorizationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

## Proof of Concept

Due to the nature of this vulnerability requiring blockchain consensus mechanics and multiple concurrent block producers, a complete proof of concept would require:

1. Multiple miner nodes configured in a test network
2. Coordination of timing to have multiple miners at round boundary simultaneously
3. Network simulation to observe competing NextRound blocks

A simplified demonstration showing the missing validation:

```csharp
[Fact]
public void Test_MissingExtraBlockProducerAuthorizationForNextRound()
{
    // Setup: Create a round with 3 miners, designate one as extra block producer
    var round = GenerateTestRound(3);
    var extraBlockProducer = round.RealTimeMinersInformation.Values.First(m => m.IsExtraBlockProducer);
    var regularMiner = round.RealTimeMinersInformation.Values.First(m => !m.IsExtraBlockProducer);
    
    // Create NextRound consensus data from a NON-extra-block-producer miner
    var nextRoundFromRegularMiner = new AElfConsensusHeaderInformation
    {
        Behaviour = AElfConsensusBehaviour.NextRound,
        SenderPubkey = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(regularMiner.Pubkey)),
        Round = GenerateNextRound(round)
    };
    
    // Validate - this should FAIL but currently PASSES
    var validationResult = ValidateConsensusBeforeExecution(
        new BytesValue { Value = nextRoundFromRegularMiner.ToByteString() }
    );
    
    // VULNERABILITY: Regular miner can trigger NextRound even though they're not the extra block producer
    Assert.False(validationResult.Success); // This assertion FAILS, proving the vulnerability
    Assert.Contains("extra block producer", validationResult.Message);
}
```

The test would demonstrate that a regular miner (not the designated extra block producer) can successfully pass validation for a NextRound transaction, when they should be rejected.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-19)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-30)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L169-177)
```csharp
        var supposedExtraBlockProducer =
            currentRound.RealTimeMinersInformation.Single(m => m.Value.IsExtraBlockProducer).Key;

        // Check extra block time slot.
        if (Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime() &&
            supposedExtraBlockProducer == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]EXTRA");
            return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-82)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

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
