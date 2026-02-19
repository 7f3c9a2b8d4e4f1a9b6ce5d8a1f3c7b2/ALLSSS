### Title
Missing Authorization Check Allows Multiple Miners to Concurrently Trigger Round Transitions

### Summary
The AEDPoS consensus contract lacks authorization validation to ensure only the designated extra block producer can trigger `NextRound` transitions. Any miner whose time slot has passed can produce a block with a `NextRound` transaction, allowing multiple miners to simultaneously create competing round transitions, leading to consensus forks and instability.

### Finding Description

The vulnerability exists in the consensus validation flow where round transitions are not properly authorized.

**Root Cause**: The `ValidateBeforeExecution` method applies multiple validation providers for `NextRound` behavior, but none verify that the block producer is the designated extra block producer authorized to terminate the current round. [1](#0-0) 

The validation providers used include:
- `MiningPermissionValidationProvider` - only checks if sender is in the miner list, not their time slot authorization [2](#0-1) 

- `TimeSlotValidationProvider` - for `NextRound` (new round), only validates the new round's time slot structure via `CheckRoundTimeSlots()`, but does not check WHO can trigger it [3](#0-2) 

- `RoundTerminateValidationProvider` - only checks that the round number increments by exactly 1, not authorization [4](#0-3) 

While an `IsCurrentMiner()` method exists that checks extra block producer authorization during the extra block time slot: [5](#0-4) 

This check is never invoked during the validation flow before block execution.

**Behavior Provider Issue**: The consensus behavior provider determines that ANY miner whose time slot has passed can trigger round termination: [6](#0-5) 

**Execution Flow**: When `NextRound` transactions execute, the only protections are:

1. `EnsureTransactionOnlyExecutedOnceInOneBlock()` - prevents multiple consensus transactions in the SAME block, not across competing blocks: [7](#0-6) 

2. `TryToUpdateRoundNumber()` - only checks round number increments by 1, which all competing blocks at the same height satisfy when reading from the same parent state: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Violation**: Multiple miners can simultaneously trigger round transitions, creating competing forks where each fork successfully transitions to the next round number but with potentially different internal state (different `ExtraBlockProducerOfPreviousRound`, different miner orders, different timestamps). [9](#0-8) 

**Affected Parties**:
- All network participants face consensus instability
- Miners lose deterministic round transition leadership
- Cross-chain bridges may receive conflicting state proofs from competing forks
- Applications experience delayed finality and potential reorganizations

**Severity Justification**: This violates the critical invariant "Correct round transitions and time-slot validation, miner schedule integrity" by allowing unauthorized miners to trigger round transitions. The designated extra block producer role, determined by `CalculateNextExtraBlockProducerOrder()`, becomes meaningless if any miner can trigger the transition. [10](#0-9) 

### Likelihood Explanation

**Reachable Entry Point**: Any miner can call the public consensus methods through block production.

**Feasible Preconditions**:
1. Round in progress where all regular time slots have completed
2. Multiple miners simultaneously request their consensus commands via `GetConsensusCommand`
3. Network conditions allow multiple miners to produce blocks before one becomes dominant [11](#0-10) 

**Attack Complexity**: Low - this occurs naturally without malicious intent when:
- Network latency causes miners to not immediately see each other's blocks
- Multiple miners reach the end of round simultaneously
- No coordinator explicitly designates the next block producer

**Probability**: High during normal operation at round boundaries, especially in geographically distributed networks or under network stress. Each round termination is a potential race condition opportunity.

### Recommendation

**Primary Fix**: Add authorization validation in `ValidateBeforeExecution` for `NextRound` behavior to check that the sender is the designated extra block producer and the current time is within the extra block time slot.

Create a new validation provider:
```csharp
public class ExtraBlockProducerAuthorizationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.NextRound)
            return new ValidationResult { Success = true };
            
        var supposedExtraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation
            .Single(m => m.Value.IsExtraBlockProducer).Key;
            
        if (validationContext.SenderPubkey != supposedExtraBlockProducer)
            return new ValidationResult { 
                Message = "Only the designated extra block producer can trigger NextRound" 
            };
            
        // Also verify time is within extra block time slot
        if (validationContext.CurrentBlockTime < validationContext.BaseRound.GetExtraBlockMiningTime())
            return new ValidationResult { 
                Message = "Extra block time slot has not started" 
            };
            
        return new ValidationResult { Success = true };
    }
}
```

Add this provider to the validation chain: [1](#0-0) 

**Secondary Fix**: Modify the behavior provider to only return `NextRound` for the designated extra block producer: [12](#0-11) 

**Test Cases**: 
1. Verify non-extra-block-producer cannot trigger NextRound even after all time slots pass
2. Verify extra block producer can successfully trigger NextRound during their time slot
3. Test that concurrent NextRound attempts from multiple miners result in only one accepted chain

### Proof of Concept

**Initial State**:
- Round N at block height H
- 5 miners, all completed their time slots
- Miner A is designated extra block producer (has `IsExtraBlockProducer = true`)
- Current time > last miner's time slot end

**Attack Steps**:

1. Miners B, C, D simultaneously call `GetConsensusCommand`: [11](#0-10) 

2. All receive `NextRound` behavior from `GetConsensusBehaviourToTerminateCurrentRound()`: [12](#0-11) 

3. All three miners produce blocks at height H+1 with `NextRound` transactions

4. Each block passes validation:
   - `MiningPermissionValidationProvider`: All are in miner list ✓
   - `RoundTerminateValidationProvider`: All check N+1 == N+1 ✓
   - `TimeSlotValidationProvider`: All check new round structure ✓

5. Each block executes on its fork:
   - Reads parent state with `LatestExecutedHeight = H-1`
   - Check passes: `H-1 != H+1` ✓
   - Sets `LatestExecutedHeight = H+1`
   - Transitions to Round N+1

**Expected Result**: Only miner A (extra block producer) should be able to trigger NextRound

**Actual Result**: Miners B, C, D all successfully trigger NextRound on competing forks

**Success Condition**: Network splits into 3+ competing chains, all at Round N+1, violating single-chain consensus integrity.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-54)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();

        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();

        Context.LogDebug(() =>
            $"{currentRound.ToString(_processingBlockMinerPubkey)}\nArranged behaviour: {behaviour.ToString()}");

        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
    }
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
