### Title
Unauthorized Round Termination by Non-Designated Miners on Side Chains

### Summary
On side chains, any miner who has not produced a block in the current round and whose time slot has passed can terminate the round by returning `NextRound` behavior, even if they are not the designated extra block producer. This breaks the consensus invariant that only the calculated extra block producer should terminate rounds, allowing miners to manipulate round termination for economic gain and mining privileges.

### Finding Description

**Root Cause**: The `SideChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` method unconditionally returns `NextRound` without validating whether the calling miner is the designated extra block producer. [1](#0-0) 

**Execution Path**:
1. When a miner calls `GetConsensusCommand()`, the system invokes `GetConsensusBehaviour()` from the base class [2](#0-1) 

2. If the miner has not produced a block (`OutValue == null`), the code calls `HandleMinerInNewRound()` at line 51 [3](#0-2) 

3. When the miner's time slot has passed, `HandleMinerInNewRound()` returns `Nothing` at line 114 [4](#0-3) 

4. Since the behaviour is `Nothing`, line 55 does not return early, and execution continues to line 82 which calls `GetConsensusBehaviourToTerminateCurrentRound()`

5. For side chains, this unconditionally returns `NextRound`, allowing any miner who missed their slot to terminate the round

**Why Protections Fail**:
- The extra block producer is deterministically calculated via `CalculateNextExtraBlockProducerOrder()` based on signatures [5](#0-4) 

- One miner per round is designated with `IsExtraBlockProducer = true` [6](#0-5) 

- However, no validation provider checks this flag during `NextRound` behavior validation [7](#0-6) 

- The `IsCurrentMiner()` method does check for extra block producer privileges, but this check is never invoked during consensus behavior determination [8](#0-7) 

### Impact Explanation

**Consensus Integrity Violation**: The designated extra block producer is calculated deterministically to ensure fair rotation and prevent manipulation. Allowing arbitrary miners to terminate rounds breaks this invariant.

**Economic Benefit to Attacker**:
1. The terminating miner becomes `ExtraBlockProducerOfPreviousRound` in the next round [9](#0-8) 

2. Their `ProducedBlocks` count is incremented, directly affecting mining reward calculations [10](#0-9) 

3. Mining rewards are calculated as `minedBlocks × miningRewardPerBlock` and donated to Treasury [11](#0-10) 

4. They gain extended mining privileges, including the ability to mine at the start of the next round and produce tiny blocks [12](#0-11) 

**Affected Parties**: All side chain miners, as the consensus mechanism's fairness and determinism are compromised. Honest miners lose their designated round termination opportunities.

**Severity**: HIGH - This violates the "Correct round transitions and miner schedule integrity" critical invariant for consensus systems.

### Likelihood Explanation

**Attacker Capabilities**: Any miner in the side chain miner list can execute this attack. No special privileges or complex setup required.

**Attack Complexity**: Trivial
1. Miner intentionally does not produce a block during their assigned time slot
2. Wait for their time slot to pass
3. Call `GetConsensusCommand()` - a standard public method [13](#0-12) 

4. Receive `NextRound` behavior and produce the round-terminating block

**Feasibility Conditions**: 
- Miner must be in the current round's miner list (checked at line 26-27)
- Miner's time slot must have passed (automatic with time progression)
- No other miner has already terminated the round (creates race condition between multiple non-mining miners)

**Economic Rationality**: The attack cost is zero (simply not mining), while the benefit includes increased block production statistics and potential mining rewards. Multiple miners can attempt this simultaneously, creating a race to terminate rounds for economic advantage.

**Detection**: The attack is difficult to distinguish from legitimate network delays or node failures, as the system intentionally allows non-designated miners to terminate rounds as a "recovery mechanism" per code comments.

### Recommendation

**Immediate Fix**: Add validation in `GetConsensusBehaviourToTerminateCurrentRound()` to check if the calling miner is the designated extra block producer:

```csharp
protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
{
    // Only the designated extra block producer should terminate the round
    var extraBlockProducer = CurrentRound.RealTimeMinersInformation
        .FirstOrDefault(m => m.Value.IsExtraBlockProducer);
    
    if (extraBlockProducer.Key == _pubkey)
    {
        return AElfConsensusBehaviour.NextRound;
    }
    
    return AElfConsensusBehaviour.Nothing;
}
```

**Alternative**: Add a validation provider that checks `IsExtraBlockProducer` for `NextRound` and `NextTerm` behaviors:

```csharp
public class ExtraBlockProducerValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextRound ||
            validationContext.ExtraData.Behaviour == AElfConsensusBehaviour.NextTerm)
        {
            var extraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation
                .FirstOrDefault(m => m.Value.IsExtraBlockProducer).Key;
            
            if (extraBlockProducer != validationContext.SenderPubkey)
            {
                return new ValidationResult 
                { 
                    Message = "Only designated extra block producer can terminate the round." 
                };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Register this provider in the validation pipeline at line 86-87 of `AEDPoSContract_Validation.cs`.

**Test Cases**:
1. Verify only the designated extra block producer can return `NextRound`
2. Verify non-designated miners receive `Nothing` behavior when their slot passes
3. Verify the extra block producer is correctly calculated via `CalculateNextExtraBlockProducerOrder()`
4. Test the recovery mechanism when the designated extra block producer is offline (may need separate handling)

### Proof of Concept

**Initial State**:
- Side chain with 5 miners (A, B, C, D, E)
- Current round in progress
- Miner C is designated as extra block producer (`IsExtraBlockProducer = true`) based on signature calculation
- Miners A and B have already mined
- Miner D has not mined

**Attack Steps**:
1. Miner D intentionally does not mine during their time slot (order 4)
2. Wait for Miner D's time slot to pass
3. Miner D calls `GetConsensusCommand(D_pubkey)`
4. System flow:
   - Checks `D.OutValue == null` → TRUE
   - Calls `HandleMinerInNewRound()` → returns `Nothing` (time slot passed)
   - Falls through to `GetConsensusBehaviourToTerminateCurrentRound()` → returns `NextRound`
   - Miner D receives valid `NextRound` consensus command
5. Miner D produces block with `NextRound` behavior
6. Validation passes (no check for `IsExtraBlockProducer`)
7. `GetConsensusExtraDataForNextRound()` sets `nextRound.ExtraBlockProducerOfPreviousRound = D_pubkey`
8. Miner D's `ProducedBlocks` incremented

**Expected Result**: Only Miner C should be able to terminate the round as the designated extra block producer.

**Actual Result**: Miner D successfully terminates the round, stealing Miner C's round termination privilege and associated economic benefits.

**Success Condition**: Miner D's pubkey appears as `ExtraBlockProducerOfPreviousRound` in the next round, and their `ProducedBlocks` count is incremented, despite not being the designated extra block producer.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L20-23)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-115)
```csharp
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;

            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;

            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-178)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L191-196)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
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
