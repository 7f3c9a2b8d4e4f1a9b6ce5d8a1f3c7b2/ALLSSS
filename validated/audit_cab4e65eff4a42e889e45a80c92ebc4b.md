# Audit Report

## Title
Unauthorized Round Termination Due to Missing Extra Block Producer Authorization Check

## Summary
The AEDPoS consensus contract contains a critical authorization bypass that allows any miner who has reached their maximum block count during their time slot to prematurely terminate the consensus round. This bypasses the protocol invariant that only the designated extra block producer should terminate rounds during the extra block time slot, enabling unfair block production distribution and consensus schedule manipulation.

## Finding Description

The vulnerability exists in the consensus behavior determination logic where a critical authorization check is missing. [1](#0-0) 

When a miner has `OutValue != null` (has mined), `!_isTimeSlotPassed` (still within their time slot), and `ActualMiningTimes.Count >= _maximumBlocksCount` (reached block limit), but is NOT the extra block producer of the previous round, the function falls through and calls `GetConsensusBehaviourToTerminateCurrentRound()`, which returns `NextRound` or `NextTerm` behavior without verifying the miner is authorized to terminate the round.

The validation system fails to prevent this unauthorized termination:

**1. PreCheck() Authorization is Insufficient** [2](#0-1) 

The `PreCheck()` method only validates that the miner is in the current or previous round's miner list, NOT that they have authority to terminate rounds.

**2. TimeSlotValidationProvider Doesn't Check Authorization** [3](#0-2) 

For NextRound/NextTerm behaviors, it only calls `CheckRoundTimeSlots()` which validates time slot spacing equality, but does NOT check if the current miner is authorized to terminate the round or if it's the extra block time slot.

**3. RoundTerminateValidationProvider Only Checks Round Number** [4](#0-3) 

This provider only validates round/term number correctness, not authorization to terminate.

**4. IsCurrentMiner() Has Proper Checks But Isn't Called** [5](#0-4) 

The `IsCurrentMiner()` method contains comprehensive checks for extra block producer authorization during the extra block time slot, but this method is never called in the NextRound/NextTerm execution path validated in `ValidateBeforeExecution()`. [6](#0-5) 

## Impact Explanation

This vulnerability breaks the core consensus invariant that only the designated extra block producer can terminate rounds during the extra block time slot. The impacts include:

1. **Consensus Schedule Disruption**: Unauthorized miners terminate rounds before all miners have had their scheduled time slots, violating the consensus protocol's fairness guarantees defined by the round time slot structure. [7](#0-6) 

2. **Unfair Block Production Distribution**: Miners who haven't had their turn lose block production opportunities and associated mining rewards, breaking the equitable distribution model.

3. **Extra Block Producer Role Hijacking**: The attacker becomes the extra block producer of the next round, gaining the privilege to terminate that round as well, enabling repeated exploitation. [8](#0-7) 

4. **Chain Stability Risk**: Coordinated exploitation could manipulate consensus timing and disrupt the intended round schedule, potentially affecting chain liveness and consensus integrity.

## Likelihood Explanation

**Attacker Capabilities**: Must be an active miner in the current round who mines legitimate blocks to reach maximum block count. While becoming a miner requires passing the election process (high barrier to entry), this is within the threat model for consensus vulnerabilities where a malicious elected miner is assumed.

**Attack Complexity**: LOW - Given miner status, the attacker simply needs to:
1. Mine blocks during their legitimate time slot until reaching `_maximumBlocksCount`
2. While still in their time slot, receive `NextRound` behavior from the consensus command generation [9](#0-8) 

3. Execute the returned `NextRound` or `NextTerm` transaction, which will pass validation and terminate the round [10](#0-9) 

**Feasibility**: HIGH - The entry points are publicly callable, no exceptional conditions required beyond normal mining participation. No additional economic barriers exist beyond the inherent cost of being an elected miner.

## Recommendation

Add authorization validation to check that only the extra block producer can terminate rounds, and verify the current time is within the extra block time slot:

1. **In TimeSlotValidationProvider**: For NextRound/NextTerm behaviors, add a check that verifies:
   - Current block time >= `currentRound.GetExtraBlockMiningTime()`
   - Sender pubkey matches the designated extra block producer

2. **Alternative approach**: Call `IsCurrentMiner()` during NextRound/NextTerm validation to leverage its existing comprehensive authorization checks.

3. **In GetConsensusBehaviour()**: Add an explicit check before returning `GetConsensusBehaviourToTerminateCurrentRound()` to ensure the miner is authorized to terminate (is extra block producer or is mining during extra block time slot).

## Proof of Concept

To create a test that proves this vulnerability:

1. **Setup**: Create a test round with multiple miners, each with defined time slots
2. **Execute**: Have a non-extra-block-producer miner mine `_maximumBlocksCount` blocks during their normal time slot (before all miners have completed their slots)
3. **Call**: Have that miner call `GetConsensusCommand()` which will return `NextRound` behavior
4. **Validate**: Execute the NextRound transaction - it will pass all validation checks despite the miner not being authorized
5. **Verify**: Check that the round was terminated prematurely, skipping other miners' time slots, and the exploiting miner became the extra block producer of the next round

The test should demonstrate that a miner can terminate the round during their own time slot without being the designated extra block producer, violating the consensus protocol's authorization model.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-82)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L172-178)
```csharp
        // Check extra block time slot.
        if (Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime() &&
            supposedExtraBlockProducer == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]EXTRA");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L254-254)
```csharp
        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-92)
```csharp
        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L164-171)
```csharp
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
```
