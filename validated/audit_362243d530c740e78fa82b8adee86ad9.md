# Audit Report

## Title
Unauthorized Round Termination Due to Missing Extra Block Producer Authorization Check

## Summary
The AEDPoS consensus contract fails to validate that only the designated extra block producer can terminate rounds. Any miner who has already mined a block can prematurely trigger NextRound/NextTerm behaviors after their time slot expires, bypassing the intended extra block producer mechanism and violating consensus schedule integrity.

## Finding Description

The vulnerability exists across the consensus command generation and validation pipeline where authorization to terminate rounds is never verified.

**Flawed Behavior Assignment:** The behavior provider grants round-terminating behaviors to any miner whose `OutValue` is not null and whose time slot has passed, without checking if they are the designated extra block producer. [1](#0-0) 

When the logic falls through to line 82, it returns `GetConsensusBehaviourToTerminateCurrentRound()` which yields NextRound or NextTerm behavior. [2](#0-1) 

**Insufficient Entry Point Validation:** The public `GetConsensusCommand` method only verifies miner list membership via `IsInMinerList`, not extra block producer authorization. [3](#0-2) 

The `IsInMinerList` method merely checks dictionary key existence. [4](#0-3) 

**Missing Validation in Pipeline:** None of the validation providers enforce extra block producer authorization:

- `MiningPermissionValidationProvider` only validates miner list membership. [5](#0-4) 

- `RoundTerminateValidationProvider` only checks round/term number correctness. [6](#0-5) 

- The validation orchestrator adds these providers for NextRound/NextTerm but never includes extra block producer checks. [7](#0-6) 

**Execution Permission Check Insufficient:** The `PreCheck` method during transaction execution only validates miner list membership, not extra block producer status. [8](#0-7) 

**Design Intent Violated:** The codebase maintains infrastructure for extra block producer designation. Each round designates one miner with `IsExtraBlockProducer = true`. [9](#0-8) 

The extra block mining time is explicitly calculated. [10](#0-9) 

The `IsCurrentMiner` method correctly validates extra block producer authorization for the extra block time slot. [11](#0-10) 

However, this validation method is never invoked in the consensus command generation or block validation pipeline.

## Impact Explanation

**Consensus Protocol Integrity Violation:** This vulnerability breaks the fundamental AEDPoS consensus invariant that rounds must be terminated only by designated extra block producers. Miners can manipulate the consensus schedule by prematurely ending rounds, preventing later-scheduled miners from producing blocks.

**Quantified Economic Impact:** In a round with N miners where the attacker is at position K < N:
- (N - K) miners lose their block production opportunity
- These miners receive zero mining rewards for that round
- The attacker monopolizes the right to determine round transitions
- Block rewards are unfairly redistributed to earlier-positioned miners

**Affected Parties:**
- **Legitimate miners:** Direct economic loss from missed block rewards
- **Extra block producer:** Role is completely bypassed, intended privileges nullified
- **Network:** Consensus schedule predictability is destroyed
- **Protocol integrity:** Core design assumption violated

**Severity Assessment: Medium** because:
- Requires attacker to be an elected miner (high privilege, but achievable)
- Direct economic impact on other miners' rewards
- Violates critical consensus invariant
- Does not enable direct treasury theft but manipulates reward distribution
- Damages long-term protocol fairness and predictability

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be in current miner list (achievable via election/staking)
- Must have produced at least one block in the current round (normal mining operation)
- No additional vulnerabilities or special privileges needed

**Attack Complexity: Low**
- Single call to `GetConsensusCommand` after attacker's time slot expires
- No race conditions required
- No timing attacks needed
- Deterministic success given preconditions

**Execution Steps:**
1. Attacker mines their normal block during assigned time slot (sets `OutValue`)
2. Attacker waits until their time slot expires (`IsTimeSlotPassed` becomes true)
3. Attacker requests consensus command via `GetConsensusCommand`
4. Behavior provider returns NextRound/NextTerm behavior
5. Attacker produces block with round-terminating transaction
6. Validation passes (all checks only verify miner list membership)
7. Round terminates prematurely

**Detection Difficulty:**
- Attack appears as legitimate round transition on-chain
- No obvious indicators distinguish it from proper extra block producer behavior
- Only post-facto analysis of `IsExtraBlockProducer` flag reveals the violation

**Probability Assessment: Medium-High**
- Scenario occurs regularly (miners transition rounds frequently)
- Low technical barrier once miner status achieved
- Economic incentive exists (capture remaining block rewards)
- No monitoring mechanisms to prevent or detect exploitation

## Recommendation

Add extra block producer authorization validation in the consensus command generation and validation pipeline:

1. **In ConsensusBehaviourProviderBase.cs**: Before returning termination behavior at line 82, check if the current time is within the extra block time slot and if the miner is the designated extra block producer.

2. **Add ExtraBlockProducerValidationProvider**: Create a new validation provider that checks:
   - For NextRound/NextTerm behaviors, verify `Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime()`
   - Verify the sender's `IsExtraBlockProducer` flag is true
   - Add this provider to the validation chain in `ValidateBeforeExecution`

3. **Enhance PreCheck**: Add extra block producer validation for NextRound/NextTerm transactions.

## Proof of Concept

A complete proof of concept would require setting up a multi-miner test environment where:
1. Initialize a round with 5 miners
2. Have miner at position 3 mine their block normally
3. Advance time past position 3's time slot but before position 4's time slot
4. Have position 3 call GetConsensusCommand → verify it returns NextRound
5. Have position 3 execute NextRound transaction → verify it succeeds
6. Verify positions 4 and 5 can no longer mine in that round
7. Verify position 3 is not the designated extra block producer for the round

This demonstrates that non-extra-block-producers can terminate rounds prematurely, violating the consensus schedule and causing economic loss to bypassed miners.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L49-83)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L10-47)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var extraData = validationContext.ExtraData;
        if (extraData.Behaviour == AElfConsensusBehaviour.NextRound) return ValidationForNextRound(validationContext);

        if (extraData.Behaviour == AElfConsensusBehaviour.NextTerm) return ValidationForNextTerm(validationContext);

        validationResult.Success = true;
        return validationResult;
    }

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-66)
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
