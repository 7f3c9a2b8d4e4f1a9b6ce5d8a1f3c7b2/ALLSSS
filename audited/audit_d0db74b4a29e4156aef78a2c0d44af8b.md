### Title
Non-EBP Miners Can Execute Invalid Round Termination Commands

### Summary
The AEDPoS consensus system fails to validate that only the designated Extra Block Producer (EBP) can produce NextRound/NextTerm blocks. Any miner whose time slot has passed can generate termination commands and produce blocks that end the current round, allowing them to usurp the EBP role and gain unintended privileges in subsequent rounds.

### Finding Description

The vulnerability exists in the consensus command generation and validation flow:

**Root Cause - Missing EBP Validation:**

When a miner requests a consensus command, the behavior is determined by `ConsensusBehaviourProviderBase.GetConsensusBehaviour()`. [1](#0-0)  When a miner's time slot has passed and no other conditions apply, it returns `GetConsensusBehaviourToTerminateCurrentRound()` which provides NextRound or NextTerm behavior to ANY miner, without checking if they are the designated EBP.

**Exploitation Path:**

1. The system creates a `TerminateRoundCommandStrategy` for any miner receiving NextRound/NextTerm behavior [2](#0-1) 

2. This strategy calls `ArrangeExtraBlockMiningTime()` which arranges mining time for the provided pubkey, even if it's not the designated EBP [3](#0-2) 

3. When generating consensus extra data, the system sets the requesting miner as the previous round's EBP without validation: [4](#0-3) 

**Validation Gaps:**

The validation providers perform NO check that the sender is the designated EBP:
- `MiningPermissionValidationProvider` only verifies the sender is in the miner list [5](#0-4) 
- `RoundTerminateValidationProvider` only checks round/term number increments [6](#0-5) 
- `PreCheck()` only validates the sender is in current or previous miner list [7](#0-6) 

The designated EBP for each round is deterministically calculated and stored with `IsExtraBlockProducer = true` [8](#0-7)  but this information is never validated during round termination.

### Impact Explanation

**Consensus Integrity Violation:**
- The wrong miner is recorded as `ExtraBlockProducerOfPreviousRound`, breaking the consensus invariant that only the designated EBP should terminate rounds
- Multiple miners could simultaneously attempt to terminate a round, potentially causing chain forks or consensus confusion

**Privilege Escalation:**
The miner who produces the termination block gains special privileges in the next round:
- Can produce additional tiny blocks beyond normal limits [9](#0-8) 
- Can mine before the next round officially starts [10](#0-9) 

**Affected Parties:**
- The legitimate EBP loses their designated role and associated privileges
- The blockchain's consensus determinism is compromised
- If mining rewards or penalties are tied to EBP status, economic incentives are misaligned

**Severity:** Critical - This violates a fundamental consensus invariant and allows unauthorized miners to control round transitions.

### Likelihood Explanation

**Attacker Capabilities:**
Any regular miner in the active miner set can exploit this vulnerability. No special permissions or compromised keys are required beyond being a valid miner.

**Preconditions:**
- The attacker is in the current round's miner list (normal for active miners)
- The attacker's regular time slot has passed
- The attacker is not producing tiny blocks

**Execution Practicality:**
Highly practical - the exploit occurs naturally when miners query for consensus commands:
1. Miner calls `GetConsensusCommand()` with their pubkey [11](#0-10) 
2. Behavior provider returns NextRound/NextTerm if time slot passed
3. Miner produces block with this behavior
4. Validation passes despite miner not being designated EBP

**Economic Rationality:**
Zero additional cost - miners perform these operations as part of normal block production. The exploit requires no special transactions or resource expenditure.

**Detection Difficulty:**
The invalid termination may go undetected since all validation checks pass. The only indicator is the mismatch between who SHOULD have been the EBP (deterministically calculated) versus who actually produced the termination block.

### Recommendation

**Code-Level Mitigation:**

Add EBP validation in the `ValidateBeforeExecution` method by creating a new validation provider:

```csharp
public class ExtraBlockProducerValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.NextRound &&
            validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.NextTerm)
            return new ValidationResult { Success = true };

        var expectedEbp = validationContext.BaseRound.RealTimeMinersInformation
            .FirstOrDefault(m => m.Value.IsExtraBlockProducer).Key;
        
        if (expectedEbp != validationContext.SenderPubkey)
            return new ValidationResult 
            { 
                Message = $"Only designated EBP {expectedEbp} can terminate round, not {validationContext.SenderPubkey}" 
            };

        return new ValidationResult { Success = true };
    }
}
```

Register this provider in `ValidateBeforeExecution` for NextRound and NextTerm behaviors: [12](#0-11) 

**Invariant Check:**
Add assertion in `GetConsensusExtraDataForNextRound()` before line 178:
```csharp
var expectedEbp = currentRound.RealTimeMinersInformation
    .First(m => m.Value.IsExtraBlockProducer).Key;
Assert(pubkey == expectedEbp, $"Only designated EBP can terminate round");
```

**Test Cases:**
- Test that non-EBP miners receive error when attempting NextRound behavior
- Test that designated EBP successfully terminates round
- Test round transition with multiple miners attempting termination
- Test EBP privilege inheritance in subsequent rounds

### Proof of Concept

**Initial State:**
- Round N with 5 miners: A, B, C, D, E
- Miner C has `IsExtraBlockProducer = true` (designated EBP via `CalculateNextExtraBlockProducerOrder()`)
- Miners A, B, D have completed their time slots
- Current time is past D's expected mining time

**Attack Steps:**

1. Miner D (non-EBP) calls `GetConsensusCommand()` with D's pubkey
2. `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` checks:
   - D's OutValue is not null (D mined earlier) ✓
   - D's time slot has passed ✓
   - D cannot produce more tiny blocks ✓
   - Falls through to `GetConsensusBehaviourToTerminateCurrentRound()` returning NextRound
3. `TerminateRoundCommandStrategy` is created with D's pubkey
4. D produces block with NextRound behavior
5. `GetConsensusExtraDataForNextRound()` sets `nextRound.ExtraBlockProducerOfPreviousRound = D`
6. Validation succeeds (D is in miner list, round number increments correctly)
7. `ProcessNextRound()` executes, transitioning to Round N+1

**Expected Result:**
Only Miner C (designated EBP) should be able to produce NextRound block

**Actual Result:**
Miner D successfully produces NextRound block and is recorded as `ExtraBlockProducerOfPreviousRound`, gaining C's privileges in Round N+1

**Success Condition:**
In Round N+1, D can produce additional tiny blocks and mine before round start, demonstrating privilege escalation from usurping the EBP role.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L106-112)
```csharp
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L41-43)
```csharp
                return new ConsensusCommandProvider(
                        new TerminateRoundCommandStrategy(currentRound, pubkey, currentBlockTime,
                            behaviour == AElfConsensusBehaviour.NextTerm))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L23-38)
```csharp
        public override ConsensusCommand GetAEDPoSConsensusCommand()
        {
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
                LimitMillisecondsOfMiningBlock =
                    _isNewTerm ? LastBlockOfCurrentTermMiningLimit : DefaultBlockMiningLimit
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-46)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-91)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```
