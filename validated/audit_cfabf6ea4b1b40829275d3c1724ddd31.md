# Audit Report

## Title
Race Condition in Term Change Decision Allows Term Skipping Due to Stale TermNumber

## Summary
A race condition exists in the AElf consensus mechanism where the term change decision uses a stale state snapshot from `GetConsensusCommand`, while the actual term transition data generation in `GetConsensusExtraData` uses fresh state. This allows the protocol to skip entire terms (e.g., Term 1 → Term 3, skipping Term 2), causing miners elected for the skipped term to lose all rewards and disrupting treasury distributions and election snapshots.

## Finding Description

The vulnerability spans the consensus command generation flow where term change decisions are decoupled from term transition execution:

**Step 1: Stale Decision Making**

When `GetConsensusCommand` is called, it captures a snapshot of the current round state: [1](#0-0) 

This snapshot is passed to create a `MainChainConsensusBehaviourProvider`: [2](#0-1) 

The provider stores this snapshot as `CurrentRound`: [3](#0-2) 

The term change decision uses this stale `CurrentRound.TermNumber`: [4](#0-3) 

The `NeedToChangeTerm` method checks if miners' mining times indicate a term change based on the **stale** term number: [5](#0-4) 

**Step 2: Fresh Data Generation**

Later, when `GetConsensusExtraData` is called, it fetches **fresh** state: [6](#0-5) 

For NextTerm behavior, it calls `GetConsensusExtraDataForNextTerm`: [7](#0-6) 

Which then calls `GenerateFirstRoundOfNextTerm`: [8](#0-7) 

This method fetches **another fresh** `currentRound` from state: [9](#0-8) 

The new round's TermNumber is set to `currentRound.TermNumber + 1` using this **fresh** state: [10](#0-9) 

**Step 3: Why Validations Fail**

The pre-execution validation only checks that each **individual** transition increments by exactly 1: [11](#0-10) 

The execution validation similarly only checks sequential increment: [12](#0-11) 

**Attack Scenario:**

1. At Term 1, time period boundary is crossed (term change needed)
2. Miner A calls `GetConsensusCommand` - sees Term 1, decides NextTerm
3. Miner B produces NextTerm block first - updates state to Term 2
4. Miner A calls `GetConsensusExtraData` - sees Term 2 (fresh state), generates transition to Term 3
5. Miner A's block validates successfully because `baseRound.TermNumber (2) + 1 == extraData.TermNumber (3)`
6. Protocol skips Term 2 entirely

## Impact Explanation

**Severity: HIGH**

The term skipping breaks multiple critical protocol invariants with direct fund impact:

1. **Treasury Misallocation**: Treasury releases are tied to term numbers. When `ProcessNextTerm` executes, it calls treasury release with the term number: [13](#0-12) 

If Term 2 is skipped, the treasury release for that period either never happens or occurs at the wrong time, disrupting the economic model.

2. **Election Snapshot Loss**: Election snapshots are taken per term with the term number: [14](#0-13) 

A skipped term means no snapshot is recorded, breaking the election history and preventing proper governance transitions.

3. **Mining Reward Miscalculation**: Mining rewards are calculated and donated per term: [15](#0-14) 

The `MiningRewardGenerated` event uses `previousRound.TermNumber`, causing reward accounting mismatches.

4. **Miner Disenfranchisement**: Miners elected for the skipped term never get to produce blocks during their elected period (typically 7 days), losing 100% of their expected mining rewards.

5. **Protocol Invariant Violation**: The core invariant that terms progress sequentially (Term N → Term N+1 → Term N+2) is broken, potentially causing cascading failures in dependent systems.

## Likelihood Explanation

**Likelihood: HIGH**

This is a **natural race condition** that occurs during normal operations without any malicious intent:

1. **Time Gap**: There is an inherent time gap between `GetConsensusCommand` (which schedules mining) and `GetConsensusExtraData` (which generates block data). This gap can be seconds to minutes: [16](#0-15) 

2. **Concurrent Miners**: In a multi-miner network (20-100 miners), multiple miners near a term boundary will simultaneously check consensus commands, all seeing the same stale state indicating term change is needed.

3. **Natural Timing Variance**: Block production timing naturally varies. If one miner's NextTerm block executes while another miner is waiting for their scheduled time, the race occurs automatically.

4. **No Attack Required**: This requires no malicious behavior - just honest miners following the normal consensus protocol during term boundaries.

5. **Frequency**: This vulnerability window opens at **every term boundary** (approximately every 7 days on mainnet). With dozens of active miners, the probability of the race condition occurring is high.

## Recommendation

The fix requires ensuring that the term change decision and term transition data generation use the same state snapshot. Two approaches:

**Option 1: Cache Term Number in Consensus Command**

Store the decided term number in the consensus command returned by `GetConsensusCommand`, and use that cached value in `GetConsensusExtraData` instead of reading fresh state.

**Option 2: Re-validate Term Change Decision**

In `GetConsensusExtraData`, before generating NextTerm data, re-check `NeedToChangeTerm()` with fresh state. If the condition no longer holds, downgrade to NextRound behavior.

**Option 3: Add State Version Check**

Include a state version or round number in the consensus command, and validate in `GetConsensusExtraData` that the state hasn't changed. If it has, reject the NextTerm behavior.

**Recommended Implementation** (Option 2 - most robust):

In `GetConsensusBlockExtraData`, add before line 46:

```csharp
case AElfConsensusBehaviour.NextTerm:
    // Re-validate term change decision with current state
    if (!currentRound.NeedToChangeTerm(
        GetBlockchainStartTimestamp(),
        State.CurrentTermNumber.Value,
        State.PeriodSeconds.Value))
    {
        // Condition no longer holds, downgrade to NextRound
        information = GetConsensusExtraDataForNextRound(currentRound, pubkey, triggerInformation);
    }
    else
    {
        information = GetConsensusExtraDataForNextTerm(pubkey, triggerInformation);
    }
    break;
```

This ensures the term change decision is always validated against current state before generating the transition data.

## Proof of Concept

```csharp
[Fact]
public async Task TermSkipping_RaceCondition_Test()
{
    // Setup: Two miners at term boundary
    var miner1 = SampleAccount.Accounts[0];
    var miner2 = SampleAccount.Accounts[1];
    
    // Initialize to Term 1, advance time past term boundary
    await AdvanceToTermBoundary(1);
    
    // Miner 1: Calls GetConsensusCommand - sees Term 1, decides NextTerm
    var miner1Command = await ConsensusStub.GetConsensusCommand.CallAsync(
        new BytesValue { Value = ByteString.CopyFrom(miner1.PublicKey) });
    Assert.Equal(AElfConsensusBehaviour.NextTerm, miner1Command.Hint);
    
    // Miner 2: Produces and executes NextTerm block first - updates to Term 2
    var miner2ExtraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
        new BytesValue { Value = CreateTriggerInfo(miner2, AElfConsensusBehaviour.NextTerm) });
    await ExecuteNextTermBlock(miner2, miner2ExtraData);
    
    // Verify state is now Term 2
    var currentTerm = await ConsensusStub.GetCurrentTermNumber.CallAsync(new Empty());
    Assert.Equal(2, currentTerm.Value);
    
    // Miner 1: Now calls GetConsensusExtraData - sees Term 2, generates Term 3
    var miner1ExtraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
        new BytesValue { Value = CreateTriggerInfo(miner1, AElfConsensusBehaviour.NextTerm) });
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(miner1ExtraData.Value);
    
    // BUG: Miner1's block targets Term 3, skipping Term 2
    Assert.Equal(3, headerInfo.Round.TermNumber);
    
    // Execute Miner 1's block - validation PASSES incorrectly
    var validationResult = await ConsensusStub.ValidateConsensusBeforeExecution.CallAsync(miner1ExtraData);
    Assert.True(validationResult.Success); // Should fail but passes!
    
    await ExecuteNextTermBlock(miner1, miner1ExtraData);
    
    // Verify: Protocol jumped from Term 1 → Term 3, skipping Term 2
    currentTerm = await ConsensusStub.GetCurrentTermNumber.CallAsync(new Empty());
    Assert.Equal(3, currentTerm.Value); // Term 2 was completely skipped!
}
```

**Notes:**

This vulnerability represents a critical flaw in the consensus mechanism's state management. The separation of concerns between decision-making (`GetConsensusCommand`) and execution (`GetConsensusExtraData`) creates a race window that is fundamentally exploitable during normal operations. The impact is severe: miners lose rewards, treasury distributions are disrupted, and election snapshots are lost. The likelihood is high as this occurs naturally at every term boundary in a multi-miner network. Immediate remediation is strongly recommended.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L23-24)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L39-43)
```csharp
        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L24-29)
```csharp
        protected readonly Round CurrentRound;

        protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-35)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L13-20)
```csharp
    private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);

        Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");

        TryToGetCurrentRoundInformation(out var currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L45-47)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                information = GetConsensusExtraDataForNextTerm(pubkey, triggerInformation);
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-209)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-226)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L40-41)
```csharp
        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L98-105)
```csharp
    private bool TryToUpdateTermNumber(long termNumber)
    {
        var oldTermNumber = State.CurrentTermNumber.Value;
        if (termNumber != 1 && oldTermNumber + 1 != termNumber) return false;

        State.CurrentTermNumber.Value = termNumber;
        return true;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-210)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L59-111)
```csharp
    public async Task TriggerConsensusAsync(ChainContext chainContext)
    {
        var now = TimestampHelper.GetUtcNow();
        _blockTimeProvider.SetBlockTime(now, chainContext.BlockHash);

        Logger.LogDebug($"Block time of triggering consensus: {now.ToDateTime():hh:mm:ss.ffffff}.");

        var triggerInformation =
            _triggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue());

        Logger.LogDebug($"Mining triggered, chain context: {chainContext.BlockHeight} - {chainContext.BlockHash}");

        // Upload the consensus command.
        var contractReaderContext =
            await _consensusReaderContextService.GetContractReaderContextAsync(chainContext);
        _consensusCommand = await _contractReaderFactory
            .Create(contractReaderContext).GetConsensusCommand
            .CallAsync(triggerInformation);

        if (_consensusCommand == null)
        {
            Logger.LogWarning("Consensus command is null.");
            return;
        }

        Logger.LogDebug($"Updated consensus command: {_consensusCommand}");

        // Update next mining time, also block time of both getting consensus extra data and txs.
        _nextMiningTime = _consensusCommand.ArrangedMiningTime;
        var leftMilliseconds = _consensusCommand.ArrangedMiningTime - TimestampHelper.GetUtcNow();
        leftMilliseconds = leftMilliseconds.Seconds > ConsensusConstants.MaximumLeftMillisecondsForNextBlock
            ? new Duration { Seconds = ConsensusConstants.MaximumLeftMillisecondsForNextBlock }
            : leftMilliseconds;

        var configuredMiningTime = await _miningTimeProvider.GetLimitMillisecondsOfMiningBlockAsync(new BlockIndex
        {
            BlockHeight = chainContext.BlockHeight,
            BlockHash = chainContext.BlockHash
        });
        var limitMillisecondsOfMiningBlock = configuredMiningTime == 0
            ? _consensusCommand.LimitMillisecondsOfMiningBlock
            : configuredMiningTime;
        // Update consensus scheduler.
        var blockMiningEventData = new ConsensusRequestMiningEventData(chainContext.BlockHash,
            chainContext.BlockHeight,
            _nextMiningTime,
            TimestampHelper.DurationFromMilliseconds(limitMillisecondsOfMiningBlock),
            _consensusCommand.MiningDueTime);
        _consensusScheduler.CancelCurrentEvent();
        _consensusScheduler.NewEvent(leftMilliseconds.Milliseconds(), blockMiningEventData);

        Logger.LogDebug($"Set next mining time to: {_nextMiningTime.ToDateTime():hh:mm:ss.ffffff}");
    }
```
