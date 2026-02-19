### Title
Missing Round ID in First Round Consensus Hint Causes Invalid InValue Retrieval

### Summary
The `FirstRoundCommandStrategy` creates consensus hints without `RoundId` and `PreviousRoundId` fields for round 1 UpdateValue operations, causing the production `AEDPoSTriggerInformationProvider` to retrieve `Hash.Empty` instead of actual InValue from cache. This results in predictable OutValue and Signature calculations that undermine the consensus security model for the initial blockchain round.

### Finding Description

**Root Cause Location:** [1](#0-0) 

When `currentRound.RoundNumber == 1` and `behaviour == AElfConsensusBehaviour.UpdateValue`, the code uses `FirstRoundCommandStrategy` which creates a consensus hint containing only the `Behaviour` field: [2](#0-1) 

This is inconsistent with `NormalBlockCommandStrategy` which always includes `RoundId` and `PreviousRoundId`: [3](#0-2) 

**Why Protections Fail:**

In production, `AEDPoSTriggerInformationProvider` extracts the hint and attempts to retrieve InValue and PreviousInValue from cache using the hint's `RoundId` and `PreviousRoundId` fields: [4](#0-3) 

Since protobuf3 defaults unset int64 fields to 0, and `FirstRoundCommandStrategy` doesn't set these fields, `hint.RoundId` and `hint.PreviousRoundId` are both 0. The cache lookup with key 0 returns `Hash.Empty`: [5](#0-4) 

The contract then computes OutValue and Signature from this empty hash: [6](#0-5) 

**Evidence of Bug:**

The test infrastructure manually provides InValue values, explicitly bypassing the production cache retrieval mechanism with the comment "It doesn't matter for testing": [7](#0-6) 

This test workaround masks the production bug where real `AEDPoSTriggerInformationProvider` would fail to retrieve proper InValue.

### Impact Explanation

**Consensus Integrity Violation:**

During round 1 UpdateValue operations (the initial consensus round of the blockchain), all miners will:
1. Have their InValue set to `Hash.Empty` instead of unique secret values
2. Generate identical, predictable OutValue = `Hash(Hash.Empty)`
3. Produce signatures based on wrong input values
4. Violate the secret sharing security model

**Specific Harms:**
- **Consensus Security**: First round lacks proper randomness and secret sharing, making it vulnerable to manipulation
- **Protocol Integrity**: Round 1 miners all produce identical cryptographic values, defeating the purpose of distributed consensus
- **Verification Failures**: Consensus data generated in round 1 may fail validation or create inconsistent blockchain state
- **Affected Parties**: All blockchain nodes and miners participating in genesis/initialization

**Severity Justification:**
This is a MEDIUM severity issue because:
- It affects a critical consensus mechanism
- Only impacts round 1 (limited scope)
- Doesn't directly lead to fund theft but undermines consensus security
- Creates potential for consensus manipulation during blockchain initialization

### Likelihood Explanation

**Execution Certainty:**
- **Reachable Entry Point**: The public `GetConsensusCommand` method is called during normal block production [8](#0-7) 

- **Automatic Trigger**: Round 1 miners attempting UpdateValue behavior will automatically hit this code path through the consensus behavior provider logic: [9](#0-8) 

- **No Attack Required**: This is a design flaw that manifests during normal blockchain initialization when the first miner (and subsequent miners) attempt to mine blocks in round 1

- **Detection Constraints**: The bug is masked in tests due to manual InValue injection, making it difficult to detect without production deployment or careful code review

**Probability**: HIGH - Occurs with 100% probability during round 1 mining operations when using production infrastructure.

### Recommendation

**Code-Level Mitigation:**

Modify `FirstRoundCommandStrategy` to include `RoundId` and `PreviousRoundId` in the consensus hint, consistent with `NormalBlockCommandStrategy`:

```csharp
public override ConsensusCommand GetAEDPoSConsensusCommand()
{
    var miningInterval = MiningInterval;
    var offset = _consensusBehaviour == AElfConsensusBehaviour.UpdateValue && Order == 1
        ? miningInterval
        : Order.Add(MinersCount).Sub(1).Mul(miningInterval);
    var arrangedMiningTime = MiningTimeArrangingService.ArrangeMiningTimeWithOffset(CurrentBlockTime, offset);
    
    // Add RoundId and PreviousRoundId to hint
    long previousRoundId = 0;
    if (CurrentRound.RoundNumber > 1)
    {
        // Attempt to get previous round ID
        // Implementation depends on access to State
    }
    
    return new ConsensusCommand
    {
        Hint = new AElfConsensusHint 
        { 
            Behaviour = _consensusBehaviour,
            RoundId = CurrentRound.RoundId,  // Add this
            PreviousRoundId = previousRoundId  // Add this
        }.ToByteString(),
        ArrangedMiningTime = arrangedMiningTime,
        MiningDueTime = arrangedMiningTime.AddMilliseconds(miningInterval),
        LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
    };
}
```

**Invariant Checks:**
- Add assertion in `AEDPoSTriggerInformationProvider` to validate that `hint.RoundId` is non-zero for UpdateValue behavior
- Add unit test verifying that first round UpdateValue commands include proper RoundId in hint

**Test Cases:**
- Update test infrastructure to use real `AEDPoSTriggerInformationProvider` instead of manually injecting InValue
- Add integration test for round 1 mining that validates InValue retrieval works correctly
- Add test case verifying hint consistency between `FirstRoundCommandStrategy` and `NormalBlockCommandStrategy`

### Proof of Concept

**Initial State:**
1. Blockchain at genesis/initialization
2. First round (RoundNumber = 1) created and stored
3. First miner ready to produce block with UpdateValue behavior

**Execution Sequence:**

1. Miner calls `GetConsensusCommand` with their pubkey
2. Code determines behavior should be `UpdateValue` for round 1
3. Condition at line 28 is TRUE: `currentRound.RoundNumber == 1 && behaviour == AElfConsensusBehaviour.UpdateValue`
4. `FirstRoundCommandStrategy` is instantiated and returns command with hint containing only `Behaviour` field
5. `AEDPoSTriggerInformationProvider.GetTriggerInformationForBlockHeaderExtraData` is called with this command
6. Hint is parsed: `RoundId = 0`, `PreviousRoundId = 0` (protobuf defaults)
7. `_inValueCache.GetInValue(0)` is called, returns `Hash.Empty`
8. `_inValueCache.GetInValue(0)` is called for previous, returns `Hash.Empty`
9. Trigger information contains `InValue = Hash.Empty`, `PreviousInValue = Hash.Empty`
10. Contract's `GetConsensusExtraDataToPublishOutValue` computes:
    - `OutValue = Hash(Hash.Empty)` (predictable, same for all miners)
    - `Signature = Hash(OutValue || Hash.Empty)` (predictable)

**Expected vs Actual:**
- **Expected**: Unique InValue per miner, proper secret sharing, unpredictable OutValue
- **Actual**: All miners use `Hash.Empty`, identical predictable outputs, broken consensus security

**Success Condition**: Verification that `triggerInformation.InValue == Hash.Empty` in production round 1 mining scenario.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L28-30)
```csharp
        if (currentRound.RoundNumber == 1 && behaviour == AElfConsensusBehaviour.UpdateValue)
            return new ConsensusCommandProvider(new FirstRoundCommandStrategy(currentRound, pubkey,
                currentBlockTime, behaviour)).GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs (L40-46)
```csharp
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint { Behaviour = _consensusBehaviour }.ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                MiningDueTime = arrangedMiningTime.AddMilliseconds(miningInterval),
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L28-40)
```csharp
            return new ConsensusCommand
            {
                Hint = new AElfConsensusHint
                {
                    Behaviour = AElfConsensusBehaviour.UpdateValue,
                    RoundId = CurrentRound.RoundId,
                    PreviousRoundId = _previousRoundId
                }.ToByteString(),
                ArrangedMiningTime = arrangedMiningTime,
                // Cancel mining after time slot of current miner because of the task queue.
                MiningDueTime = CurrentRound.GetExpectedMiningTime(Pubkey).AddMilliseconds(MiningInterval),
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
            };
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L53-68)
```csharp
        if (hint.Behaviour == AElfConsensusBehaviour.UpdateValue)
        {
            var newInValue = _inValueCache.GetInValue(hint.RoundId);
            var previousInValue = _inValueCache.GetInValue(hint.PreviousRoundId);
            Logger.LogDebug($"New in value {newInValue} for round of id {hint.RoundId}");
            Logger.LogDebug($"Previous in value {previousInValue} for round of id {hint.PreviousRoundId}");
            var trigger = new AElfConsensusTriggerInformation
            {
                Pubkey = Pubkey,
                InValue = newInValue,
                PreviousInValue = previousInValue,
                Behaviour = hint.Behaviour
            };

            return trigger.ToBytesValue();
        }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IInValueCache.cs (L23-33)
```csharp
    public Hash GetInValue(long roundId)
    {
        // Remove old in values. (Keep 10 in values.)
        const int keepInValuesCount = 10;
        if (_inValues.Keys.Count > keepInValuesCount)
            foreach (var id in _inValues.Keys.OrderByDescending(id => id).Skip(keepInValuesCount))
                _inValues.Remove(id);

        _inValues.TryGetValue(roundId, out var inValue);
        return inValue ?? Hash.Empty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L65-69)
```csharp
        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
```

**File:** src/AElf.ContractTestKit.AEDPoSExtension/BlockMiningService.cs (L401-409)
```csharp
        var triggerInformation = new AElfConsensusTriggerInformation
        {
            Behaviour = hint.Behaviour,
            // It doesn't matter for testing.
            InValue = HashHelper.ComputeFrom($"InValueOf{pubkey}"),
            PreviousInValue = HashHelper.ComputeFrom($"InValueOf{pubkey}"),
            Pubkey = pubkey.Value,
            RandomNumber = randomNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-114)
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
```
