### Title
Unhandled Dictionary Access Exception in Consensus Extra Data Generation During Round Transitions

### Summary
The consensus contract's `GetConsensusExtraData` and `GenerateConsensusTransactions` methods directly access `RealTimeMinersInformation` dictionary without validating key existence, unlike `GetConsensusCommand` which performs `IsInMinerList` validation. During round/term transitions where miner lists change, a miner's pubkey may be absent from the new round, causing unhandled `KeyNotFoundException` that disrupts block generation and consensus continuity.

### Finding Description

**Root Cause:**

The vulnerability exists in multiple locations where `currentRound.RealTimeMinersInformation[pubkey]` is accessed without prior key existence validation: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Protection Asymmetry:**

`GetConsensusCommand` properly validates miner list membership before accessing the dictionary: [5](#0-4) 

However, `GetConsensusExtraData` and `GenerateConsensusTransactions` lack this validation: [6](#0-5) [7](#0-6) 

**Execution Flow:**

1. `GetConsensusCommand` retrieves `currentRound` at block height H and validates pubkey membership
2. System schedules mining for future time T based on returned `ConsensusCommand`
3. Between validation and mining time T, round/term transition occurs via `GenerateNextRoundInformation` which modifies miner lists
4. At time T, `GetConsensusExtraDataAsync` calls contract's `GetConsensusExtraData` which retrieves NEW `currentRound`
5. `GetConsensusBlockExtraData` is invoked without miner list validation
6. Dictionary access throws `KeyNotFoundException` when pubkey is absent from new round [8](#0-7) 

**Why Protections Fail:**

The `IsInMinerList` check at line 137 of Round.cs only protects the initial `GetConsensusCommand` call: [9](#0-8) 

This check does NOT protect subsequent calls to `GetConsensusExtraData` or `GenerateConsensusTransactions`, which occur at a later time with potentially different round state. The consensus service has no exception handling: [10](#0-9) 

**Miner List Mutation Evidence:**

The codebase confirms miners can be removed from `RealTimeMinersInformation` during round generation when evil miners are detected and replaced: [11](#0-10) 

### Impact Explanation

**Consensus Disruption:**

When the exception occurs during block generation, the affected miner cannot produce blocks, causing:
- Failed block production attempts consuming system resources
- Missed time slots reducing network throughput
- Potential chain stall if multiple miners affected during coordinated term transition

**Affected Parties:**

- **Miners transitioning out**: Miners replaced due to poor performance or election changes fail to produce final blocks they were scheduled for
- **Network participants**: Block production delays impact transaction confirmation times
- **Protocol integrity**: Consensus mechanism reliability compromised during critical transition periods

**Severity Justification:**

HIGH severity because:
1. Directly impacts core consensus operations (block generation)
2. No exception handling means total failure, not graceful degradation
3. Occurs during normal protocol operations (round/term transitions), not just attack scenarios
4. Affects critical invariant: "Correct round transitions and time-slot validation, miner schedule integrity"

### Likelihood Explanation

**Attack Complexity:**

No attacker action required - this is a natural race condition in the consensus protocol. The vulnerability triggers through normal system operations:

**Realistic Preconditions:**

1. **Round Transitions**: Occur regularly every ~minutes (configurable) when miners complete time slots
2. **Term Transitions**: Occur periodically during election cycles when new validators are selected
3. **Miner Replacements**: Automatic when miners miss too many time slots or behave maliciously
4. **Timing Window**: Gap between `GetConsensusCommand` (validation time) and `GetConsensusExtraData` (usage time) is inherent to consensus scheduling

**Feasibility:**

The trigger information provider always uses the current node's pubkey: [12](#0-11) 

Miners in transition have valid consensus commands but are absent from new rounds, making the scenario guaranteed during:
- Every term change affecting outgoing validators
- Evil miner replacements (automatic enforcement)
- Election result changes between rounds

**Probability:**

MODERATE to HIGH frequency:
- Occurs at EVERY term boundary for replaced miners
- Occurs during mid-term miner replacements
- Higher probability in networks with frequent validator set changes
- No manual trigger or privileged access required

### Recommendation

**Immediate Fix:**

Add key existence validation in `GetConsensusBlockExtraData` before calling behavior-specific methods:

```csharp
private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
{
    var triggerInformation = new AElfConsensusTriggerInformation();
    triggerInformation.MergeFrom(input.Value);
    
    Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");
    
    TryToGetCurrentRoundInformation(out var currentRound);
    
    var publicKeyBytes = triggerInformation.Pubkey;
    var pubkey = publicKeyBytes.ToHex();
    
    // ADD THIS CHECK:
    if (!currentRound.IsInMinerList(pubkey))
    {
        // Return empty/default consensus information for miners not in current round
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = publicKeyBytes,
            Round = currentRound,
            Behaviour = AElfConsensusBehaviour.Nothing
        }.ToBytesValue();
    }
    
    // ... rest of method
}
```

**Alternative Protection:**

Add `ContainsKey` checks before each dictionary access:

```csharp
if (currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = ...
    // ... other accesses
}
```

**Test Cases:**

1. Simulate term transition where miner A receives `GetConsensusCommand` in term N, then term N+1 starts without miner A, followed by miner A calling `GetConsensusExtraData`
2. Trigger evil miner replacement mid-round, verify replaced miner's subsequent block attempts handled gracefully
3. Test concurrent round transition during block generation flow

### Proof of Concept

**Initial State:**
- Network running with 5 miners: [A, B, C, D, E]
- Current round N at height 1000
- Miner A scheduled to produce block at height 1001
- Miner A detected as evil (missed timeouts) and marked for replacement

**Exploitation Steps:**

1. **T=0ms**: Miner A calls `GetConsensusCommand` at height 1000
   - `currentRound` = Round N with miners [A, B, C, D, E]
   - `IsInMinerList("A")` returns `true` ✓
   - Returns valid `ConsensusCommand` with arranged mining time T=5000ms

2. **T=3000ms**: Miner D produces block at height 1001 calling `NextRound`
   - `GenerateNextRoundInformation` executes
   - Detects miner A as evil (missed time slots)
   - Calls Election contract `GetMinerReplacementInformation`
   - Removes A from `RealTimeMinersInformation`
   - Adds replacement miner F
   - New round N+1 with miners [B, C, D, E, F]

3. **T=5000ms**: Miner A attempts to produce block
   - Calls `GetConsensusExtraData` 
   - `TryToGetCurrentRoundInformation` returns Round N+1
   - `GetConsensusBlockExtraData` extracts pubkey "A"
   - NO `IsInMinerList` check performed
   - Accesses `currentRound.RealTimeMinersInformation["A"]` at line 58
   - **KeyNotFoundException thrown**
   - Block generation fails completely

**Expected Result:**
Miner A gracefully handles transition, either producing no block or handling with proper error

**Actual Result:**
Unhandled exception crashes block generation flow, miner A unable to participate until manual restart

**Success Condition:**
Exception logged in consensus service, miner A excluded from round N+1 without system-level failure

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L20-31)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);

        var publicKeyBytes = triggerInformation.Pubkey;
        var pubkey = publicKeyBytes.ToHex();

        var information = new AElfConsensusHeaderInformation();
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L58-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L116-118)
```csharp
                  $"{updatedRound.RealTimeMinersInformation[pubkey].PreviousInValue}");

        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L140-140)
```csharp
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L158-163)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L26-27)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L61-74)
```csharp
    public override TransactionList GenerateConsensusTransactions(BytesValue input)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);
        // Some basic checks.
        Assert(triggerInformation.Pubkey.Any(),
            "Data to request consensus information should contain pubkey.");

        var pubkey = triggerInformation.Pubkey;
        var randomNumber = triggerInformation.RandomNumber;
        var consensusInformation = new AElfConsensusHeaderInformation();
        consensusInformation.MergeFrom(GetConsensusBlockExtraData(input, true).Value);
        var transactionList = GenerateTransactionListByExtraData(consensusInformation, pubkey, randomNumber);
        return transactionList;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L195-209)
```csharp
    public async Task<byte[]> GetConsensusExtraDataAsync(ChainContext chainContext)
    {
        _blockTimeProvider.SetBlockTime(_nextMiningTime, chainContext.BlockHash);

        Logger.LogDebug(
            $"Block time of getting consensus extra data: {_nextMiningTime.ToDateTime():hh:mm:ss.ffffff}.");

        var contractReaderContext =
            await _consensusReaderContextService.GetContractReaderContextAsync(chainContext);
        var input = _triggerInformationProvider.GetTriggerInformationForBlockHeaderExtraData(
            _consensusCommand.ToBytesValue());
        var consensusContractStub = _contractReaderFactory.Create(contractReaderContext);
        var output = await consensusContractStub.GetConsensusExtraData.CallAsync(input);
        return output.Value.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L328-328)
```csharp
                    var minerInRound = new MinerInRound
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L32-32)
```csharp
    private ByteString Pubkey => ByteString.CopyFrom(AsyncHelper.RunSync(_accountService.GetPublicKeyAsync));
```
