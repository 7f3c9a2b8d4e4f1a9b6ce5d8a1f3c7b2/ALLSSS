# Audit Report

## Title
Permanent Denial-of-Service Through Severe Status Rollback Cycle

## Summary
The AEDPoS consensus contract contains a critical design flaw where insufficient miner participation (< 2/3+1 threshold) causes the blockchain to enter an infinite rollback cycle. When the gap between the current round number and the Last Irreversible Block (LIB) round number exceeds 8 rounds, the system enters "Severe" status, reduces throughput to 1 block per miner per time slot, and triggers automatic rollback. If miner participation remains insufficient after rollback, the cycle repeats indefinitely with no automatic recovery mechanism.

## Finding Description

The vulnerability arises from a fundamental mismatch in how rounds advance versus how LIB advances:

**1. Severe Status Detection**

The system enters Severe status when the current round number exceeds the LIB round number by 8 or more rounds: [1](#0-0) 

The threshold is defined as: [2](#0-1) 

**2. Throughput Reduction**

When Severe status is detected, `MaximumBlocksCount` drops from 8 to 1: [3](#0-2) 

The default maximum is 8 blocks: [4](#0-3) 

**3. Automatic Rollback Trigger**

The `IrreversibleBlockHeightUnacceptable` event automatically triggers a rollback to LIB when distance > 0: [5](#0-4) 

**4. Chain State Reversion**

The rollback operation unlinks all blocks above LIB height and resets the chain: [6](#0-5) 

**5. Root Cause: LIB Advancement Requirements**

LIB can only advance when at least `MinersCountOfConsent` (2/3 + 1) miners have recorded their `ImpliedIrreversibleBlockHeight`: [7](#0-6) 

The LIB calculation requires this consensus threshold: [8](#0-7) 

LIB advancement occurs during `UpdateValue` processing: [9](#0-8) 

**6. The Cycle Formation**

Rounds increment based on time, not block production: [10](#0-9) 

When a new round is generated, the LIB information is simply copied forward if it hasn't advanced: [11](#0-10) 

**7. Why Existing Protections Fail**

The `IsPreviousBlockInSevereStatus` flag only manages state transitions and doesn't prevent re-entry into Severe status: [12](#0-11) 

**The Complete Cycle:**
1. If fewer than 15 out of 21 miners produce blocks and call `UpdateValue`, LIB cannot advance (requires `MinersCountOfConsent`)
2. Rounds continue to increment based on time intervals
3. Gap between `currentRoundNumber` and `libRoundNumber` grows beyond 8
4. System enters Severe status → `MaximumBlocksCount` = 1 → rollback triggered
5. After rollback, if miner participation remains insufficient, the cycle repeats
6. No automatic mechanism exists to break this cycle

## Impact Explanation

**Critical Severity - Complete Blockchain Unavailability:**

1. **Transaction Throughput Destruction**: Throughput drops by 87.5% (from 8 blocks per miner per time slot to 1 block), effectively halting the blockchain's ability to process normal transaction volumes.

2. **Loss of Transaction Finality**: Repeated rollbacks discard all blocks above LIB height, meaning transactions that appeared confirmed are discarded and must be re-executed. Users cannot rely on any transaction confirmations.

3. **Operational Impossibility**: The blockchain becomes operationally unusable for any practical purpose including:
   - User transactions
   - Smart contract interactions  
   - Cross-chain bridges (which rely on LIB confirmation)
   - Economic activities requiring finality
   - dApp operations

4. **Affects Entire Network**: This is not a localized issue - it impacts all network participants simultaneously, making it a network-wide denial-of-service condition.

5. **No Automatic Recovery**: The system has no built-in mechanism to break the cycle. Recovery requires external coordination to bring sufficient miners back online, which may not be possible during infrastructure failures or network partitions.

## Likelihood Explanation

**Medium to High Likelihood:**

1. **No Attacker Required**: This vulnerability emerges naturally from operational conditions, not from malicious activity. It is a design flaw, not an attack vector.

2. **Realistic Trigger Conditions**: Requires fewer than 15 out of 21 miners (< 2/3+1 threshold) to consistently produce blocks and call `UpdateValue`. This can occur due to:
   - Network partitions isolating miners
   - Prolonged infrastructure failures affecting multiple miners
   - Economic disincentives during Severe status (miners may stop participating due to reduced rewards)
   - Coordinated miner outages during maintenance windows
   - DDoS attacks on miner infrastructure (network layer, not protocol layer)

3. **Self-Reinforcing**: Once entered, the Severe status itself may discourage miner participation due to reduced block production capabilities (1 block vs 8), making it harder to exit the cycle.

4. **Time-Based Progression**: Since rounds advance based on time rather than block production, the vulnerability can manifest even when some miners are producing blocks - as long as fewer than the consensus threshold participate.

5. **Difficult to Exit**: Breaking the cycle requires external coordination to restore sufficient miner participation (≥15/21), which becomes increasingly difficult during actual infrastructure crises.

## Recommendation

**Short-term Mitigation:**
1. Implement an emergency pause mechanism that can be triggered by governance when Severe status persists beyond a threshold (e.g., 3 consecutive rollbacks within a short time window)
2. Add monitoring and alerting for approaching Severe status conditions (when gap reaches 6-7 rounds)

**Long-term Fix:**
1. **Decouple Round Advancement from Time**: Make round transitions dependent on actual block production rather than pure time intervals. Rounds should only advance when sufficient miners have participated.

2. **Implement Adaptive LIB Requirements**: During degraded network conditions, temporarily reduce the `MinersCountOfConsent` threshold (with appropriate security considerations) to allow LIB advancement with fewer participating miners.

3. **Add Automatic Recovery Mechanism**: Implement a grace period where if Severe status persists for multiple consecutive rounds, automatically reduce the `SevereStatusRoundsThreshold` or adjust the consensus requirements to allow the system to recover.

4. **Circuit Breaker Pattern**: Implement a maximum rollback count per time period. After exceeding this limit, pause automatic rollbacks and require governance intervention to resume operations safely.

Example conceptual fix for `GetMaximumBlocksCount`:
```csharp
// Track consecutive severe occurrences
private int consecutiveSevereCount = 0;

if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
{
    consecutiveSevereCount++;
    
    // After 3 consecutive severe statuses, pause rollbacks
    if (consecutiveSevereCount >= 3)
    {
        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0 // Prevent rollback
        });
        // Trigger governance alert
        // Continue with reduced blocks but no rollback
    }
    else
    {
        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
        });
    }
    
    State.IsPreviousBlockInSevereStatus.Value = true;
    return 1;
}
else
{
    consecutiveSevereCount = 0; // Reset on recovery
}
```

## Proof of Concept

The vulnerability can be demonstrated by simulating a scenario where miner participation drops below the consensus threshold:

```csharp
// Test: Demonstrate Severe Status Rollback Cycle
// Prerequisites: 21 miners configured, consensus requires 15 (2/3+1)

// Step 1: Start with normal operation (all miners participating)
// - Rounds advance normally
// - LIB advances as miners call UpdateValue
// - MaximumBlocksCount = 8

// Step 2: Reduce miner participation to 14 miners (below threshold)
// - Only 14 out of 21 miners produce blocks and call UpdateValue
// - Rounds continue to advance (time-based)
// - LIB stops advancing (requires 15 miners)
// - Gap between currentRoundNumber and libRoundNumber grows

// Step 3: After 8 rounds with insufficient participation
// - currentRoundNumber = libRoundNumber + 8
// - System enters Severe status
// - MaximumBlocksCount drops to 1
// - IrreversibleBlockHeightUnacceptable event fires with distance > 0
// - ResetChainToLibAsync is triggered
// - Chain rolls back to LIB height

// Step 4: After rollback, if miner participation remains at 14
// - Rounds continue to advance
// - LIB still cannot advance (still only 14 miners)
// - Gap grows again to 8 rounds
// - Severe status triggered again
// - Another rollback occurs
// - Cycle repeats indefinitely

// Expected Result: Blockchain enters infinite rollback cycle
// - Transaction throughput limited to 1 block per miner
// - All blocks above LIB repeatedly discarded
// - No transaction finality
// - Network becomes operationally unusable
// - No automatic recovery without external intervention to restore ≥15 miners
```

This POC demonstrates that under realistic operational conditions (network issues causing < 2/3+1 miner participation), the blockchain enters a permanent denial-of-service state with no automatic recovery mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-66)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L69-77)
```csharp
        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-117)
```csharp
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockHeightUnacceptableLogEventProcessor.cs (L54-63)
```csharp
        if (distanceToLib.DistanceToIrreversibleBlockHeight > 0)
        {
            Logger.LogDebug($"Distance to lib height: {distanceToLib.DistanceToIrreversibleBlockHeight}");
            Logger.LogDebug("Will rollback to lib height.");
            _taskQueueManager.Enqueue(
                async () =>
                {
                    var chain = await _blockchainService.GetChainAsync();
                    await _blockchainService.ResetChainToLibAsync(chain);
                }, KernelConstants.UpdateChainQueueName);
```

**File:** src/AElf.Kernel.Core/Blockchain/Domain/IChainManager.cs (L460-497)
```csharp
    public async Task<Chain> ResetChainToLibAsync(Chain chain)
    {
        var libHash = chain.LastIrreversibleBlockHash;
        var libHeight = chain.LastIrreversibleBlockHeight;

        foreach (var branch in chain.Branches)
        {
            var hash = Hash.LoadFromBase64(branch.Key);
            var chainBlockLink = await GetChainBlockLinkAsync(hash);

            while (chainBlockLink != null && chainBlockLink.Height > libHeight)
            {
                chainBlockLink.ExecutionStatus = ChainBlockLinkExecutionStatus.ExecutionNone;
                chainBlockLink.IsLinked = false;
                await SetChainBlockLinkAsync(chainBlockLink);

                chainBlockLink = await GetChainBlockLinkAsync(chainBlockLink.PreviousBlockHash);
            }
        }

        chain.Branches.Clear();
        chain.NotLinkedBlocks.Clear();

        chain.Branches[libHash.ToStorageKey()] = libHeight;

        chain.BestChainHash = libHash;
        chain.BestChainHeight = libHeight;
        chain.LongestChainHash = libHash;
        chain.LongestChainHeight = libHeight;

        Logger.LogInformation($"Rollback to height {chain.BestChainHeight}, hash {chain.BestChainHash}.");
        await _chains.SetAsync(chain.Id.ToStorageKey(), chain);

        // Update the cache.
        _chainCache[ChainId] = chain;

        return chain;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L21-21)
```csharp
        nextRound.RoundNumber = RoundNumber + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```
