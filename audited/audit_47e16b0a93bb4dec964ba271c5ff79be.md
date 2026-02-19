### Title
Chain Reorganization Causes State Read Failure and Permanent Chain Halt

### Summary
During chain reorganization, the blockchain state manager incorrectly rejects state reads from the new canonical chain when the abandoned fork's state was previously merged at the same block height. This causes consensus validation to fail with an "cannot read history state" exception, preventing valid blocks from being processed and resulting in permanent chain halt.

### Finding Description

The vulnerability exists in the state reading mechanism used during consensus validation. When validating a block, the system reads consensus state from the parent block using `TryToGetCurrentRoundInformation()` [1](#0-0) , which internally calls `BlockchainStateManager.GetAsync()` [2](#0-1) .

The root cause is in `BlockchainStateManager.GetAsync()` where it checks if the best chain state (from `VersionedStates`) has a block height greater than or equal to the requested block height [3](#0-2) . When this condition is true and the block hashes don't match, it throws an `InvalidOperationException` assuming the caller is trying to read old history that should no longer be accessible.

**Exploit Path:**

1. Fork A is the best chain and reaches height 100
2. Consensus determines LIB advances to block A_100 at height 100, firing an `IrreversibleBlockFound` event [4](#0-3) 
3. `NewIrreversibleBlockFoundEventHandler` processes the event and calls `MergeBlockStateAsync()` [5](#0-4) 
4. State from blocks up to A_100 is merged into `VersionedStates` with `blockHash=A_100, blockHeight=100`
5. Fork B appears with greater length/difficulty and becomes the longest chain
6. `BlockAttachService.AttachBlockAsync()` attempts to execute Fork B's blocks [6](#0-5) 
7. When executing block B_101, validation reads state using `ChainContext(blockHash=B_100, blockHeight=100)` [7](#0-6) 
8. The consensus service creates a contract reader context from this chain context [8](#0-7) 
9. `BlockchainStateManager.GetAsync()` is called with `blockHeight=100, blockHash=B_100`
10. Since `VersionedStates` contains merged state with `blockHash=A_100, blockHeight=100`, and `100 >= 100` is true, the exception is thrown before the search in `BlockStateSets` can occur
11. Block execution fails, the branch is marked as `ExecutionFailed`
12. The chain cannot progress beyond the reorganization point

The `LibInformationValidationProvider.ValidateHeaderInformation()` logic itself [9](#0-8)  is not reached because the exception occurs during the state read in `ValidateBeforeExecution()`.

### Impact Explanation

**Consensus Integrity Failure**: The chain experiences permanent halt at the reorganization point. Valid blocks from the new canonical chain are incorrectly rejected, preventing consensus from progressing.

**Complete DoS**: Once triggered, the node cannot recover without manual intervention to reset chain state. All subsequent blocks on the new canonical fork are rejected, effectively destroying the node's ability to participate in consensus.

**Network-Wide Impact**: If multiple nodes experience the same reorganization scenario simultaneously (during network partitions or coordinated mining), the entire network consensus can fail, requiring coordinated manual recovery.

**Irreversible State**: The merged state from the abandoned fork remains in `VersionedStates`, permanently blocking state reads from the correct fork at those heights. The cleanup mechanism in `NewIrreversibleBlockFoundEventHandler` [10](#0-9)  only cleans up block state sets, not the merged versioned states from abandoned forks.

This violates the critical invariant for "Consensus & Cross-Chain: Correct round transitions and time-slot validation, miner schedule integrity, LIB height rules."

### Likelihood Explanation

**Feasible Preconditions**:
- Network fork must occur (moderate likelihood during network partitions or competing miners)
- LIB must advance on the abandoned fork before reorganization (high likelihood as LIB advances regularly through consensus)
- New fork must reach same or higher height as merged LIB (high likelihood in typical reorg scenarios)

**Attack Complexity**: No attacker action required - this is a natural consequence of normal fork resolution combined with LIB advancement. The scenario occurs through normal blockchain operation.

**Practical Occurrence**: Chain reorganizations are expected events in any blockchain system. Combined with continuous LIB advancement (which happens in every round through the consensus mechanism processing update values), this creates a realistic scenario with **MEDIUM to HIGH probability** in production environments.

**No Special Privileges Required**: This affects normal node operation and requires no attacker privileges or capabilities beyond the natural occurrence of network forks.

### Recommendation

**Immediate Fix**: Modify `BlockchainStateManager.GetAsync()` to handle cross-fork state reads during reorganizations:

```csharp
// In GetAsync method, lines 118-128
if (bestChainState.BlockHash == blockHash)
{
    value = bestChainState.Value;
    isInStore = true;
}
else
{
    if (bestChainState.BlockHeight > blockHeight)
        throw new InvalidOperationException(...);
    
    // When heights are equal, search BlockStateSets instead of throwing
    var blockStateSet = await FindBlockStateSetWithKeyAsync(key, 
        Math.Min(bestChainState.BlockHeight, blockHeight - 1), blockHash);
    
    TryGetFromBlockStateSet(blockStateSet, key, out value);
    
    if (value == null && blockStateSet == null)
    {
        bestChainState = await VersionedStates.GetAsync(key);
        value = bestChainState?.Value;
    }
}
```

**Additional Safeguards**:
1. Track fork lineage in `ChainBlockLink` to identify when reading from a different fork
2. During reorganization, delay state merging until the new best chain is confirmed stable
3. Add `FindBlockStateSetWithKeyAsync()` logic to handle equal heights by checking if the block is reachable from the requested hash [11](#0-10) 

**Test Cases**:
1. Create fork at height 50, advance LIB to height 100 on Fork A
2. Introduce Fork B from height 50 to height 101
3. Attempt to execute Fork B blocks - should succeed without state read exceptions
4. Verify state reads correctly use BlockStateSets for Fork B even when Fork A state is merged at overlapping heights

### Proof of Concept

**Initial State**:
- Genesis block at height 0
- Fork A: blocks 1-100, all executed and LIB advanced to block 100
- `VersionedStates` contains merged state: `{"Consensus.CurrentRoundNumber": {value: 50, blockHash: A_100, blockHeight: 100}}`

**Exploit Steps**:
1. Create Fork B from genesis: blocks B_1 through B_101
2. Attach block B_101 to chain via `BlockAttachService.AttachBlockAsync(B_101)`
3. System detects `LongestChainFound` status
4. `GetNotExecutedBlocks(B_101)` returns `[B_1, B_2, ..., B_100, B_101]`
5. `ExecuteBlocksAsync()` begins executing blocks sequentially
6. When executing B_101:
   - `ValidateBlockBeforeExecuteAsync()` creates `ChainContext{blockHash: B_100, blockHeight: 100}`
   - Consensus validation attempts to read state with these parameters
   - `BlockchainStateManager.GetAsync("Consensus.CurrentRoundNumber", 100, B_100)` is invoked
   
**Expected Result**: State should be read from B_100's `BlockStateSet`, validation succeeds, block executes successfully.

**Actual Result**: `InvalidOperationException` thrown with message "cannot read history state, best chain state hash: {A_100_hash}, key: Consensus.CurrentRoundNumber, block height: 100, block hash: {B_100_hash}". Block execution fails, Fork B rejected permanently.

**Success Condition**: Node permanently unable to process Fork B, chain halted at height 100, requiring manual state database reset to recover.

### Notes

This vulnerability affects the core state reading mechanism rather than the specific validation logic in `LibInformationValidationProvider.ValidateHeaderInformation()`. The validation at line 16 is correct but never reached due to the earlier state read failure. The bug fundamentally breaks the assumption that merged state from the "best chain" is always the correct state to read - during reorganizations, different forks at the same height must coexist until the reorganization completes.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** src/AElf.Kernel.Core/SmartContract/Domain/IBlockchainStateManager.cs (L120-123)
```csharp
                if (bestChainState.BlockHeight >= blockHeight)
                    //because we may clear history state
                    throw new InvalidOperationException(
                        $"cannot read history state, best chain state hash: {bestChainState.BlockHash.ToHex()}, key: {key}, block height: {blockHeight}, block hash{blockHash.ToHex()}");
```

**File:** src/AElf.Kernel.Core/SmartContract/Domain/IBlockchainStateManager.cs (L165-185)
```csharp
    private async Task<BlockStateSet> FindBlockStateSetWithKeyAsync(string key, long bestChainHeight,
        Hash blockHash)
    {
        var blockStateKey = blockHash.ToStorageKey();
        var blockStateSet = await BlockStateSets.GetAsync(blockStateKey);

        while (blockStateSet != null && blockStateSet.BlockHeight > bestChainHeight)
        {
            if (
                TryGetFromBlockStateSet(blockStateSet, key, out _)) break;

            blockStateKey = blockStateSet.PreviousHash?.ToStorageKey();

            if (blockStateKey != null)
                blockStateSet = await BlockStateSets.GetAsync(blockStateKey);
            else
                blockStateSet = null;
        }

        return blockStateSet;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L54-87)
```csharp
    private async Task ProcessLogEventAsync(Block block, IrreversibleBlockFound irreversibleBlockFound)
    {
        try
        {
            var chain = await _blockchainService.GetChainAsync();

            if (chain.LastIrreversibleBlockHeight > irreversibleBlockFound.IrreversibleBlockHeight)
                return;

            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;

            if (chain.LastIrreversibleBlockHeight == irreversibleBlockFound.IrreversibleBlockHeight) return;

            var blockIndex = new BlockIndex(libBlockHash, irreversibleBlockFound.IrreversibleBlockHeight);
            Logger.LogDebug($"About to set new lib height: {blockIndex.BlockHeight} " +
                            $"Event: {irreversibleBlockFound} " +
                            $"BlockIndex: {blockIndex.BlockHash} - {blockIndex.BlockHeight}");
            _taskQueueManager.Enqueue(
                async () =>
                {
                    var currentChain = await _blockchainService.GetChainAsync();
                    if (currentChain.LastIrreversibleBlockHeight < blockIndex.BlockHeight)
                        await _blockchainService.SetIrreversibleBlockAsync(currentChain, blockIndex.BlockHeight,
                            blockIndex.BlockHash);
                }, KernelConstants.UpdateChainQueueName);
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Failed to resolve IrreversibleBlockFound event.");
            throw;
        }
    }
```

**File:** src/AElf.Kernel/NewIrreversibleBlockFoundEventHandler.cs (L40-51)
```csharp
    public Task HandleEventAsync(NewIrreversibleBlockFoundEvent eventData)
    {
        _taskQueueManager.Enqueue(async () =>
        {
            await _blockchainStateService.MergeBlockStateAsync(eventData.BlockHeight,
                eventData.BlockHash);

            CleanChain(eventData.BlockHash, eventData.BlockHeight);
        }, KernelConstants.MergeBlockStateQueueName);

        return Task.CompletedTask;
    }
```

**File:** src/AElf.Kernel/NewIrreversibleBlockFoundEventHandler.cs (L53-86)
```csharp
    private void CleanChain(Hash irreversibleBlockHash, long irreversibleBlockHeight)
    {
        _taskQueueManager.Enqueue(async () =>
        {
            // Clean BlockStateSet
            var discardedBlockHashes = _chainBlockLinkService.GetCachedChainBlockLinks()
                .Where(b => b.Height <= irreversibleBlockHeight).Select(b => b.BlockHash).ToList();
            await _blockchainStateService.RemoveBlockStateSetsAsync(discardedBlockHashes);

            // Clean chain branch
            var chain = await _blockchainService.GetChainAsync();
            var discardedBranch = await _blockchainService.GetDiscardedBranchAsync(chain);

            _taskQueueManager.Enqueue(
                async () =>
                {
                    if (discardedBranch.BranchKeys.Count > 0 || discardedBranch.NotLinkedKeys.Count > 0)
                        await _blockchainService.CleanChainBranchAsync(discardedBranch);

                    await LocalEventBus.PublishAsync(new CleanBlockExecutedDataChangeHeightEventData
                    {
                        IrreversibleBlockHeight = irreversibleBlockHeight
                    });
                    _chainBlockLinkService.CleanCachedChainBlockLinks(irreversibleBlockHeight);
                },
                KernelConstants.UpdateChainQueueName);

            // Clean transaction block index cache
            await _transactionBlockIndexService.UpdateTransactionBlockIndicesByLibHeightAsync(irreversibleBlockHeight);

            // Clean idle executive
            _smartContractExecutiveService.CleanIdleExecutive();
        }, KernelConstants.ChainCleaningQueueName);
    }
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/IBlockAttachService.cs (L39-69)
```csharp
    public async Task AttachBlockAsync(Block block)
    {
        var chain = await _blockchainService.GetChainAsync();

        var status = await _blockchainService.AttachBlockToChainAsync(chain, block);
        if (!status.HasFlag(BlockAttachOperationStatus.LongestChainFound))
        {
            Logger.LogDebug($"Try to attach to chain but the status is {status}.");
            return;
        }

        var notExecutedChainBlockLinks =
            await _chainBlockLinkService.GetNotExecutedChainBlockLinksAsync(chain.LongestChainHash);
        var notExecutedBlocks =
            await _blockchainService.GetBlocksAsync(notExecutedChainBlockLinks.Select(l => l.BlockHash));

        var executionResult = new BlockExecutionResult();
        try
        {
            executionResult = await _blockchainExecutingService.ExecuteBlocksAsync(notExecutedBlocks);
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Block execute fails.");
            throw;
        }
        finally
        {
            await _blockExecutionResultProcessingService.ProcessBlockExecutionResultAsync(chain, executionResult);
        }
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L70-74)
```csharp
        var isValid = await _consensusService.ValidateConsensusBeforeExecutionAsync(new ChainContext
        {
            BlockHash = block.Header.PreviousBlockHash,
            BlockHeight = block.Header.Height - 1
        }, consensusExtraData.ToByteArray());
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L119-149)
```csharp
    public async Task<bool> ValidateConsensusBeforeExecutionAsync(ChainContext chainContext,
        byte[] consensusExtraData)
    {
        var now = TimestampHelper.GetUtcNow();
        _blockTimeProvider.SetBlockTime(now, chainContext.BlockHash);

        var contractReaderContext =
            await _consensusReaderContextService.GetContractReaderContextAsync(chainContext);
        var validationResult = await _contractReaderFactory
            .Create(contractReaderContext)
            .ValidateConsensusBeforeExecution
            .CallAsync(new BytesValue { Value = ByteString.CopyFrom(consensusExtraData) });

        if (validationResult == null)
        {
            Logger.LogDebug("Validation of consensus failed before execution.");
            return false;
        }

        if (!validationResult.Success)
        {
            Logger.LogDebug($"Consensus validating before execution failed: {validationResult.Message}");
            await LocalEventBus.PublishAsync(new ConsensusValidationFailedEventData
            {
                ValidationResultMessage = validationResult.Message,
                IsReTrigger = validationResult.IsReTrigger
            });
        }

        return validationResult.Success;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L8-34)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```
