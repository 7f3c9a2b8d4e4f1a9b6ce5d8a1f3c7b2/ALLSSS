### Title
Last Irreversible Block (LIB) Calculation Can Fail Indefinitely With Insufficient Miner Participation

### Summary
The `Deconstruct()` method in `LastIrreversibleBlockHeightCalculator` returns `libHeight = 0` when fewer than `MinersCountOfConsent` (⌈2n/3⌉ + 1) miners have mined blocks with non-zero `ImpliedIrreversibleBlockHeight` values in the previous round. If miner participation consistently stays below this threshold across multiple rounds due to network issues, DDoS attacks, or timing problems, the LIB never advances, preventing block finalization and breaking cross-chain communication.

### Finding Description

The vulnerability exists in the LIB calculation logic: [1](#0-0) 

The calculation retrieves miners who mined in the current round, then fetches their `ImpliedIrreversibleBlockHeight` values from the previous round. If the count is below `MinersCountOfConsent`, it returns 0. [2](#0-1) 

The `MinersCountOfConsent` property calculates the Byzantine Fault Tolerant threshold as `(total_miners * 2 / 3) + 1`.

`ImpliedIrreversibleBlockHeight` is only set during `UpdateValue` behavior when a miner produces their first block in a time slot: [3](#0-2) 

When miners miss their time slots entirely (don't mine at all), their `ImpliedIrreversibleBlockHeight` remains 0 from the default initialization: [4](#0-3) 

The LIB calculation is invoked during block processing: [5](#0-4) 

When `libHeight = 0`, the condition at line 272 fails (since `0 < 0` is false), preventing the `IrreversibleBlockFound` event from firing. Without this event, the blockchain's LIB never advances: [6](#0-5) 

The existing `SolitaryMinerDetection` mechanism only halts consensus when a single miner mines alone for 2 rounds: [7](#0-6) 

This protection doesn't prevent scenarios where 40-65% of miners participate (enough to continue consensus but below the 2/3 threshold needed for LIB calculation).

### Impact Explanation

When LIB remains at 0:

1. **Block Finality Loss**: No blocks become irreversible, eliminating transaction finality guarantees. Users and dApps cannot rely on transaction confirmations.

2. **Cross-Chain Communication Failure**: Cross-chain indexing depends on LIB: [8](#0-7) 

Without advancing LIB, cross-chain transfers, asset bridging, and inter-chain contract calls become blocked or unsafe.

3. **Protocol-Wide Impact**: Affects all users, dApps, side chains, and partner chains relying on finality and cross-chain operations.

4. **Severity**: High - breaks critical protocol invariants for consensus finality and cross-chain integrity.

### Likelihood Explanation

**Attacker Capabilities**: No malicious actors needed; natural network disruptions or operational issues suffice.

**Attack Scenarios**:
- Network partition isolating 35%+ of miners
- DDoS attacks targeting multiple miner nodes simultaneously
- Infrastructure failures (cloud provider outages affecting multiple miners)
- Configuration errors during network upgrades
- Timing synchronization issues

**Execution Practicality**: Example with 7 miners (MinersCountOfConsent = 5):
- Round N-1: Only 4 miners successfully mine blocks
- Round N: Any subset mines, but only 4 have non-zero `ImpliedIrreversibleBlockHeight` from N-1
- Round N LIB calculation: 4 < 5, returns libHeight = 0
- Pattern repeats if participation stays at 4 or below

**Feasibility**: Medium-High probability in adverse conditions. While evil miner detection eventually replaces non-participants, this takes multiple rounds, during which LIB remains stuck at 0.

**Detection**: The system logs "Finished calculation of lib height: 0" but consensus continues, masking the severity until cross-chain operations fail.

### Recommendation

**Immediate Fix**: Add explicit validation and circuit-breaker logic:

```csharp
public void Deconstruct(out long libHeight)
{
    if (_currentRound.IsEmpty || _previousRound.IsEmpty)
    {
        libHeight = 0;
        return; // Add missing return statement
    }

    var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
    var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
    
    // Add warning/alert when participation is insufficient
    if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
    {
        Context.LogWarning(
            $"Insufficient miner participation for LIB calculation: {impliedIrreversibleHeights.Count}/{_currentRound.MinersCountOfConsent}");
        libHeight = 0;
        return;
    }

    libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
}
```

**Additional Protections**:

1. **Fallback LIB Advancement**: If LIB hasn't advanced for N rounds (e.g., 3-5 rounds), use a fallback calculation with relaxed thresholds or use simple "current height - safety margin" approach.

2. **Consensus Halt**: Extend `SolitaryMinerDetection` to halt consensus when participation drops below MinersCountOfConsent threshold for multiple consecutive rounds, preventing indefinite operation without finality.

3. **Emergency LIB Recovery**: Add governance method to manually set LIB during extended outages (requires multi-sig authorization).

4. **Test Cases**: Add regression tests simulating:
   - Sustained participation at 40-65% of miners
   - Alternating sets of miners participating
   - Network partition scenarios
   - Recovery from extended LIB stall

### Proof of Concept

**Initial State**: 7-miner network, MinersCountOfConsent = 5

**Exploitation Steps**:

1. **Round 1-2**: Normal operation, all 7 miners participate, LIB advances normally
2. **Round 3**: Network partition causes 3 miners to go offline. Only miners A, B, C, D participate (4 miners)
   - Each sets their `ImpliedIrreversibleBlockHeight` for round 3
3. **Round 4**: Same 4 miners (A, B, C, D) participate
   - LIB calculation: Gets 4 miners who mined in round 4 (A, B, C, D)
   - Checks their `ImpliedIrreversibleBlockHeight` from round 3: all 4 have non-zero values
   - Count = 4 < MinersCountOfConsent (5)
   - Returns libHeight = 0
   - No `IrreversibleBlockFound` event fired
4. **Round 5-N**: Pattern continues with same 4 miners
   - LIB calculation repeatedly returns 0
   - Cross-chain operations begin failing
   - Transaction finality unavailable

**Expected Result**: LIB should advance or consensus should halt

**Actual Result**: Consensus continues indefinitely without LIB advancement, breaking finality guarantees and cross-chain communication while producing new blocks

**Success Condition**: Observe LIB stuck at 0 for multiple rounds while block height continues increasing, then verify cross-chain indexing service reports errors attempting to fetch data requiring LIB advancement.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-19)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);

    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L23-38)
```csharp
        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L66-96)
```csharp
    private bool SolitaryMinerDetection(Round currentRound, string pubkey)
    {
        var isAlone = false;
        // Skip this detection until 4th round.
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
        {
            // Not single node.

            var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
            isAlone = minedMinersOfCurrentRound.Count == 0;

            // If only this node mined during previous round, stop mining.
            if (TryToGetPreviousRoundInformation(out var previousRound) && isAlone)
            {
                var minedMiners = previousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }

            // check one further round.
            if (isAlone && TryToGetRoundInformation(previousRound.RoundNumber.Sub(1),
                    out var previousPreviousRound))
            {
                var minedMiners = previousPreviousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }
        }

        return isAlone;
    }
```

**File:** src/AElf.CrossChain/CrossChainModuleEventHandler.cs (L25-28)
```csharp
    public async Task HandleEventAsync(NewIrreversibleBlockFoundEvent eventData)
    {
        await _crossChainService.UpdateCrossChainDataWithLibAsync(eventData.BlockHash, eventData.BlockHeight);
    }
```
