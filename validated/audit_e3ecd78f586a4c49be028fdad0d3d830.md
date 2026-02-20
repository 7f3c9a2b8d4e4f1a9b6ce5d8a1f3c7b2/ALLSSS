# Audit Report

## Title
Last Irreversible Block (LIB) Height Stuck at Zero During Round 2 Due to Missing ImpliedIrreversibleBlockHeight Updates in Non-UpdateValue Behaviors

## Summary
The AEDPoS consensus mechanism only updates the `ImpliedIrreversibleBlockHeight` field during UpdateValue behavior. When Round 1 completes via NextRound without any UpdateValue blocks (e.g., when the first miner is offline), all Round 2 miners are created with `ImpliedIrreversibleBlockHeight = 0`. This causes the LIB calculation in Round 2 to filter out all Round 1 miners, resulting in an empty list that keeps LIB stuck at 0 throughout the entire Round 2, blocking all finality-dependent operations including cross-chain transfers.

## Finding Description

**Root Cause:**

The `ImpliedIrreversibleBlockHeight` field is exclusively set during UpdateValue behavior: [1](#0-0) 

However, other consensus behaviors do NOT update this field:
- **TinyBlock behavior**: [2](#0-1) 

- **NextRound behavior**: [3](#0-2) 

- **NextTerm behavior**: [4](#0-3) 

**Vulnerable Execution Path:**

1. **First Miner Offline in Round 1**: The consensus behavior logic contains a special rule where non-first miners trigger NextRound if the first miner hasn't produced blocks: [5](#0-4) 

2. **NextRound Generation Without ImpliedIrreversibleBlockHeight**: When NextRound is triggered, `GenerateNextRoundInformation` creates NEW `MinerInRound` objects that only populate specific fields and do NOT set `ImpliedIrreversibleBlockHeight`: [6](#0-5) [7](#0-6) 

3. **Round 2 LIB Calculation Failure**: During Round 2, the LIB calculator retrieves miners from the current round and fetches their `ImpliedIrreversibleBlockHeight` values from the previous round (Round 1): [8](#0-7) 

4. **Empty List After Filtering**: The `GetSortedImpliedIrreversibleBlockHeights` method filters miners with `ImpliedIrreversibleBlockHeight > 0`: [9](#0-8) 

Since all Round 1 miners have `ImpliedIrreversibleBlockHeight = 0` (never set, default protobuf value), the filtered list is empty and `libHeight` is set to 0.

5. **LIB Update Condition Fails**: The LIB update logic only updates if the new LIB is strictly higher than the current LIB: [10](#0-9) 

Since both `libHeight` and `ConfirmedIrreversibleBlockHeight` are 0, the condition (0 < 0) evaluates to false, and LIB remains stuck at 0 throughout Round 2.

## Impact Explanation

**High Severity - Denial of Service on Consensus Finality:**

This vulnerability creates a critical operational failure with the following impacts:

1. **LIB Stuck at Zero**: Throughout the entire Round 2, the Last Irreversible Block height remains at 0, meaning NO blocks are confirmed as irreversible.

2. **Cross-Chain Operations Blocked**: Cross-chain systems rely on irreversible block confirmations. The event handler that triggers cross-chain updates only fires when LIB advances: [11](#0-10) [12](#0-11) 

With LIB at 0, cross-chain transfers and state synchronization cannot proceed.

3. **Finality-Dependent Applications Fail**: Any application or service waiting for transaction finality will be indefinitely blocked.

4. **Recovery Requires Full Round**: LIB can only recover in Round 3 when the calculator can reference Round 2's miners who have non-zero `ImpliedIrreversibleBlockHeight` values.

This constitutes a direct violation of the consensus invariant that LIB must progress monotonically with block production.

## Likelihood Explanation

**Medium to High Likelihood During Genesis/Initialization:**

The vulnerability triggers when Round 1 completes without any miner producing an UpdateValue block:

1. **First Miner Failure**: The miner with Order == 1 in Round 1 must fail to produce blocks due to network issues, node offline, delayed startup, or configuration errors.

2. **Automatic NextRound Trigger**: The consensus protocol itself enforces this behavior - when the first miner hasn't produced blocks, other miners automatically return NextRound behavior. This is not an edge case but a designed protocol mechanism.

3. **Genesis/Initialization Vulnerability Window**: This scenario is most likely during initial chain deployment when network connectivity may be unstable or configuration errors affect the first miner.

**No Sophisticated Attack Required**: This can occur naturally due to network issues or can be trivially induced by a malicious first miner simply going offline during Round 1.

## Recommendation

Modify `GenerateNextRoundInformation` to preserve `ImpliedIrreversibleBlockHeight` from the previous round when creating new `MinerInRound` objects:

```csharp
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minerInRound.Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots,
    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight  // ADD THIS
};
```

Alternatively, modify `GetSortedImpliedIrreversibleBlockHeights` to use a fallback mechanism when all heights are 0, or modify the LIB calculator to handle the empty list case more gracefully by using the previous round's `ConfirmedIrreversibleBlockHeight` as a minimum.

## Proof of Concept

The vulnerability can be reproduced by:

1. Initialize a chain with Round 1 containing multiple miners
2. Configure the first miner (Order == 1) to not produce blocks
3. Allow the second miner to trigger NextRound behavior (automatically happens per ConsensusBehaviourProviderBase logic)
4. Observe that Round 2 begins with all miners having `ImpliedIrreversibleBlockHeight = 0`
5. When miners in Round 2 produce UpdateValue blocks, verify that LIB remains at 0 because the calculator filters out all Round 1 heights
6. Verify that no `IrreversibleBlockFound` events are fired
7. Confirm that cross-chain operations remain blocked throughout Round 2

The test should validate that `GetSortedImpliedIrreversibleBlockHeights` returns an empty list when querying Round 1 miners after a NextRound transition without any UpdateValue blocks in Round 1.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L94-102)
```csharp
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-55)
```csharp
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-19)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
    }
```

**File:** src/AElf.CrossChain/CrossChainModuleEventHandler.cs (L25-28)
```csharp
    public async Task HandleEventAsync(NewIrreversibleBlockFoundEvent eventData)
    {
        await _crossChainService.UpdateCrossChainDataWithLibAsync(eventData.BlockHash, eventData.BlockHeight);
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
