# Audit Report

## Title
Inconsistent Miner Count Threshold Causes LIB Calculation Failure During Term Transitions

## Summary
A mathematical inconsistency in the `LastIrreversibleBlockHeightCalculator` prevents Last Irreversible Block (LIB) advancement during term transitions when new miners join. The algorithm compares a filtered count of previous round miners against a threshold calculated from all current round miners, causing legitimate LIB updates to fail when the miner list changes.

## Finding Description

The vulnerability exists in the LIB calculation algorithm within the `Deconstruct()` method of the `LastIrreversibleBlockHeightCalculator` class. [1](#0-0) 

The bug stems from an asymmetric miner counting approach:

1. **Current Round Miners**: The method retrieves miners who successfully mined in the current round using `GetMinedMiners()`, which returns miners where `SupposedOrderOfNextRound != 0`. [2](#0-1) 

2. **Previous Round Filtering**: These current round miner pubkeys are used to filter the previous round via `GetSortedImpliedIrreversibleBlockHeights()`. [3](#0-2)  This filtering excludes any new miners who didn't exist in the previous round.

3. **Threshold Calculation**: The filtered count is compared against `MinersCountOfConsent`, which is calculated as `RealTimeMinersInformation.Count * 2/3 + 1` based on ALL current round miners. [4](#0-3) 

During term transitions, the miner list is updated via `ProcessNextTerm()`. [5](#0-4)  New miners join and are marked with `IsMinerListJustChanged = true`. [6](#0-5) 

When miners subsequently call `UpdateValue` to submit block information, the LIB calculator is invoked. [7](#0-6) 

**Critical Flaw**: New miners who mined in the current round cannot contribute to the filtered count because they don't exist in the previous round's `RealTimeMinersInformation`. However, they ARE included in the denominator when calculating `MinersCountOfConsent`. This creates an artificial deficit that fails the threshold check even when sufficient miners participated.

## Impact Explanation

**Medium Severity - Operational Disruption with Temporary Finality Delay**

When the threshold check fails, `libHeight` is set to 0, preventing LIB advancement. The `IrreversibleBlockFound` event is not fired when the calculated LIB is not greater than the current confirmed height, [8](#0-7)  which means the blockchain service's LIB update mechanism is not triggered. [9](#0-8) 

**Concrete Impact**:
- Cross-chain operations that depend on LIB are delayed, as the cross-chain module listens for `NewIrreversibleBlockFoundEvent`. [10](#0-9) 
- Finality guarantees are postponed for all new blocks during the affected rounds
- Network participants cannot rely on irreversibility confirmation during term transitions
- Side chains waiting for main chain LIB updates experience delays

**Example Scenario**:
- Previous round: 7 miners [A, B, C, D, E, F, G]
- Current round after term transition: 7 miners [D, E, F, G, H, I, J]
- 5 miners successfully mined: [D, E, G, H, I]
- Threshold: 7 × 2/3 + 1 = 5 miners required
- Filtered count: Only 3 (D, E, G existed in previous round; H, I are new)
- Check fails: 3 < 5, despite 5 legitimate participants

The issue is self-resolving once new miners establish presence across multiple rounds, limiting it to Medium severity rather than High.

## Likelihood Explanation

**High Likelihood - Triggered by Normal Consensus Operations**

This vulnerability occurs during regular network operations without requiring any attacker:

1. **Trigger Frequency**: Every term transition where the miner list changes. Term transitions are part of normal AEDPoS consensus flow.

2. **Entry Point**: The public `UpdateValue` method, called by miners during standard block production workflow.

3. **Preconditions**: Only requires that new miners join during a term transition - a routine occurrence in election-based consensus.

4. **Detection**: Observable through monitoring when LIB height stops advancing for 1-2 rounds after term changes, despite normal block production continuing.

The vulnerability affects the first rounds of each new term proportionally to the number of new miners joining. With significant miner set changes (e.g., 30-50% turnover), the issue becomes highly likely to manifest.

## Recommendation

Fix the asymmetric counting by using consistent miner sets for both the threshold calculation and the filtered count. Two possible approaches:

**Option 1 - Use Previous Round Threshold**:
Calculate `MinersCountOfConsent` from the previous round's miner count instead of the current round:
```csharp
if (impliedIrreversibleHeights.Count < _previousRound.MinersCountOfConsent)
```

**Option 2 - Filter Both Rounds by Common Miners**:
Only consider miners that exist in both rounds for LIB calculation:
```csharp
var commonMiners = _currentRound.GetMinedMiners()
    .Where(m => _previousRound.RealTimeMinersInformation.ContainsKey(m.Pubkey))
    .Select(m => m.Pubkey).ToList();
var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(commonMiners);
var threshold = commonMiners.Count.Mul(2).Div(3).Add(1);
if (impliedIrreversibleHeights.Count < threshold)
```

**Option 3 - Skip LIB Calculation During Term Transitions**:
Defer LIB advancement for the first round of a new term when `IsMinerListJustChanged` is true, allowing new miners to establish history.

## Proof of Concept

```csharp
[Fact]
public void TestLIBCalculationFailsDuringTermTransition()
{
    // Setup: Create previous round with 7 miners
    var previousRound = new Round
    {
        RoundNumber = 1,
        TermNumber = 1,
        RealTimeMinersInformation =
        {
            ["MinerA"] = new MinerInRound { Pubkey = "MinerA", ImpliedIrreversibleBlockHeight = 100 },
            ["MinerB"] = new MinerInRound { Pubkey = "MinerB", ImpliedIrreversibleBlockHeight = 100 },
            ["MinerC"] = new MinerInRound { Pubkey = "MinerC", ImpliedIrreversibleBlockHeight = 100 },
            ["MinerD"] = new MinerInRound { Pubkey = "MinerD", ImpliedIrreversibleBlockHeight = 100 },
            ["MinerE"] = new MinerInRound { Pubkey = "MinerE", ImpliedIrreversibleBlockHeight = 100 },
            ["MinerF"] = new MinerInRound { Pubkey = "MinerF", ImpliedIrreversibleBlockHeight = 100 },
            ["MinerG"] = new MinerInRound { Pubkey = "MinerG", ImpliedIrreversibleBlockHeight = 100 }
        }
    };

    // Current round after term transition: 4 new miners joined (H, I, J, K), 3 old remain (D, E, G)
    var currentRound = new Round
    {
        RoundNumber = 2,
        TermNumber = 2,
        IsMinerListJustChanged = true,
        RealTimeMinersInformation =
        {
            ["MinerD"] = new MinerInRound { Pubkey = "MinerD", SupposedOrderOfNextRound = 1 },
            ["MinerE"] = new MinerInRound { Pubkey = "MinerE", SupposedOrderOfNextRound = 2 },
            ["MinerG"] = new MinerInRound { Pubkey = "MinerG", SupposedOrderOfNextRound = 3 },
            ["MinerH"] = new MinerInRound { Pubkey = "MinerH", SupposedOrderOfNextRound = 4 }, // NEW
            ["MinerI"] = new MinerInRound { Pubkey = "MinerI", SupposedOrderOfNextRound = 5 }, // NEW
            ["MinerJ"] = new MinerInRound { Pubkey = "MinerJ", SupposedOrderOfNextRound = 6 }, // NEW
            ["MinerK"] = new MinerInRound { Pubkey = "MinerK", SupposedOrderOfNextRound = 7 }  // NEW
        }
    };

    // All 7 miners mined successfully in current round
    var calculator = new LastIrreversibleBlockHeightCalculator(currentRound, previousRound);
    calculator.Deconstruct(out var libHeight);

    // Expected: LIB should advance (7 miners mined, threshold is 7*2/3+1 = 5)
    // Actual: libHeight = 0 because only 3 miners (D,E,G) existed in previous round
    // Filtered count: 3 < Threshold: 5 -> FAILS despite 7 participants
    
    Assert.Equal(0, libHeight); // This demonstrates the bug
    
    // The correct behavior would be libHeight = 100
    // But due to the asymmetric counting, LIB advancement is blocked
}
```

This test demonstrates that when 4 out of 7 miners are new (57% turnover), the LIB calculation fails even though all 7 miners participated, as only the 3 existing miners contribute to the filtered count while the threshold requires 5.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L47-87)
```csharp
    protected override async Task ProcessLogEventAsync(Block block, LogEvent logEvent)
    {
        var irreversibleBlockFound = new IrreversibleBlockFound();
        irreversibleBlockFound.MergeFrom(logEvent);
        await ProcessLogEventAsync(block, irreversibleBlockFound);
    }

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

**File:** src/AElf.CrossChain/CrossChainModuleEventHandler.cs (L25-28)
```csharp
    public async Task HandleEventAsync(NewIrreversibleBlockFoundEvent eventData)
    {
        await _crossChainService.UpdateCrossChainDataWithLibAsync(eventData.BlockHash, eventData.BlockHeight);
    }
```
