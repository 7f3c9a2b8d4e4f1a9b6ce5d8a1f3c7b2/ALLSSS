# Audit Report

## Title
Last Irreversible Block (LIB) Height Stuck at Zero During Round 2 Due to Missing ImpliedIrreversibleBlockHeight Updates in Non-UpdateValue Behaviors

## Summary
The AEDPoS consensus mechanism fails to update the `ImpliedIrreversibleBlockHeight` field during TinyBlock, NextRound, and NextTerm behaviors. When Round 1 completes without any UpdateValue blocks (possible if the first miner is offline and other miners trigger NextRound), all miners enter Round 2 with `ImpliedIrreversibleBlockHeight = 0`. This causes the LIB calculation to fail and keeps LIB stuck at 0 throughout Round 2, blocking cross-chain operations and finality-dependent services.

## Finding Description

The vulnerability stems from incomplete handling of the `ImpliedIrreversibleBlockHeight` field across different consensus behaviors.

**Root Cause Analysis:**

Only the UpdateValue behavior sets `ImpliedIrreversibleBlockHeight` to the current block height. [1](#0-0) 

The other three consensus behaviors do NOT update this field:
- **TinyBlock**: [2](#0-1) 
- **NextRound**: [3](#0-2) 
- **NextTerm**: [4](#0-3) 

**Vulnerable Execution Path:**

1. During Round 1, all miners initialize with `ImpliedIrreversibleBlockHeight = 0` (protobuf int64 default). [5](#0-4) 

2. The consensus behavior logic explicitly allows non-first miners to trigger NextRound if the first miner hasn't produced blocks. [6](#0-5) 

3. When NextRound is triggered, new MinerInRound objects are created copying only `ProducedBlocks` and `MissedTimeSlots` - NOT `ImpliedIrreversibleBlockHeight`. [7](#0-6) [8](#0-7) 

4. In Round 2, when miners produce UpdateValue blocks, the LIB calculator filters Round 1 miners by `ImpliedIrreversibleBlockHeight > 0`. [9](#0-8) 

5. Since all Round 1 miners have value 0, the filtered list is empty. The calculator returns `libHeight = 0`. [10](#0-9) 

6. The LIB update only proceeds if the new value is strictly greater than the current value. [11](#0-10) 

With both values at 0, the condition `0 < 0` is false, so LIB remains stuck at 0.

## Impact Explanation

**High Severity - Denial of Service on Consensus Finality:**

- **LIB Stuck at Zero**: Throughout the entire Round 2 (potentially hundreds of blocks depending on miner count and mining interval), no blocks can be confirmed as irreversible.

- **Cross-Chain Operations Blocked**: Cross-chain indexing validation requires LIB height > genesis height. [12](#0-11) 

With LIB stuck at 0, cross-chain transfers and state synchronization cannot proceed safely. [13](#0-12) 

- **Finality-Dependent Applications Fail**: Any application or service waiting for transaction finality (irreversibility confirmation) will be blocked for an entire round.

- **Recovery Only in Round 3**: LIB can only recover when Round 3 begins and the calculator can reference Round 2's miners who have non-zero `ImpliedIrreversibleBlockHeight` values.

This breaks the fundamental invariant that LIB should monotonically increase as blocks are produced and reach 2/3+ consensus.

## Likelihood Explanation

**Medium to High Likelihood:**

The vulnerability triggers automatically if Round 1 completes without any UpdateValue blocks. This scenario occurs when:

1. **First Miner Failure**: The miner with Order == 1 in Round 1 fails to produce blocks (offline, network issues, delayed node start)

2. **Automatic NextRound Trigger**: The consensus mechanism explicitly designed this as a safety feature - when the first miner hasn't produced blocks, other miners must trigger NextRound to prevent fork blocks. [6](#0-5) 

3. **Genesis/Initialization Vulnerability Window**: This is most likely during initial chain deployment when:
   - Network connectivity may be unstable
   - Miner nodes are still synchronizing  
   - Configuration errors could delay the first miner
   - Genesis timing issues are most common

**No sophisticated attack required** - this can occur naturally due to network conditions, or be induced by a malicious first miner simply going offline during Round 1.

## Recommendation

Update all consensus behaviors (TinyBlock, NextRound, NextTerm) to properly preserve or initialize the `ImpliedIrreversibleBlockHeight` field when creating new round information.

**For NextRound/NextTerm**: When generating new rounds, copy the `ImpliedIrreversibleBlockHeight` from the previous round's miner information:

In `Round_Generation.cs`, when creating new `MinerInRound` objects, add:
```csharp
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minerInRound.Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots,
    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight // ADD THIS
};
```

**For TinyBlock**: In `ProcessTinyBlock`, explicitly preserve the existing `ImpliedIrreversibleBlockHeight` value (no change needed as it doesn't create new objects, but document this invariant).

**Alternative solution**: Initialize `ImpliedIrreversibleBlockHeight` to the current block height for all miners in the genesis round to ensure it starts with a valid value.

## Proof of Concept

```csharp
// Test scenario demonstrating LIB stuck at 0 during Round 2
// Prerequisites:
// 1. Genesis block with Round 1 created (all miners have ImpliedIrreversibleBlockHeight = 0)
// 2. First miner (Order = 1) goes offline
// 3. Second miner triggers NextRound

[Fact]
public async Task LIB_StuckAt_Zero_When_Round1_Has_No_UpdateValue_Blocks()
{
    // Arrange: Setup consensus with Round 1
    var miners = GenerateTestMiners(5);
    var round1 = miners.GenerateFirstRoundOfNewTerm(4000, TimestampHelper.GetUtcNow());
    
    // Verify all miners start with ImpliedIrreversibleBlockHeight = 0
    foreach (var miner in round1.RealTimeMinersInformation.Values)
    {
        Assert.Equal(0, miner.ImpliedIrreversibleBlockHeight);
    }
    
    // Act: Simulate first miner offline, second miner triggers NextRound
    // (first miner never calls UpdateValue, so OutValue remains null)
    var secondMinerKey = round1.RealTimeMinersInformation.Values.First(m => m.Order == 2).Pubkey;
    
    // Second miner detects first miner is offline and triggers NextRound
    var nextRoundInput = GenerateNextRoundInput(round1);
    var round2 = nextRoundInput.ToRound();
    
    // Verify Round 2 miners still have ImpliedIrreversibleBlockHeight = 0
    foreach (var miner in round2.RealTimeMinersInformation.Values)
    {
        Assert.Equal(0, miner.ImpliedIrreversibleBlockHeight);
    }
    
    // Act: Simulate miner producing UpdateValue block in Round 2
    var updateMiner = round2.RealTimeMinersInformation.Values.First();
    updateMiner.ImpliedIrreversibleBlockHeight = 100; // Miner sets their value
    
    // Calculate LIB using previousRound (Round 1) and currentRound (Round 2)
    var calculator = new LastIrreversibleBlockHeightCalculator(round2, round1);
    calculator.Deconstruct(out var libHeight);
    
    // Assert: LIB is stuck at 0 because all Round 1 miners have ImpliedIrreversibleBlockHeight = 0
    Assert.Equal(0, libHeight);
    
    // Verify cross-chain validation would fail
    var crossChainValidationPasses = libHeight > 0; // Genesis height is 0
    Assert.False(crossChainValidationPasses);
}
```

## Notes

This vulnerability represents a critical gap in the consensus finality mechanism that can naturally occur during network instability, particularly at genesis. The fix requires ensuring `ImpliedIrreversibleBlockHeight` is consistently maintained across all round transitions, not just during UpdateValue operations.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-272)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L25-38)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L46-56)
```csharp
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** src/AElf.CrossChain.Core/Indexing/Infrastructure/IrreversibleBlockStateProvider.cs (L36-36)
```csharp
        _irreversibleBlockExists = lastIrreversibleBlockHeight > AElfConstants.GenesisBlockHeight;
```

**File:** src/AElf.CrossChain.Core/Extensions/LocalLibExtensions.cs (L14-15)
```csharp
        if (chain.LastIrreversibleBlockHeight < height + CrossChainConstants.LibHeightOffsetForCrossChainIndex)
            return null;
```
