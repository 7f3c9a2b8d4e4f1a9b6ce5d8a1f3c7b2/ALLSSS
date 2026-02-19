### Title
Last Irreversible Block (LIB) Height Stuck at Zero During Round 2 Due to Missing ImpliedIrreversibleBlockHeight Updates in Non-UpdateValue Behaviors

### Summary
The consensus mechanism only updates `ImpliedIrreversibleBlockHeight` during the UpdateValue behavior, not during TinyBlock, NextRound, or NextTerm behaviors. If Round 1 completes without any UpdateValue blocks (e.g., when the first miner fails to produce blocks and other miners trigger NextRound), all miners in Round 1 retain `ImpliedIrreversibleBlockHeight = 0`. This causes the LIB calculation in Round 2 to return an empty list after filtering, keeping LIB stuck at 0 throughout Round 2, blocking finality-dependent operations.

### Finding Description

**Root Cause:**

The `ImpliedIrreversibleBlockHeight` field is only set during the UpdateValue consensus behavior: [1](#0-0) 

Other behaviors do not update this field:
- **TinyBlock behavior**: Does not set `ImpliedIrreversibleBlockHeight` [2](#0-1) 

- **NextRound behavior**: Does not set `ImpliedIrreversibleBlockHeight` [3](#0-2) 

- **NextTerm behavior**: Does not set `ImpliedIrreversibleBlockHeight` [4](#0-3) 

**Vulnerable Execution Path:**

1. During Round 1 (first round after genesis), all miners initialize with `ImpliedIrreversibleBlockHeight = 0` (default protobuf value).

2. The consensus behavior logic allows non-first miners to trigger NextRound if the first miner hasn't produced blocks: [5](#0-4) 

3. If the first miner is offline/delayed and NextRound is triggered before any UpdateValue blocks are produced, Round 2 is created via: [6](#0-5) 

4. Round 2 miners are newly created `MinerInRound` objects with `ImpliedIrreversibleBlockHeight = 0` by default.

5. During Round 2, the LIB calculator is invoked and filters miners from Round 1: [7](#0-6) 

The filter on line 15 excludes all miners with `ImpliedIrreversibleBlockHeight = 0`, resulting in an empty list.

6. The LIB calculator checks if the count is sufficient: [8](#0-7) 

With an empty list (count = 0 < MinersCountOfConsent), `libHeight` is set to 0 and the function returns.

7. The LIB update logic only updates if the new LIB is higher than the current: [9](#0-8) 

Since `libHeight = 0` and `ConfirmedIrreversibleBlockHeight = 0`, the condition at line 272 is false (0 < 0), so LIB remains stuck at 0 throughout Round 2.

### Impact Explanation

**Operational Denial of Service on Consensus Finality:**

- **LIB Stuck at Zero**: Throughout the entire Round 2 (potentially hundreds of blocks depending on miner count and mining interval), the Last Irreversible Block height remains at 0.

- **Cross-Chain Operations Blocked**: Cross-chain proof verification and indexing rely on irreversible block heights. With LIB at 0, cross-chain transfers and state synchronization cannot proceed safely. [10](#0-9) 

- **Finality-Dependent Applications Fail**: Any application or service waiting for transaction finality (irreversibility confirmation) will be blocked, as no blocks can be confirmed as irreversible.

- **Recovery Only in Round 3**: LIB can only recover in Round 3 when the calculator can reference Round 2's miners who have non-zero `ImpliedIrreversibleBlockHeight` values. This means at least one full round of operational degradation.

**Severity**: High - This constitutes a Denial of Service on critical consensus finality functionality, directly violating the "LIB height rules" invariant specified in the audit requirements.

### Likelihood Explanation

**Triggering Conditions:**

The vulnerability triggers if Round 1 completes without any miner producing an UpdateValue block. This occurs when:

1. **First Miner Failure**: The miner with Order == 1 in Round 1 fails to produce blocks (offline, network issues, malicious behavior, or delayed node start).

2. **Automatic NextRound Trigger**: Per the consensus rules, when the first miner hasn't produced blocks (`OutValue == null`), other miners with Order != 1 automatically return NextRound behavior to prevent fork blocks: [5](#0-4) 

3. **Genesis/Initialization Vulnerability Window**: This scenario is most likely during initial chain deployment when:
   - Network connectivity may be unstable
   - Miner nodes are still synchronizing
   - Configuration errors could delay the first miner
   - Genesis timing issues could cause the first miner to miss their slot

**Likelihood Assessment**: **Medium to High** during genesis and initialization phases. Once triggered, it automatically affects the entire Round 2 without requiring further attacker action.

**Attacker Capabilities**: No sophisticated attack required - can occur naturally due to network issues or can be induced by a malicious first miner simply going offline during Round 1.

### Recommendation

**Fix 1: Update ImpliedIrreversibleBlockHeight in All Block-Producing Behaviors**

Modify TinyBlock, NextRound, and NextTerm behaviors to set `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` similar to UpdateValue:

In `GetConsensusExtraDataForTinyBlock`: [2](#0-1) 

Add after line 163:
```csharp
currentRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

In `GetConsensusExtraDataForNextRound`: [3](#0-2) 

Add after line 196:
```csharp
nextRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**Fix 2: Add Fallback Logic in LIB Calculator**

When the filtered list is empty but miners have produced blocks, use the minimum confirmed block height as a fallback: [10](#0-9) 

Add logic to use `_currentRound.ConfirmedIrreversibleBlockHeight` from the previous round if the filtered list is empty but blocks have been mined.

**Fix 3: Missing Return Statement Bug**

Add a `return` statement after line 22 to prevent execution when rounds are empty: [11](#0-10) 

Change to:
```csharp
if (_currentRound.IsEmpty || _previousRound.IsEmpty) { libHeight = 0; return; }
```

**Test Cases:**

1. Simulate genesis with first miner offline
2. Verify NextRound triggered in Round 1 without UpdateValue blocks
3. Confirm LIB calculation in Round 2 handles empty ImpliedIrreversibleBlockHeight list gracefully
4. Verify LIB recovery in Round 3
5. Test all consensus behaviors set ImpliedIrreversibleBlockHeight correctly

### Proof of Concept

**Initial State:**
- Fresh chain deployment with FirstRound called
- 5 miners configured, Order 1-5
- All miners have `ImpliedIrreversibleBlockHeight = 0`
- Round 1 initialized

**Attack/Failure Sequence:**

1. **Block 1 (Genesis)**: FirstRound transaction executed, Round 1 created
   - All miners: `ImpliedIrreversibleBlockHeight = 0`, `OutValue = null`

2. **Block 2 (Round 1)**: Miner Order 1 is offline/delayed
   - First miner's time slot passes without producing UpdateValue block
   - `CurrentRound.FirstMiner().OutValue == null` remains true

3. **Block 3 (Round 1)**: Miner Order 2 produces block
   - Consensus behavior check per lines 94-102 in ConsensusBehaviourProviderBase
   - Conditions met: `RoundNumber == 1 && Order != 1 && FirstMiner().OutValue == null`
   - Returns `AElfConsensusBehaviour.NextRound`
   - NextRound block produced, triggering ProcessNextRound
   - Round 2 created, all Round 1 miners still have `ImpliedIrreversibleBlockHeight = 0`

4. **Block 4 (Round 2)**: First miner in Round 2 produces UpdateValue block
   - Sets their own `ImpliedIrreversibleBlockHeight = 4` in Round 2
   - LIB calculator invoked with currentRound = Round 2, previousRound = Round 1
   - Gets minedMiners from Round 2 (this miner)
   - Filters Round 1 for these miners with `ImpliedIrreversibleBlockHeight > 0`
   - **Result**: Empty list (all Round 1 miners have 0)
   - Count = 0 < MinersCountOfConsent (at least 4 for 5 miners)
   - Returns `libHeight = 0`

5. **Blocks 5-N (Round 2 continues)**: More miners produce UpdateValue blocks
   - All set their `ImpliedIrreversibleBlockHeight` in Round 2
   - Every LIB calculation still references Round 1 (previousRound)
   - **LIB remains stuck at 0 throughout entire Round 2**

6. **Block N+1 (Round 3)**: First block of Round 3
   - LIB calculator now has previousRound = Round 2
   - Round 2 miners have non-zero `ImpliedIrreversibleBlockHeight` values
   - LIB calculation succeeds, returns proper irreversible height
   - **LIB finally updates after Round 3 begins**

**Expected Result**: LIB should advance continuously as blocks are confirmed by 2/3+ miners.

**Actual Result**: LIB stuck at 0 for entire Round 2 (could be 100+ blocks), causing finality DoS until Round 3.

**Success Condition**: Cross-chain operations fail, applications waiting for finality timeout, LIB height query returns 0 despite many blocks being produced and confirmed by majority of miners.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L155-171)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForTinyBlock(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = currentRound.GetTinyBlockRound(pubkey),
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
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
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
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
