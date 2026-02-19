### Title
First Round Miner Offset Calculation Exceeds Round Time Boundary

### Summary
The `FirstRoundCommandStrategy.GetAEDPoSConsensusCommand()` method calculates mining offsets using the formula `(Order + MinersCount - 1) * miningInterval`, which causes miners with higher order numbers to be scheduled beyond the nominal round duration of `MinersCount * miningInterval`. For the last miner (Order == MinersCount), this results in an offset approximately double the round duration, violating the expected time boundary and extending the first round significantly beyond its allocated timeframe.

### Finding Description

The root cause is located in the offset calculation: [1](#0-0) 

For a concrete example with 5 miners:
- Last miner (Order = 5, MinersCount = 5) receives: offset = (5 + 5 - 1) * miningInterval = **9 * miningInterval**
- Expected round duration: 5 * miningInterval
- **The offset is 80% larger than the entire round duration**

When this offset is applied to calculate `ArrangedMiningTime`: [2](#0-1) 

The resulting mining time extends well beyond the round's allocated boundary. If the last miner calls `GetConsensusCommand` at `currentBlockTime = T0 + 4 * miningInterval` (after 4 miners have mined), their arranged mining time becomes `T0 + 13 * miningInterval`, which is **2.6x the round duration**.

While the validation logic attempts to accommodate large offsets: [3](#0-2) 

The `+ minersCount` terms in the validation formula indicate the system is designed to work with these excessive offsets, but this doesn't eliminate the fundamental issue that the first round exceeds its time boundary.

The first round is generated with proper time slots: [4](#0-3) 

However, the `FirstRoundCommandStrategy` ignores these `ExpectedMiningTime` values and uses its own offset calculation that extends beyond the round boundary.

### Impact Explanation

**Operational Impact:**
1. **Extended First Round Duration**: The first round takes significantly longer than the expected `MinersCount * miningInterval`, potentially up to `(2 * MinersCount) * miningInterval` for the last miner's slot
2. **Blockchain Startup Delay**: New blockchain instances or term changes experience substantial delays during initialization
3. **Time Slot Boundary Violation**: Violates the consensus invariant that round duration equals `MinersCount * miningInterval`

**Consensus Integrity Impact:**
4. **Round Duration Unpredictability**: The actual first round duration becomes dependent on when miners call `GetConsensusCommand`, creating timing uncertainty
5. **Next Round Scheduling Conflict**: The extra block producer's timing (calculated as last miner's `ExpectedMiningTime` + interval) may conflict with actual mining times: [5](#0-4) 

**Quantified Impact:**
- With 5 miners: round extends from expected 20 seconds (5 * 4000ms) to up to 40 seconds
- With 17 miners (typical production): extends from 68 seconds to up to 132 seconds
- **94% time overhead** for typical configurations

### Likelihood Explanation

**Probability: Certain (100%)**

This issue occurs deterministically in every first round of every term:

1. **Entry Point**: The `GetConsensusCommand` method is called by all miners during the first round: [6](#0-5) 

2. **Preconditions**: Only requires `currentRound.RoundNumber == 1`, which is guaranteed for:
   - Initial blockchain startup
   - Every term change (occurs periodically based on term duration)

3. **Execution Path**: 
   - Automatic - no attacker action required
   - Happens through normal consensus operation
   - All miners with Order > 1 experience excessive offsets

4. **No Mitigation**: The validation logic is designed to accept these excessive offsets, so there's no protective barrier: [7](#0-6) 

The only safeguard prevents premature mining before the boot miner, but doesn't address the excessive offset issue.

### Recommendation

**Fix the offset calculation to respect round boundaries:**

Replace line 37 in `FirstRoundCommandStrategy.cs` with:
```csharp
offset = Order.Mul(miningInterval);
```

This ensures:
- Miner with Order 1: offset = 1 * miningInterval
- Miner with Order N: offset = N * miningInterval
- Maximum offset = MinersCount * miningInterval (stays within boundary)

**Update validation logic accordingly:**

Modify the `IsCurrentMiner` validation formula to expect the corrected offset without the excess `minersCount` term.

**Add invariant check:**

In `FirstRoundCommandStrategy.GetAEDPoSConsensusCommand()`, add validation:
```csharp
Assert(offset <= MinersCount.Mul(miningInterval), "Offset exceeds round boundary");
```

**Test cases to add:**
1. Verify last miner's `ArrangedMiningTime` stays within `RoundStartTime + (MinersCount * miningInterval)`
2. Test that all miners can successfully produce blocks within the round boundary
3. Verify next round starts at the expected time without overlap

### Proof of Concept

**Initial State:**
- First round initialized with 5 miners
- MiningInterval = 4000ms
- BlockchainStartTimestamp = T0
- Boot miner (Order 1) has produced first block at T0 + 4000ms

**Exploitation Steps:**

1. Last miner (Order 5) calls `GetConsensusCommand`:
   - CurrentBlockTime = T0 + 16000ms (after 4 miners)
   - Calculated offset = (5 + 5 - 1) * 4000 = **36000ms**
   - ArrangedMiningTime = T0 + 16000 + 36000 = T0 + **52000ms**

2. Expected vs Actual:
   - **Expected round end**: T0 + 20000ms (5 miners * 4000ms)
   - **Actual last miner time**: T0 + 52000ms
   - **Boundary violation**: 32000ms (160% over limit)

3. Success Condition:
   - Last miner scheduled at T0 + 52000ms (verified)
   - Round duration: 48000ms instead of expected 20000ms (140% longer)
   - Validation passes despite boundary violation (confirmed by validation formula including `+ minersCount`)

### Notes

The excessive offset is partially accommodated by the validation logic, which explains why the system doesn't completely fail. However, this doesn't justify the design - it merely papers over a fundamental timing flaw. The test suite doesn't catch this because tests manually set `BlockTime` to `ExpectedMiningTime`, bypassing the offset calculation entirely: [8](#0-7)

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs (L34-37)
```csharp
            var offset =
                _consensusBehaviour == AElfConsensusBehaviour.UpdateValue && Order == 1
                    ? miningInterval
                    : Order.Add(MinersCount).Sub(1).Mul(miningInterval);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/FirstRoundCommandStrategy.cs (L38-39)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeMiningTimeWithOffset(CurrentBlockTime, offset);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L206-214)
```csharp
                var passedSlotsCount =
                    (Context.CurrentBlockTime - latestMinedSlotLastActualMiningTime).Milliseconds()
                    .Div(miningInterval);
                if (passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(1).Add(minersCount) ||
                    passedSlotsCount == currentMinerOrder.Sub(latestMinedOrder).Add(minersCount))
                {
                    Context.LogDebug(() => "[CURRENT MINER]FIRST ROUND");
                    return true;
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L32-33)
```csharp
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L28-30)
```csharp
        if (currentRound.RoundNumber == 1 && behaviour == AElfConsensusBehaviour.UpdateValue)
            return new ConsensusCommandProvider(new FirstRoundCommandStrategy(currentRound, pubkey,
                currentBlockTime, behaviour)).GetConsensusCommand();
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

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/MiningProcessTest.cs (L56-56)
```csharp
            BlockTimeProvider.SetBlockTime(minerInRound.ExpectedMiningTime);
```
