### Title
Offline Miners Produce Blocks with Future Timestamps Exceeding Validation Limit Causing Consensus Rejection

### Summary
When a consensus miner is offline for multiple rounds and then comes back online, the `CalculateFutureRoundStartTime()` method calculates a block timestamp that can be up to one full round duration (plus miner time slot offset) ahead of the current time. This causes produced blocks to be rejected by other consensus participants because the timestamp exceeds the 4-second `AllowedFutureBlockTimeSpan` validation limit, resulting in consensus disruption for the recovering miner.

### Finding Description

The vulnerability exists in the time calculation logic for miners who have missed multiple rounds: [1](#0-0) 

The root cause is at line 57 where `missedRoundsCount.Add(1)` projects the start time of the NEXT round after all missed rounds. Combined with line 36 which adds the miner's time slot offset, the final arranged mining time can be far in the future: [2](#0-1) 

**Mathematical Analysis:**
- `futureRoundStartTime = RoundStartTime + (missedRoundsCount + 1) × totalMilliseconds`
- Where `totalMilliseconds = (MinersCount + 1) × miningInterval` as shown: [3](#0-2) 

With typical mining interval of 4000ms: [4](#0-3) 

For a 10-miner network: `totalMilliseconds = 11 × 4000 = 44,000ms = 44 seconds`

The arranged time becomes: `currentTime + (up to 44 seconds) + (minerOrder × 4 seconds)`

For a miner with order 5, this could be: `currentTime + 44s + 20s = currentTime + 64 seconds`

This timestamp is then used as the block time through the consensus flow: [5](#0-4) [6](#0-5) 

However, when other consensus participants receive this block, validation fails because the timestamp exceeds the allowed future time span: [7](#0-6) 

The `AllowedFutureBlockTimeSpan` is only 4 seconds: [8](#0-7) 

Since 64 seconds >> 4 seconds, the block is rejected.

### Impact Explanation

**Consensus Disruption:** Miners who have been offline (even briefly—just a few missed rounds) cannot successfully produce valid blocks when they return online. Their blocks are systematically rejected by all other consensus participants, effectively preventing their participation until the round naturally advances or other miners produce blocks that update the round state.

**Severity Quantification:**
- With 10 miners and 4000ms interval: blocks rejected if miner offline for any duration causing timestamp > 4s ahead
- The "+1" in the calculation guarantees at least one full round (44s) is added, exceeding the limit
- Affects any miner experiencing temporary network issues, crashes, or brief downtime
- Network with more miners or longer intervals amplifies the issue (e.g., 20 miners = 84s round duration)

**Affected Parties:**
- Recovering miners cannot produce valid blocks
- Network consensus flow is disrupted until round state naturally progresses
- Reduces network resilience to node failures

### Likelihood Explanation

**High Likelihood:** This occurs through normal consensus operations without any malicious action:

1. **Reachable Entry Point:** Normal consensus command generation flow called during block production: [9](#0-8) [10](#0-9) 

2. **Feasible Preconditions:** Only requires a miner to miss multiple rounds due to:
   - Brief network connectivity issues
   - Node crashes/restarts
   - Temporary system overload
   - Routine maintenance

3. **No Special Permissions Required:** Happens automatically when any authorized miner comes back online

4. **Deterministic Outcome:** The mathematical calculation guarantees the timestamp will exceed 4 seconds for networks with typical parameters

### Recommendation

**Fix the calculation in `CalculateFutureRoundStartTime` to respect the validation limit:**

1. Remove the problematic "+1" that projects to the next round, or cap the calculated timestamp:
```
private Timestamp CalculateFutureRoundStartTime(long missedRoundsCount = 0, int miningInterval = 0)
{
    if (miningInterval == 0)
        miningInterval = GetMiningInterval();

    var totalMilliseconds = TotalMilliseconds(miningInterval);
    var calculatedTime = GetRoundStartTime().AddMilliseconds(missedRoundsCount.Mul(totalMilliseconds));
    
    // Ensure calculated time doesn't exceed a safe threshold from current time
    var maxAllowedTime = Context.CurrentBlockTime.AddSeconds(2); // Conservative 2s buffer
    return calculatedTime > maxAllowedTime ? maxAllowedTime : calculatedTime;
}
```

2. **Alternative approach:** Use current block time directly when missedRoundsCount is large:
```
if (missedRoundsCount > 0) {
    // For offline miners, use current time plus minimal offset
    return currentBlockTime.AddMilliseconds(miningInterval);
}
```

3. **Add validation check** before returning the arranged mining time to ensure it falls within acceptable bounds

4. **Add test cases** covering:
   - Miner offline for 1-100 rounds
   - Various network sizes (1-20 miners)
   - Different mining intervals
   - Verify produced blocks pass validation

### Proof of Concept

**Initial State:**
- 10 active miners in consensus
- Mining interval: 4000ms
- Current round start time (in state): T₀ = 1000 seconds
- Current block time: T_now = 2000 seconds (node was offline)
- Recovering miner has order: 5

**Execution Steps:**

1. Recovering miner requests consensus command
2. `ArrangeAbnormalMiningTime` called with `currentBlockTime = 2000s`
3. Calculation proceeds:
   - `distanceToRoundStartTime = 2000 - 1000 = 1000 seconds`
   - `totalMilliseconds = (10 + 1) × 4000 = 44,000ms = 44 seconds`
   - `missedRoundsCount = 1000 / 44 = 22` (integer division)
   - `futureRoundStartTime = 1000 + (22 + 1) × 44 = 1000 + 1012 = 2012 seconds`
   - `arrangedMiningTime = 2012 + (5 × 4) = 2032 seconds`

4. Block produced with `Header.Time = 2032 seconds`
5. Other nodes receive block at their current time ≈ 2000 seconds
6. Validation check: `2032 - 2000 = 32 seconds > 4 seconds (AllowedFutureBlockTimeSpan)`

**Expected Result:** Block should be accepted by consensus participants

**Actual Result:** Block is rejected with "Future block received" message, causing consensus disruption

**Success Condition:** The vulnerability is confirmed when the calculated timestamp (2032s) exceeds the validation limit (2000s + 4s = 2004s) by 28 seconds.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L33-37)
```csharp
        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L51-58)
```csharp
    private Timestamp CalculateFutureRoundStartTime(long missedRoundsCount = 0, int miningInterval = 0)
    {
        if (miningInterval == 0)
            miningInterval = GetMiningInterval();

        var totalMilliseconds = TotalMilliseconds(miningInterval);
        return GetRoundStartTime().AddMilliseconds(missedRoundsCount.Add(1).Mul(totalMilliseconds));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L68-73)
```csharp
    public int TotalMilliseconds(int miningInterval = 0)
    {
        if (miningInterval == 0) miningInterval = GetMiningInterval();

        return RealTimeMinersInformation.Count * miningInterval + miningInterval;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L87-88)
```csharp
        _nextMiningTime = _consensusCommand.ArrangedMiningTime;
        var leftMilliseconds = _consensusCommand.ArrangedMiningTime - TimestampHelper.GetUtcNow();
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L197-198)
```csharp
        _blockTimeProvider.SetBlockTime(_nextMiningTime, chainContext.BlockHash);

```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L133-139)
```csharp
        if (block.Header.Height != AElfConstants.GenesisBlockHeight &&
            block.Header.Time.ToDateTime() - TimestampHelper.GetUtcNow().ToDateTime() >
            KernelConstants.AllowedFutureBlockTimeSpan.ToTimeSpan())
        {
            Logger.LogDebug("Future block received {Block}, {BlockTime}", block, block.Header.Time.ToDateTime());
            return Task.FromResult(false);
        }
```

**File:** src/AElf.Kernel.Types/KernelConstants.cs (L19-19)
```csharp
    public static Duration AllowedFutureBlockTimeSpan = new() { Seconds = 4 };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L25-26)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L22-25)
```csharp
        public static Timestamp ArrangeExtraBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return round.ArrangeAbnormalMiningTime(pubkey, currentBlockTime);
        }
```
