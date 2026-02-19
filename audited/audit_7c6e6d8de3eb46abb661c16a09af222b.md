### Title
Missing ActualMiningTimes Check in ArrangeAbnormalMiningTime Allows Multiple Blocks in Single Saving Time Slot

### Summary
The production implementation of `ArrangeAbnormalMiningTime` lacks a critical check present in test code that validates whether a miner has already produced a block. This allows miners to repeatedly produce blocks within the same saving time slot window (up to the 8-block limit), rather than the intended single catch-up block, giving them unfair advantage for transaction ordering and MEV extraction.

### Finding Description
The `IsCurrentMiner()` function uses `ArrangeAbnormalMiningTime` to calculate a "saving time slot" for miners who missed their normal time slot. [1](#0-0) 

The production `ArrangeAbnormalMiningTime` method calculates the saving time slot based solely on current block time, round start time, and miner order, without checking if the miner has already produced any blocks. [2](#0-1) 

In contrast, the test implementation includes an explicit check: if the time slot hasn't passed AND the miner hasn't produced a block yet (`OutValue == null`), only then should the abnormal mining time be arranged. [3](#0-2) 

**Root Cause**: The production code omits the validation that prevents a miner from getting multiple saving time slot approvals after they've already mined once.

**Why Existing Protections Are Insufficient**:
1. `EnsureTransactionOnlyExecutedOnceInOneBlock` only prevents multiple consensus transactions within the same block height, not across consecutive blocks. [4](#0-3) 

2. The `MaximumTinyBlocksCount` constant limits consecutive blocks to 8, which constrains but doesn't prevent the abuse. [5](#0-4) 

3. When `ProcessUpdateValue` or `ProcessTinyBlock` is called, it updates `ActualMiningTimes` but this doesn't prevent the next invocation of `ArrangeAbnormalMiningTime` from returning the same saving time slot calculation. [6](#0-5) 

### Impact Explanation
**Direct Consensus Impact**: A miner who misses their normal time slot can produce up to 8 consecutive blocks rapidly within their 4-second saving time slot window, rather than the intended single catch-up block. This grants them:

- **Transaction Ordering Manipulation**: Control over transaction sequencing across 8 blocks enables MEV extraction and potential censorship
- **Unfair Mining Advantage**: One miner produces 8 blocks while others get only their single normal slot
- **Consensus Fairness Violation**: The round-robin mining schedule is compromised when one participant gets 8× their intended block production

The comment in the code explicitly states the saving time slot is for producing "a block (for terminating current round and start new round)" (singular), not multiple blocks. [7](#0-6) 

**Quantified Impact**: In a typical mining interval of 4000ms, a miner could produce 8 blocks instead of 1, gaining 700% more block rewards and transaction fee revenue for that window.

### Likelihood Explanation
**Attacker Capabilities**: Any miner in the consensus set can exploit this - no special privileges required beyond being a validly elected miner.

**Attack Complexity**: Low. The exploit is passive - a miner simply:
1. Misses their normal time slot (intentionally goes offline or experiences network issues)
2. Comes back online during the calculated saving time slot window
3. Produces blocks rapidly; `IsCurrentMiner()` continues returning true because `ArrangeAbnormalMiningTime` doesn't check `ActualMiningTimes`

**Feasibility**: Highly practical. The saving time slot mechanism is designed to be used, and `IsCurrentMiner()` is called by multiple system contracts to validate mining permissions. [8](#0-7) 

**Detection**: Difficult to distinguish from legitimate saving time slot usage versus abuse, as the behavior looks identical until multiple blocks are produced.

**Constraints**: The `ContinuousBlocksValidationProvider` enforces the 8-block limit, preventing truly unlimited abuse. [9](#0-8) 

### Recommendation
Add the missing check from the test code to the production `ArrangeAbnormalMiningTime` method:

```csharp
public Timestamp ArrangeAbnormalMiningTime(string pubkey, Timestamp currentBlockTime,
    bool mustExceededCurrentRound = false)
{
    var miningInterval = GetMiningInterval();
    var minerInRound = RealTimeMinersInformation[pubkey];
    
    // ADD THIS CHECK:
    if (!IsTimeSlotPassed(pubkey, currentBlockTime) && minerInRound.OutValue == null)
    {
        // Miner hasn't missed their slot yet, or hasn't mined yet
        // Don't arrange abnormal mining time
        return new Timestamp { Seconds = long.MaxValue };
    }
    
    // ... rest of existing logic
}
```

**Invariant to Enforce**: A miner should only receive ONE saving time slot per missed normal time slot, and only if they haven't already produced a block in the current round.

**Test Cases**: 
1. Verify that after a miner produces one block in their saving time slot, subsequent calls to `IsCurrentMiner()` within the same window return false
2. Verify that `ArrangeAbnormalMiningTime` returns an invalid timestamp when called for a miner who has already mined in the current round

### Proof of Concept
**Initial State**:
- Round N in progress with mining interval = 4000ms
- Miner A's normal time slot: 100-104 seconds
- Miner A is offline and misses their slot
- Current time reaches 150 seconds

**Exploitation Steps**:
1. At time 150s, Miner A comes online
2. `IsCurrentMiner(MinerA)` is called → invokes `ArrangeAbnormalMiningTime`
3. Calculation: missedRoundsCount = (150000 - 0) / (17 * 4000 + 4000) = 2 rounds missed
4. Saving time slot calculated as: 148-152 seconds
5. `IsCurrentMiner` returns TRUE (150 is within 148-152)
6. Miner A produces Block #1000 at 150.0s, `ActualMiningTimes` = [150.0]
7. At time 150.5s, Miner A calls `IsCurrentMiner` again
8. `ArrangeAbnormalMiningTime` runs again - **DOES NOT CHECK ActualMiningTimes**
9. Returns same calculation: 148-152 seconds
10. `IsCurrentMiner` returns TRUE again (150.5 is within 148-152)
11. Miner A produces Block #1001 at 150.5s
12. Repeat steps 7-11 for blocks #1002 through #1007 (8 blocks total before continuous blocks limit triggers)

**Expected Result**: Miner A should only be allowed to produce ONE block in the saving time slot (Block #1000), then subsequent `IsCurrentMiner` calls should return false.

**Actual Result**: Miner A produces 8 blocks consecutively within the 4-second saving time slot window due to the missing `ActualMiningTimes` check in `ArrangeAbnormalMiningTime`.

### Notes
While the question mentions "unlimited" saving time slots, the actual vulnerability is more limited: miners can produce up to 8 blocks within a SINGLE saving time slot window (constrained by `MaximumTinyBlocksCount`), not unlimited blocks across multiple rounds. Each saving time slot is tied to one missed normal time slot and expires after the mining interval. However, this still represents a significant Medium-severity consensus fairness issue where one miner gains 8× advantage during their saving time slot.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L180-189)
```csharp
        // Check saving extra block time slot.
        var nextArrangeMiningTime =
            currentRound.ArrangeAbnormalMiningTime(pubkey, Context.CurrentBlockTime, true);
        var actualArrangedMiningTime = nextArrangeMiningTime.AddMilliseconds(-currentRound.TotalMilliseconds());
        if (actualArrangedMiningTime <= Context.CurrentBlockTime &&
            Context.CurrentBlockTime <= actualArrangedMiningTime.AddMilliseconds(miningInterval))
        {
            Context.LogDebug(() => "[CURRENT MINER]SAVING");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L11-16)
```csharp
    /// <summary>
    ///     If one node produced block this round or missed his time slot,
    ///     whatever how long he missed, we can give him a consensus command with new time slot
    ///     to produce a block (for terminating current round and start new round).
    ///     The schedule generated by this command will be cancelled
    ///     if this node executed blocks from other nodes.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L19-37)
```csharp
    public Timestamp ArrangeAbnormalMiningTime(string pubkey, Timestamp currentBlockTime,
        bool mustExceededCurrentRound = false)
    {
        var miningInterval = GetMiningInterval();

        var minerInRound = RealTimeMinersInformation[pubkey];

        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
        }

        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
    }
```

**File:** test/AElf.Contracts.Election.Tests/Types/Round.cs (L72-75)
```csharp
        if (!IsTimeSlotPassed(publicKey, dateTime, out var minerInRound) && minerInRound.OutValue == null)
        {
            return new Timestamp { Seconds = long.MaxValue };
            ;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
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

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L897-906)
```csharp
    private void AssertSenderIsCurrentMiner()
    {
        if (State.ConsensusContract.Value == null)
        {
            State.ConsensusContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
        }

        Assert(State.ConsensusContract.IsCurrentMiner.Call(Context.Sender).Value, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-24)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }
```
