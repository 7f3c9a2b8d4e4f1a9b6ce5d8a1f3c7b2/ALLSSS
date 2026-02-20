# Audit Report

## Title
Extra Block Producer Receives Regular Time Slot Instead of Extra Block Slot When Distance is Non-Positive

## Summary
The `ArrangeAbnormalMiningTime` method contains a logic flaw where the extra block producer's special handling only executes when `distance > 0`. When the extra block producer misses their time slot by more than one mining interval (distance ≤ 0), execution falls through to generic time slot calculation that assigns a regular Order-based time slot instead of the proper extra block time slot, causing duplicate time slot assignments and consensus conflicts.

## Finding Description

The vulnerability exists in `ArrangeAbnormalMiningTime` where special handling for the extra block producer fails to cover the `distance <= 0` case. [1](#0-0) 

When the extra block time has passed by more than one mining interval, the condition evaluates to false and no return occurs. Execution falls through to the generic calculation that uses the miner's Order value to compute a time slot as if they were a regular miner: [2](#0-1) 

However, the extra block producer's role is to produce a block at the END of the round (after all regular miners), not at their Order position. The correct extra block mining time is calculated as the last miner's expected time plus one interval: [3](#0-2) 

This method is called by `TerminateRoundCommandStrategy` to arrange mining time for extra block production: [4](#0-3) [5](#0-4) 

The consensus command indicates `NextRound` or `NextTerm` behavior, meaning the miner should produce an extra block to terminate the round: [6](#0-5) 

However, the arranged time is a regular slot that conflicts with another miner's expected time in that future round.

During round generation, miners are assigned Orders from 1 to N, and each Order corresponds to a specific time slot: [7](#0-6) 

When the extra block producer is assigned `futureRoundStartTime + Order * miningInterval`, this is the SAME time that will be assigned to the regular miner with that Order in the future round, creating a duplicate time slot assignment.

The total round time calculation confirms that extra blocks should be produced AFTER all regular miners: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Compromise:**
Two miners are assigned the same time slot: the extra block producer (via the fallthrough calculation in `ArrangeAbnormalMiningTime`) and another miner with the same Order in the future round (via normal round generation logic). This creates a race condition where both miners attempt to produce blocks simultaneously.

**Round Termination Disruption:**
Extra block production is critical for round termination and confirming the next round's mining order. Assigning the wrong time slot type (regular position-based slot instead of extra block slot) prevents proper round termination. The extra block producer will attempt to mine at a time slot that conflicts with a regular miner, potentially causing validation failures or consensus delays that affect all network participants.

**Validation Gaps:**
The existing validation providers do not catch this cross-round time slot conflict: [9](#0-8) 

`TimeSlotValidationProvider` only validates within the current round (BaseRound) or checks the internal consistency of the provided round, but does not validate cross-round time slot conflicts. [10](#0-9) 

`CheckRoundTimeSlots` only validates that mining intervals are consistent and greater than zero, but does not check for duplicate time assignments across different consensus commands.

## Likelihood Explanation

**Triggering Conditions:**
The vulnerability triggers when:
1. The extra block producer calls `ArrangeAbnormalMiningTime` (via consensus command generation)
2. `mustExceededCurrentRound = false` (default for `ArrangeExtraBlockMiningTime`)
3. `currentBlockTime >= GetExtraBlockMiningTime() + miningInterval` (distance ≤ 0)

**Realistic Scenarios:**
This occurs during normal operational conditions documented in the method comments: [11](#0-10) 

Common scenarios include:
- Network delays causing the extra block producer to miss their time slot by more than one mining interval
- Node downtime or synchronization issues during network instability
- High network latency during peak loads

**No Attacker Required:**
This is not an attack scenario but a natural consequence of network conditions and timing. The vulnerability manifests during legitimate consensus operations when network variability causes delays.

**Probability:**
Medium to High - occurs whenever the extra block producer experiences delays exceeding one mining interval, which can happen in production networks with variable latency or node availability issues.

## Recommendation

Modify the `ArrangeAbnormalMiningTime` method to handle the `distance <= 0` case for extra block producers by calculating the proper extra block time slot in the future round:

```csharp
if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
{
    var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
        .Milliseconds();
    if (distance > 0) return GetExtraBlockMiningTime();
    
    // When distance <= 0, calculate the extra block time slot for the future round
    var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
    var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
    var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
    var minersCount = RealTimeMinersInformation.Count;
    return futureRoundStartTime.AddMilliseconds(minersCount.Mul(miningInterval));
}
```

This ensures the extra block producer is always assigned to the extra block time slot (after all regular miners) rather than a regular Order-based slot.

## Proof of Concept

```csharp
[Fact]
public void ExtraBlockProducer_MissedSlotByMoreThanOneInterval_CreatesTimeSlotConflict()
{
    // Setup: Create a round with 5 miners
    var round = GenerateRoundWithMiners(5);
    var extraBlockProducer = round.GetExtraBlockProducerInformation();
    var extraBlockTime = round.GetExtraBlockMiningTime();
    var miningInterval = round.GetMiningInterval();
    
    // Current time is after extra block time + more than one interval
    var currentTime = extraBlockTime.AddMilliseconds(miningInterval * 2);
    
    // Act: Arrange abnormal mining time for extra block producer
    var arrangedTime = round.ArrangeAbnormalMiningTime(
        extraBlockProducer.Pubkey, 
        currentTime, 
        mustExceededCurrentRound: false);
    
    // Calculate what time the future round's miner with same Order will get
    var distanceToRoundStart = (currentTime - round.GetRoundStartTime()).Milliseconds();
    var missedRounds = distanceToRoundStart / round.TotalMilliseconds(miningInterval);
    var futureRoundStart = round.GetRoundStartTime()
        .AddMilliseconds((missedRounds + 1) * round.TotalMilliseconds(miningInterval));
    var regularMinerTime = futureRoundStart.AddMilliseconds(extraBlockProducer.Order * miningInterval);
    
    // Assert: Both times are identical - CONFLICT!
    Assert.Equal(arrangedTime, regularMinerTime);
    
    // The correct extra block time should be at the end of the future round
    var correctExtraBlockTime = futureRoundStart.AddMilliseconds(5 * miningInterval);
    Assert.NotEqual(arrangedTime, correctExtraBlockTime);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L11-17)
```csharp
    /// <summary>
    ///     If one node produced block this round or missed his time slot,
    ///     whatever how long he missed, we can give him a consensus command with new time slot
    ///     to produce a block (for terminating current round and start new round).
    ///     The schedule generated by this command will be cancelled
    ///     if this node executed blocks from other nodes.
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L26-31)
```csharp
        if (GetExtraBlockProducerInformation().Pubkey == pubkey && !mustExceededCurrentRound)
        {
            var distance = (GetExtraBlockMiningTime().AddMilliseconds(miningInterval) - currentBlockTime)
                .Milliseconds();
            if (distance > 0) return GetExtraBlockMiningTime();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L33-36)
```csharp
        var distanceToRoundStartTime = (currentBlockTime - GetRoundStartTime()).Milliseconds();
        var missedRoundsCount = distanceToRoundStartTime.Div(TotalMilliseconds(miningInterval));
        var futureRoundStartTime = CalculateFutureRoundStartTime(missedRoundsCount, miningInterval);
        return futureRoundStartTime.AddMilliseconds(minerInRound.Order.Mul(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L60-73)
```csharp
    /// <summary>
    ///     In current AElf Consensus design, each miner produce his block in one time slot, then the extra block producer
    ///     produce a block to terminate current round and confirm the mining order of next round.
    ///     So totally, the time of one round is:
    ///     MiningInterval * MinersCount + MiningInterval.
    /// </summary>
    /// <param name="miningInterval"></param>
    /// <returns></returns>
    public int TotalMilliseconds(int miningInterval = 0)
    {
        if (miningInterval == 0) miningInterval = GetMiningInterval();

        return RealTimeMinersInformation.Count * miningInterval + miningInterval;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-57)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L25-26)
```csharp
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeExtraBlockMiningTime(CurrentRound, Pubkey, CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L29-32)
```csharp
                Hint = new AElfConsensusHint
                    {
                        Behaviour = _isNewTerm ? AElfConsensusBehaviour.NextTerm : AElfConsensusBehaviour.NextRound
                    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L22-25)
```csharp
        public static Timestamp ArrangeExtraBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return round.ArrangeAbnormalMiningTime(pubkey, currentBlockTime);
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-35)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```
