# Audit Report

## Title
Maximum Blocks Count Can Return Zero Leading to Severe Throughput Degradation in Abnormal Status

## Summary
The `GetMaximumBlocksCount()` function in the AEDPoS consensus contract contains a mathematical edge case where it returns 0 during Abnormal blockchain status when no miners successfully mined in both of the previous two rounds. This prevents all TinyBlock production, reducing maximum throughput by 87.5% (from 8 blocks to 1 block per time slot) precisely when the network is under stress and needs higher throughput for recovery.

## Finding Description

When the blockchain enters Abnormal mining status (Last Irreversible Block is 2-7 rounds behind the current round), `GetMaximumBlocksCount()` dynamically adjusts the maximum tiny blocks count based on miner participation across recent rounds. [1](#0-0) 

The function retrieves lists of miners who mined in rounds N-1 and N-2, then calculates their intersection to determine active miner overlap. [2](#0-1) 

When `minersOfLastTwoRounds` equals 0 (no common miners between the two rounds), the multiplication produces a zero `factor`. The `Ceiling` function implementation returns 0 when the numerator is 0, causing `Math.Min(MaximumTinyBlocksCount, 0)` to return 0. [3](#0-2) [4](#0-3) 

This zero value is passed to `ConsensusBehaviourProviderBase` during consensus command generation. [5](#0-4) 

The behaviour provider checks `ActualMiningTimes.Count < _maximumBlocksCount` to determine if TinyBlock production is allowed. When `_maximumBlocksCount` is 0, this condition is always false (since Count ≥ 0), preventing TinyBlock behaviour entirely. [6](#0-5) 

This behaviour is **inconsistent** with Severe status (a worse condition), which explicitly returns 1 to maintain minimum block production capability. [7](#0-6) 

The trigger condition occurs when `GetMinedMiners()` returns empty or non-overlapping lists for the previous two rounds. This method filters miners where `SupposedOrderOfNextRound != 0`. [8](#0-7) 

The mined miner lists are recorded during round transitions by calling `RecordMinedMinerListOfCurrentRound()`. [9](#0-8) 

## Impact Explanation

**Severe Throughput Degradation:**
Under normal conditions, `MaximumTinyBlocksCount` is configured as 8, allowing miners to produce up to 8 tiny blocks per time slot. [10](#0-9) 

When this bug returns 0, miners can only produce 1 UPDATE_VALUE block per time slot, representing an 87.5% reduction in maximum throughput (from 8 possible blocks down to 1).

**Operational Denial-of-Service:**
- Transaction backlog accumulates as the network cannot process normal transaction load
- Users experience severe delays or inability to submit transactions
- Time-sensitive governance proposals and operations may fail
- Network becomes effectively unusable despite consensus mechanisms continuing to operate

**Compounding Effect:**
This bug manifests precisely when the blockchain is already under stress (Abnormal status indicates LIB is falling behind by 2-7 rounds), exacerbating degradation when higher throughput is most critical for recovery.

## Likelihood Explanation

**Entry Point:**
The function is invoked during standard consensus command generation when miners request their next consensus behaviour. [11](#0-10) 

**Preconditions:**
1. Blockchain enters Abnormal status (LIB is 2-7 rounds behind) - this occurs naturally during network partitioning, high latency, or miner failures
2. No miners from round N-1 also mined in round N-2, resulting in zero intersection count

**Feasibility:**
These conditions are highly feasible during network stress scenarios:
- Abnormal status is a designed state for handling degraded network conditions
- When miners fail to produce blocks (network issues, downtime, synchronization problems), their `SupposedOrderOfNextRound` remains 0
- Empty or non-overlapping mined miner lists occur naturally when different subsets of miners successfully produce blocks across consecutive rounds
- No malicious actor required - happens through natural network dynamics

The deterministic code path makes this reproducible whenever preconditions are met.

## Recommendation

Add a minimum return value check in the Abnormal status branch to ensure at least 1 block can be produced, consistent with Severe status handling:

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
    var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
    var minersOfLastTwoRounds = previousRoundMinedMinerList
        .Intersect(previousPreviousRoundMinedMinerList).Count();
    var factor = minersOfLastTwoRounds.Mul(
        blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
            (int)currentRoundNumber.Sub(libRoundNumber)));
    var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
        Math.Max(1, Ceiling(factor, currentRound.RealTimeMinersInformation.Count))); // Add Math.Max(1, ...)
    Context.LogDebug(() => $"Maximum blocks count tune to {count}");
    return count;
}
```

This ensures that even with zero miner overlap, at least 1 tiny block can be produced per time slot, maintaining consistency with Severe status behavior and preserving minimum network throughput during recovery.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize blockchain in round N with some miners producing blocks
2. Transition to round N+1 with a different set of miners producing blocks (zero overlap)
3. Transition to round N+2 where LIB falls 3 rounds behind (entering Abnormal status)
4. Call `GetMaximumBlocksCount()` and verify it returns 0
5. Verify that consensus command generation prevents TinyBlock behaviour
6. Demonstrate that only 1 block per time slot can be produced instead of 8

The vulnerability is confirmed through code inspection showing the mathematical edge case where zero miner intersection leads to zero return value, inconsistent with the Severe status handling that explicitly returns 1 as a minimum.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-55)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L81-85)
```csharp
    private static int Ceiling(int num1, int num2)
    {
        var flag = num1 % num2;
        return flag == 0 ? num1.Div(num2) : num1.Div(num2).Add(1);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-54)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();

        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();

        Context.LogDebug(() =>
            $"{currentRound.ToString(_processingBlockMinerPubkey)}\nArranged behaviour: {behaviour.ToString()}");

        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L223-236)
```csharp
    private void RecordMinedMinerListOfCurrentRound()
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        State.MinedMinerListMap.Set(currentRound.RoundNumber, new MinerList
        {
            Pubkeys = { currentRound.GetMinedMiners().Select(m => ByteStringHelper.FromHexString(m.Pubkey)) }
        });

        // Remove information out of date.
        var removeTargetRoundNumber = currentRound.RoundNumber.Sub(3);
        if (removeTargetRoundNumber > 0 && State.MinedMinerListMap[removeTargetRoundNumber] != null)
            State.MinedMinerListMap.Remove(removeTargetRoundNumber);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
