# Audit Report

## Title
Maximum Blocks Count Can Return Zero Leading to Severe Throughput Degradation in Abnormal Status

## Summary
The `GetMaximumBlocksCount()` function in the AEDPoS consensus contract returns 0 when the blockchain is in Abnormal status and no miners appear in both of the last two rounds. This prevents miners from producing tiny blocks, reducing maximum throughput by 87.5% (from 8 blocks to 1 block per time slot) during periods when the network is already under stress.

## Finding Description

When the blockchain enters **Abnormal mining status** (LIB is 2-7 rounds behind current round), the `GetMaximumBlocksCount()` function calculates a dynamic maximum based on miners who successfully mined in the previous two rounds. [1](#0-0) 

The calculation retrieves mined miner lists and finds their intersection: [2](#0-1) 

When `minersOfLastTwoRounds` equals 0 (no common miners between rounds N-1 and N-2), the calculated `factor` becomes 0. The `Ceiling` function returns 0 for a zero numerator, [3](#0-2)  leading to `Math.Min(MaximumTinyBlocksCount, 0)` returning 0.

This zero value is used in consensus behavior determination. In `ConsensusBehaviourProviderBase`, the condition to allow TinyBlock production checks if `ActualMiningTimes.Count < _maximumBlocksCount`. [4](#0-3)  When `_maximumBlocksCount` is 0, this condition is always false (since Count ≥ 0), preventing TinyBlock behavior. The same check appears at another location. [5](#0-4) 

This behavior is **inconsistent** with Severe status handling, which explicitly returns 1 as a minimum to maintain basic block production. [6](#0-5) 

The vulnerability is triggered when `GetMinedMiners()` returns empty lists for one or both of the previous two rounds. This occurs when no miners have `SupposedOrderOfNextRound != 0` in a round. [7](#0-6)  These lists are recorded during round transitions. [8](#0-7) 

## Impact Explanation

**Severe Throughput Degradation:**
Under normal conditions, `MaximumTinyBlocksCount` is configured as 8, [9](#0-8)  allowing miners to produce up to 8 tiny blocks per time slot. When this bug returns 0, miners can only produce 1 UPDATE_VALUE block per time slot, representing an **87.5% reduction** in maximum throughput.

**Operational Denial-of-Service:**
- Transaction backlog accumulates as the network cannot process its normal transaction load
- Users experience severe delays or complete inability to submit transactions
- Critical governance proposals and time-sensitive operations may fail
- The network becomes effectively unusable for its intended purpose despite consensus mechanisms continuing to operate

**Compounding Effect:**
This bug manifests precisely when the blockchain is **already under stress** (Abnormal status indicates LIB is falling behind), exacerbating the degradation when higher throughput is most needed for recovery.

## Likelihood Explanation

**Entry Point:**
The function is invoked during standard consensus command generation for TinyBlock production. [10](#0-9) 

**Preconditions:**
1. Blockchain must enter Abnormal status (LIB is 2-7 rounds behind current round) - this occurs naturally during network partitioning, high latency, or miner failures
2. No miners from round N-1 also mined in round N-2, resulting in zero intersection

**Feasibility:**
These conditions are **highly feasible** during network stress scenarios:
- Abnormal status is a designed state for handling degraded network conditions
- When miners fail to produce blocks (due to network issues, downtime, or synchronization problems), their `SupposedOrderOfNextRound` remains 0
- Empty or non-overlapping mined miner lists occur naturally when different subsets of miners successfully produce blocks across consecutive rounds
- The scenario requires no attacker - it happens through natural network dynamics

The deterministic code path makes this reproducible whenever the preconditions are met.

## Recommendation

Add a minimum floor value check in the Abnormal status branch, consistent with the Severe status handling:

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
    
    // Add minimum floor to prevent zero return value
    count = Math.Max(1, count);
    
    Context.LogDebug(() => $"Maximum blocks count tune to {count}");
    return count;
}
```

This ensures miners can always produce at least 1 tiny block per time slot, maintaining minimal throughput during network stress while still applying the dynamic reduction based on network conditions.

## Proof of Concept

```csharp
[Fact]
public async Task GetMaximumBlocksCount_Returns_Zero_In_Abnormal_Status_With_No_Common_Miners()
{
    // Setup: Create a scenario where blockchain is in Abnormal status
    // and last two rounds have no common miners
    
    var currentRound = new Round
    {
        RoundNumber = 10,
        ConfirmedIrreversibleBlockRoundNumber = 6, // 4 rounds behind (Abnormal: 2 < gap < 8)
        RealTimeMinersInformation = { /* 5 miners */ }
    };
    
    // Round 9: Miners A, B mined (SupposedOrderOfNextRound != 0)
    var round9MinedMiners = new MinerList { Pubkeys = { ByteString.CopyFromUtf8("A"), ByteString.CopyFromUtf8("B") } };
    
    // Round 8: Miners C, D mined (SupposedOrderOfNextRound != 0) - no overlap with round 9
    var round8MinedMiners = new MinerList { Pubkeys = { ByteString.CopyFromUtf8("C"), ByteString.CopyFromUtf8("D") } };
    
    // Set up state
    State.MinedMinerListMap[9] = round9MinedMiners;
    State.MinedMinerListMap[8] = round8MinedMiners;
    State.CurrentRoundInformation.Value = currentRound;
    
    // Execute
    var result = GetMaximumBlocksCount();
    
    // Verify: Returns 0 instead of positive minimum
    Assert.Equal(0, result);
    
    // Verify impact: Miner cannot produce TinyBlock with _maximumBlocksCount = 0
    var behaviour = GetConsensusBehaviour(minerInRound, currentRound, 0);
    Assert.NotEqual(AElfConsensusBehaviour.TinyBlock, behaviour);
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L110-112)
```csharp
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L46-52)
```csharp
            case AElfConsensusBehaviour.TinyBlock:
            {
                var consensusCommand =
                    new ConsensusCommandProvider(new TinyBlockCommandStrategy(currentRound, pubkey,
                        currentBlockTime, GetMaximumBlocksCount())).GetConsensusCommand();
                return consensusCommand;
            }
```
