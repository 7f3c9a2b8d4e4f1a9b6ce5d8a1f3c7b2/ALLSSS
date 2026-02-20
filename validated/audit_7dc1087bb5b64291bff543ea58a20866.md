# Audit Report

## Title
Term Change During Abnormal Status Causes Excessive Consensus Restriction via Miner Count Mismatch

## Summary
The `GetMaximumBlocksCount()` function fails to account for term changes when calculating maximum tiny blocks during Abnormal blockchain status. When a term change occurs while the Last Irreversible Block (LIB) is lagging, the function intersects miner lists from different terms, yielding zero or minimal intersection, resulting in drastically reduced maximum blocks count (potentially 0) precisely when the chain needs maximum capacity to recover.

## Finding Description

The vulnerability exists in the Abnormal status handling logic within `GetMaximumBlocksCount()`. [1](#0-0) 

When the blockchain enters Abnormal status, the algorithm retrieves miner lists from rounds R-1 and R-2 via `MinedMinerListMap` and calculates their intersection to determine the maximum blocks count. However, it completely ignores term boundaries.

**Execution Path:**

1. **Term Change Setup:** When `ProcessNextTerm()` executes, it calls `RecordMinedMinerListOfCurrentRound()` which stores the old term's miners. [2](#0-1) 

2. **Miner List Recording:** The recording function captures miners who actually mined blocks in the current round before transitioning. [3](#0-2) 

3. **New Term Initialization:** The first round of the new term is generated with a completely different miner set, and the `IsMinerListJustChanged` flag is set to true. [4](#0-3) 

4. **Vulnerable Calculation:** During round T+1 (second round of new term), if Abnormal status is triggered, `GetMaximumBlocksCount()` retrieves miner lists from different terms, intersects them, and if the miner sets are disjoint, gets zero intersection. [5](#0-4) 

5. **Impact on Block Production:** The zero result flows into `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` where the check becomes `Count < 0` (always false), preventing TinyBlock production. [6](#0-5) 

**Why Protections Fail:**

The `Round` structure contains both `term_number` and `is_miner_list_just_changed` fields that could detect term boundaries. [7](#0-6) 

However, `GetMaximumBlocksCount()` never checks these fields before performing the intersection calculation, blindly assuming miner lists from consecutive rounds are comparable.

## Impact Explanation

**Operational Impact:**

With zero intersection (complete miner set replacement), the calculation returns 0. [8](#0-7) 

This sets the maximum blocks count to 0, meaning miners cannot produce any tiny blocks during their time slot.

Normal operation allows 8 tiny blocks per miner per time slot. [9](#0-8) 

Reducing this to 0 represents 100% throughput reduction for tiny blocks.

**Consensus Impact:**

This throughput restriction occurs during Abnormal status—precisely when the blockchain is struggling with LIB lag and needs maximum block production capacity to advance the LIB and recover to Normal status. The reduced throughput makes recovery slower and increases the risk of escalating to Severe status, which further restricts to 1 block maximum. [10](#0-9) 

**Severity Justification:**

Medium severity is appropriate because:
- Significant operational impact on consensus throughput during critical recovery periods
- Not directly exploitable for fund theft or state corruption
- Temporary (affects specific round T+1 after term change)
- Self-resolving (subsequent rounds use same-term comparisons)
- Naturally occurring rather than requiring attacker exploitation

## Likelihood Explanation

**Feasibility:**

This vulnerability manifests through natural system operation:

1. **Term Changes:** Occur regularly through the election/governance mechanism as part of normal protocol operation. The miner set can change significantly between terms.

2. **LIB Lag:** Occurs naturally due to network delays, node synchronization issues, temporary consensus degradation, or transaction processing delays. LIB lagging by 2-4 rounds is not uncommon under moderate network stress.

3. **Vulnerability Window:** The problematic calculation specifically triggers at round T+1 (second round after term change) when in Abnormal status (defined as `libRoundNumber + 2 < currentRoundNumber < libRoundNumber + 8`). [11](#0-10) 

**Probability:**

Medium probability because:
- Term changes occur periodically (frequency depends on chain configuration)
- LIB lag of 2-4 rounds can occur during network stress or high transaction load
- The intersection of these two events creates a realistic vulnerability window
- The issue is deterministic once conditions are met (not probabilistic)

**Detection:**

The issue manifests visibly through reduced block production rates during term transitions, observable in consensus logs showing unexpectedly low maximum blocks counts when Abnormal status coincides with recent term changes.

## Recommendation

Add term boundary checks in `GetMaximumBlocksCount()` before performing miner list intersection during Abnormal status:

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    // Check if miner list was just changed (first round of new term)
    if (currentRound.IsMinerListJustChanged)
    {
        // Use default maximum for first round of new term
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    // Check if previous rounds belong to the same term
    var previousRound = State.Rounds[currentRoundNumber.Sub(1)];
    var previousPreviousRound = State.Rounds[currentRoundNumber.Sub(2)];
    
    if (previousRound?.TermNumber != currentRound.TermNumber || 
        previousPreviousRound?.TermNumber != currentRound.TermNumber)
    {
        // Different terms - use default maximum
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    // Same term - proceed with intersection as before
    var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
    var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
    // ... rest of the existing logic
}
```

## Proof of Concept

This vulnerability requires integration testing with the full AEDPoS consensus system to properly demonstrate. A valid test would need to:

1. Set up a blockchain with term N and a set of miners
2. Execute rounds until end of term N (recording miner lists)
3. Trigger term change to term N+1 with a different miner set
4. Induce LIB lag to enter Abnormal status during round T+1
5. Call `GetMaximumBlocksCount()` and verify it returns 0
6. Verify that TinyBlock production is prevented via `GetConsensusBehaviour()`

The test would demonstrate that miners cannot produce tiny blocks during the critical recovery period in round T+1 after term change when Abnormal status is active.

**Notes**

This is a design flaw in the consensus throughput calculation logic that assumes miner list continuity across consecutive rounds. The vulnerability is only triggered during the narrow window of the second round after a term change when Abnormal blockchain status is also active. While not exploitable by attackers, it represents a critical operational issue that degrades consensus performance precisely when the system needs maximum throughput to recover from LIB lag.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L123-125)
```csharp
            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-165)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L40-43)
```csharp
        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L199-206)
```csharp
        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
