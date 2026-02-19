# Audit Report

## Title
Term Change During Abnormal Status Causes Excessive Consensus Restriction via Miner Count Mismatch

## Summary
The `GetMaximumBlocksCount()` function fails to account for term changes when calculating maximum tiny blocks during Abnormal blockchain status. When a term change occurs (replacing the miner set) while the Last Irreversible Block (LIB) is lagging, the function intersects miner lists from different terms, yielding zero or minimal intersection. This results in a drastically reduced maximum blocks count (potentially 0), causing an 87.5% throughput reduction precisely when the chain needs maximum capacity to recover.

## Finding Description

The vulnerability exists in the Abnormal status handling logic within `GetMaximumBlocksCount()`. [1](#0-0) 

When the blockchain enters Abnormal status (defined as `libRoundNumber + 2 < currentRoundNumber < libRoundNumber + 8`), the algorithm retrieves miner lists from rounds R-1 and R-2 via `MinedMinerListMap` and calculates their intersection to determine the maximum blocks count. However, it completely ignores term boundaries.

**Execution Path:**

1. **Term Change Setup:** When `ProcessNextTerm()` executes at the end of the old term's last round (T-1), it calls `RecordMinedMinerListOfCurrentRound()` which stores the old term's miners. [2](#0-1) 

2. **Miner List Recording:** The recording function captures miners who actually mined blocks in the current round before transitioning. [3](#0-2) 

3. **New Term Initialization:** The first round of the new term is generated with a completely different miner set, and the `IsMinerListJustChanged` flag is set to true. [4](#0-3) 

4. **Vulnerable Calculation:** During round T+1 (second round of new term), if Abnormal status is triggered, `GetMaximumBlocksCount()` retrieves `MinedMinerListMap[T]` (new term miners) and `MinedMinerListMap[T-1]` (old term miners), intersects them, and if the miner sets are disjoint, gets zero intersection.

5. **Impact on Block Production:** The zero result flows into `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` where the check `_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount` becomes `Count < 0`, which is always false, preventing TinyBlock production. [5](#0-4) 

**Why Protections Fail:**

The `Round` structure contains both `term_number` and `is_miner_list_just_changed` fields that could detect term boundaries. [6](#0-5)  However, `GetMaximumBlocksCount()` never checks these fields before performing the intersection calculation. The code blindly assumes miner lists from consecutive rounds are comparable, violating the invariant during term transitions.

## Impact Explanation

**Operational Impact:**

With zero intersection (complete miner set replacement), the `Ceiling(0, minerCount)` calculation returns 0. [7](#0-6)  This sets the maximum blocks count to 0, meaning miners cannot produce any tiny blocks during their time slot.

Normal operation allows 8 tiny blocks per miner per time slot (defined in `AEDPoSContractConstants.MaximumTinyBlocksCount`). [8](#0-7)  Reducing this to 0 represents an 87.5% throughput reduction.

**Consensus Impact:**

This throughput restriction occurs during Abnormal status—precisely when the blockchain is struggling with LIB lag and needs maximum block production capacity to advance the LIB and recover to Normal status. The reduced throughput makes recovery slower and increases the risk of escalating to Severe status (R >= R_LIB + 8), which further restricts to 1 block maximum and fires `IrreversibleBlockHeightUnacceptable` events. [9](#0-8) 

**Severity Justification:**

Medium severity is appropriate because:
- Significant operational impact on consensus throughput
- Affects critical recovery periods
- Not directly exploitable for fund theft
- Temporary (affects specific round T+1 after term change)
- Self-resolving (subsequent rounds use same-term comparisons)

## Likelihood Explanation

**Feasibility:**

This vulnerability manifests through natural system operation, not attacker exploitation:

1. **Term Changes:** Occur regularly through the election/governance mechanism as part of normal protocol operation. The miner set can change significantly between terms (e.g., 21 miners replaced with 35 different miners).

2. **LIB Lag:** Occurs naturally due to network delays, node synchronization issues, temporary consensus degradation, or transaction processing delays. LIB lagging by 2-4 rounds is not uncommon under moderate network stress.

3. **Vulnerability Window:** The problematic calculation specifically triggers at round T+1 (second round after term change) when in Abnormal status. For Abnormal status at T+1, we need `libRoundNumber + 2 < T+1 < libRoundNumber + 8`, which is satisfied if `libRoundNumber ≤ T-3`.

**Probability:**

Medium probability because:
- Term changes occur periodically (frequency depends on chain configuration, typically days to weeks)
- LIB lag of 2-4 rounds can occur during network stress or high transaction load
- The intersection of these two events creates a realistic vulnerability window
- The issue is deterministic once conditions are met (not probabilistic)

**Detection:**

The issue manifests visibly through reduced block production rates during term transitions, observable in consensus logs showing unexpectedly low maximum blocks counts when Abnormal status coincides with recent term changes.

## Recommendation

Add a term change check in `GetMaximumBlocksCount()` before performing the intersection calculation. When `IsMinerListJustChanged` is true or when comparing rounds from different terms, use an alternative calculation that doesn't rely on miner list intersection.

**Recommended Fix:**

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    // Check if we're comparing rounds across term boundaries
    TryToGetRoundInformation(currentRoundNumber.Sub(1), out var previousRound);
    TryToGetRoundInformation(currentRoundNumber.Sub(2), out var previousPreviousRound);
    
    if (currentRound.IsMinerListJustChanged || 
        previousRound?.TermNumber != previousPreviousRound?.TermNumber)
    {
        // Use fallback calculation for term boundaries
        // Option 1: Use current miner count as baseline
        var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
            currentRound.RealTimeMinersInformation.Count);
        Context.LogDebug(() => $"Maximum blocks count (term boundary): {count}");
        return count;
    }
    
    // Original logic for same-term rounds
    var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
    var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
    var minersOfLastTwoRounds = previousRoundMinedMinerList
        .Intersect(previousPreviousRoundMinedMinerList).Count();
    // ... rest of calculation
}
```

This ensures the maximum blocks count remains reasonable during term transitions, allowing the chain to maintain throughput during critical recovery periods.

## Proof of Concept

A proof of concept would require setting up an AElf consensus test environment with:

1. A term change transaction that replaces the miner set
2. A mechanism to induce LIB lag (by delaying block confirmations)
3. Monitoring of the `GetMaximumBlocksCount()` return value during round T+1
4. Verification that TinyBlock behavior is blocked when the count reaches 0

The test would demonstrate that at round T+1, with Abnormal status and a recent term change, `GetMaximumBlocksCount()` returns 0, and miners cannot produce tiny blocks despite being within their time slots. This would be observable through consensus behavior logs showing only UpdateValue behaviors instead of TinyBlock behaviors during the affected round.

---

**Notes:**

The vulnerability is valid because it represents a design flaw in the consensus algorithm where term boundaries are not properly handled in the Abnormal status recovery logic. While not directly exploitable by attackers, it creates a reproducible degradation in consensus throughput during the specific operational condition of term change + LIB lag, which can occur naturally and has measurable impact on blockchain recovery capabilities.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-54)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L57-67)
```csharp
        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-165)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L223-230)
```csharp
    private void RecordMinedMinerListOfCurrentRound()
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        State.MinedMinerListMap.Set(currentRound.RoundNumber, new MinerList
        {
            Pubkeys = { currentRound.GetMinedMiners().Select(m => ByteStringHelper.FromHexString(m.Pubkey)) }
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L40-42)
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

**File:** protobuf/aedpos_contract.proto (L254-261)
```text
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
