### Title
Term Change During Abnormal Status Causes Excessive Consensus Restriction via Miner Count Mismatch

### Summary
The `GetMaximumBlocksCount()` function calculates the maximum tiny blocks count by intersecting miner lists from the last two rounds and dividing by the current round's miner count. When a term change occurs during abnormal blockchain status (LIB lagging), the intersection compares miners from different terms with potentially disjoint sets, resulting in a drastically reduced or zero maximum blocks count. This over-restricts block production precisely when the chain needs maximum throughput to recover.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** When blockchain enters Abnormal status (R_LIB + 2 < R < R_LIB + CB1), the algorithm retrieves miner lists from rounds R-1 and R-2 via `MinedMinerListMap` and calculates their intersection. However, it fails to account for term changes where the miner list is completely replaced. [2](#0-1) 

The calculation uses: `factor = minersOfLastTwoRounds * (CB1 - (R - R_LIB))` divided by `currentRound.RealTimeMinersInformation.Count`. [3](#0-2) 

**Why Protections Fail:** The code has no check for term changes. The Round structure contains both `term_number` and `is_miner_list_just_changed` fields that could detect this condition, but they are unused in this calculation. [4](#0-3) 

**Execution Path:** 
1. Term change occurs via `GenerateFirstRoundOfNewTerm`, creating a new miner list (e.g., 21 old miners replaced with 35 new miners) [5](#0-4) 

2. When `RecordMinedMinerListOfCurrentRound` executes at round end, it stores different miner sets for old vs new term rounds [6](#0-5) 

3. During Abnormal status 1-2 rounds after term change, `GetMaximumBlocksCount` compares incompatible miner lists (old term round with new term round), yielding minimal or zero intersection

### Impact Explanation

**Operational Impact - Consensus Restriction:**
- With zero intersection (complete miner set replacement), the calculation yields: `Ceiling(0, 35) = 0`, setting maximum blocks count to 0 [7](#0-6) 

- Miners cannot produce tiny blocks when `ActualMiningTimes.Count < 0` is always false (Count cannot be negative) [8](#0-7) 

- Normal maximum is 8 tiny blocks per miner per time slot; reducing to 0-1 blocks represents an 87-100% throughput reduction [9](#0-8) 

**Consensus Impact:**
- Blocks are restricted during Abnormal status when the chain most needs throughput to advance LIB and recover
- Prolonged Abnormal status increases risk of transitioning to Severe status (R >= R_LIB + CB1), which further reduces to 1 block maximum and fires `IrreversibleBlockHeightUnacceptable` events [10](#0-9) 

**Severity Justification:** Medium - significant operational impact on consensus throughput during critical recovery periods, but not directly exploitable for fund theft or complete halt.

### Likelihood Explanation

**Feasibility:** This is NOT directly exploitable but occurs through natural system operation:

1. **Term Changes:** Controlled by governance/election contract, occur regularly as part of normal operations [11](#0-10) 

2. **LIB Lag:** Occurs naturally due to network delays, node synchronization issues, or temporary consensus degradation

3. **Vulnerability Window:** The problematic calculation only triggers during 2-3 rounds immediately after term change while in Abnormal status (R_LIB + 2 < R < R_LIB + 8) [12](#0-11) 

**Attack Complexity:** N/A - not exploitable by attackers, but represents a design flaw that manifests under specific operational conditions

**Probability:** Medium - term changes occur periodically (every several days/weeks depending on chain configuration), and LIB lag can occur during network stress. The intersection of these events creates vulnerability windows.

**Detection:** The issue self-manifests through reduced block production, observable in consensus logs showing low maximum blocks counts during term transitions.

### Recommendation

**Immediate Fix:** Add term change detection before calculating intersection-based restrictions:

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    // NEW: Check if term changed in last two rounds
    var currentTermNumber = currentRound.TermNumber;
    TryToGetRoundInformation(currentRoundNumber.Sub(1), out var previousRound);
    TryToGetRoundInformation(currentRoundNumber.Sub(2), out var previousPreviousRound);
    
    if (previousRound.TermNumber != previousPreviousRound.TermNumber || 
        previousRound.IsMinerListJustChanged)
    {
        // Term changed or miner list replaced - use safe default
        Context.LogDebug(() => "Term change detected, using default maximum blocks count");
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    // Original calculation only when comparing same-term rounds
    var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
    var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
    // ... rest of existing logic
}
```

**Invariant to Enforce:** When calculating cross-round miner statistics during Abnormal status, ensure compared rounds belong to the same term with consistent miner lists.

**Test Cases:**
1. **Term Change During Abnormal Status:** Simulate term change with complete miner set replacement while LIB lags by 3-5 rounds. Verify maximum blocks count remains at default value (8), not 0.
2. **Miner Replacement During Abnormal:** Test mid-term evil miner replacement scenario to ensure flag detection works correctly.
3. **Normal Abnormal Status:** Verify existing reduction logic still functions when no term change occurred.

### Proof of Concept

**Initial State:**
- Round 100: Last round of term 1 with 21 miners (miners A1-A21)
- Governance triggers term change
- Round 101: First round of term 2 with 35 new miners (miners B1-B35, NO overlap with A1-A21)
- LIB stuck at round 97 due to network partition recovery

**Transaction Steps:**
1. Round 101 completes → `RecordMinedMinerListOfCurrentRound` stores B-miners who mined in `MinedMinerListMap[101]`
2. Round 102 starts, miner queries `GetConsensusCommand`
3. System calls `GetMaximumBlocksCount()`:
   - currentRoundNumber = 102
   - R - R_LIB = 102 - 97 = 5
   - Status = Abnormal (97 + 2 < 102 < 97 + 8) ✓
   - Retrieves `MinedMinerListMap[101]` = B-miners (up to 35)
   - Retrieves `MinedMinerListMap[100]` = A-miners (up to 21)  
   - Intersection(B-miners, A-miners) = 0 (disjoint sets)
   - factor = 0 * (8 - 5) = 0
   - Ceiling(0, 35) = 0
   - Min(8, 0) = **0**

**Expected vs Actual Result:**
- **Expected:** Maximum blocks count should remain at 8 or gracefully degrade (e.g., to 4-6) during term transitions
- **Actual:** Maximum blocks count = 0, preventing all tiny block production

**Success Condition:** Miner cannot produce tiny blocks (behavior returns Nothing or TerminateRound instead of TinyBlock), observable in consensus command generation and reduced block rate during the affected rounds.

**Notes:**
- The vulnerability naturally resolves after 2-3 rounds when both R-1 and R-2 belong to the new term, but damage occurs during the critical recovery window
- The mismatch between numerator context (comparing old/new term miners) and denominator context (new term size only) creates the mathematical distortion
- Similar issues may exist in other cross-round calculations that don't account for term boundaries

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-128)
```csharp
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);

        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L12-45)
```csharp
    internal Round GenerateFirstRoundOfNewTerm(int miningInterval,
        Timestamp currentBlockTime, long currentRoundNumber = 0, long currentTermNumber = 0)
    {
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();

        var round = new Round();

        for (var i = 0; i < sortedMiners.Count; i++)
        {
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

        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;

        return round;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L290-295)
```csharp
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }
```
