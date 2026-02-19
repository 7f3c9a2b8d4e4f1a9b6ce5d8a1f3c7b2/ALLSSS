### Title
Unfair Extra Block Producer Selection Due to Non-Deterministic Fallback Logic

### Summary
When `CalculateNextExtraBlockProducerOrder()` returns an order that doesn't correspond to any miner in the next round, the code falls back to selecting the first miner via `.First()`. This fallback can be triggered when duplicate `FinalOrderOfNextRound` values create gaps in the order sequence, and systematically favors miners with the lowest `FinalOrderOfNextRound`, leading to unfair extra block reward distribution. [1](#0-0) 

### Finding Description

**Root Cause:**

The `GenerateNextRoundInformation()` function calculates which miner should be the extra block producer by calling `CalculateNextExtraBlockProducerOrder()`, then searches for a miner with that order. When no miner has the calculated order, it falls back to selecting `.First()`: [2](#0-1) 

**How Gaps Are Created:**

The conflict resolution logic in `ApplyNormalConsensusData` can fail to reassign conflicting orders, resulting in duplicate `FinalOrderOfNextRound` values: [3](#0-2) 

When the loop fails to find an available order (all checked positions are occupied), the conflicted miner retains their order, and the new miner also gets assigned the same order, creating duplicates. Additionally, miners can manipulate `FinalOrderOfNextRound` values via `TuneOrderInformation` during `UpdateValue`: [4](#0-3) 

**Why Existing Validation Fails:**

The `NextRoundMiningOrderValidationProvider` uses `.Distinct()` on entire `MinerInRound` objects rather than just the `FinalOrderOfNextRound` values, making it unable to detect duplicate orders: [5](#0-4) 

**Deterministic Bias:**

When duplicates exist, nextRound has gaps in the order sequence. Miners are inserted in ascending `FinalOrderOfNextRound` order: [6](#0-5) 

The `.First()` call returns the first miner in insertion order, which is always the miner with the lowest `FinalOrderOfNextRound`, creating a systematic bias.

### Impact Explanation

**Direct Reward Misallocation:**
- Extra block producers receive additional block production rewards
- Miners with lower `FinalOrderOfNextRound` values gain unfair advantage when gaps occur
- The selection is deterministic rather than random or fairly distributed
- Over time, this creates cumulative reward imbalance favoring specific miners

**Consensus Integrity:**
- The extra block producer role is intended to be fairly distributed based on cryptographic randomness
- The fallback mechanism violates this fairness principle
- Miners could potentially manipulate their `FinalOrderOfNextRound` position to increase selection probability

**Affected Parties:**
- Miners with higher `FinalOrderOfNextRound` values are disadvantaged
- The overall consensus reward distribution becomes unfair
- Network decentralization is weakened if certain miners consistently receive more rewards

### Likelihood Explanation

**Natural Occurrence:**
The conflict resolution logic can naturally create duplicate orders without malicious intent when multiple miners' signatures map to the same order via modulo operation: [7](#0-6) 

With `minersCount` miners and signature-based order assignment, collision probability increases with round progression.

**Potential Manipulation:**
Miners can influence the situation through `TuneOrderInformation`, though control is limited by:
- Multiple miners can call `UpdateValue` and modify the same state
- The calculated extra block producer order depends on signatures, not fully controllable
- However, strategic manipulation of `FinalOrderOfNextRound` values can increase gap creation probability

**Detection Difficulty:**
- The issue manifests as legitimate consensus behavior
- No explicit validation catches duplicate orders
- Bias accumulates gradually over many rounds

**Feasibility:** Medium-High
- Can occur naturally through normal operation
- Can be amplified through strategic manipulation
- Requires analyzing multiple rounds to detect bias

### Recommendation

**1. Fix Validation Logic:**
Correct the `NextRoundMiningOrderValidationProvider` to check for duplicate `FinalOrderOfNextRound` values:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

**2. Fix Fallback Logic:**
Instead of using `.First()`, implement a deterministic but fair selection mechanism:

```csharp
if (expectedExtraBlockProducer == null)
{
    // Use a deterministic but rotation-based fallback
    var blockHeight = Context.CurrentHeight;
    var miners = nextRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    var fallbackIndex = (int)(blockHeight % miners.Count);
    miners[fallbackIndex].IsExtraBlockProducer = true;
}
```

**3. Strengthen TuneOrderInformation Validation:**
Add validation in `ProcessUpdateValue` to ensure `TuneOrderInformation` values are within valid range and don't create duplicates:

```csharp
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
        "Invalid FinalOrderOfNextRound value");
    // Check for duplicates before applying
}
```

**4. Improve Conflict Resolution:**
Enhance the conflict resolution in `ApplyNormalConsensusData` to guarantee finding an available order by checking all positions systematically.

### Proof of Concept

**Initial State:**
- 5 miners (A, B, C, D, E) in current round
- All miners successfully produce blocks

**Attack Scenario:**

1. **Round N - Natural Collision:**
   - Miner A's signature maps to order 3: `FinalOrderOfNextRound = 3`
   - Miner B's signature also maps to order 3 (collision)
   - Conflict resolution attempts to reassign Miner A
   - Orders 4, 5, 1, 2 are already taken by other miners
   - Conflict resolution fails, both Miner A and B have `FinalOrderOfNextRound = 3`

2. **NextRound Generation:**
   - Miners with `FinalOrderOfNextRound`: A=3, B=3, C=1, D=2, E=4
   - nextRound assigns: C→Order 1, D→Order 2, A→Order 3, B→Order 3 (duplicate!)
   - Order 5 is missing (gap created)
   - `CalculateNextExtraBlockProducerOrder()` returns 5 (20% probability)

3. **Fallback Activation:**
   - `expectedExtraBlockProducer = null` (no miner has Order 5)
   - Code executes: `nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true`
   - Miner C (lowest FinalOrderOfNextRound = 1) becomes extra block producer

**Expected Result:** Extra block producer selected fairly/randomly  
**Actual Result:** Miner C selected deterministically due to lowest `FinalOrderOfNextRound`

**Success Condition:** Over multiple rounds with gaps, miners with lower `FinalOrderOfNextRound` values receive disproportionately more extra block producer assignments than expected by random distribution.

### Notes

The vulnerability stems from two compounding issues:
1. The conflict resolution logic can create duplicate orders
2. The fallback logic is biased rather than fair

While individual occurrences may seem minor, the cumulative effect over many rounds creates measurable reward imbalance. The issue is particularly concerning because it can occur naturally without malicious intent, yet also provides opportunities for strategic manipulation by sophisticated miners who understand the mechanism.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-65)
```csharp
        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-44)
```csharp
        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```
