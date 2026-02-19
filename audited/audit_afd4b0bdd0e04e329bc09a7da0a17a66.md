# Audit Report

## Title
Unfair Extra Block Producer Selection Due to Non-Deterministic Fallback Logic and Inadequate Validation

## Summary
The AEDPoS consensus contract contains a vulnerability in the extra block producer selection mechanism. When duplicate `FinalOrderOfNextRound` values create gaps in the order sequence, the `GenerateNextRoundInformation` function falls back to selecting the first miner via `.First()`, which systematically favors miners with the lowest `FinalOrderOfNextRound` values. This can be triggered naturally through order collisions or maliciously through unvalidated `TuneOrderInformation` manipulation, leading to unfair reward distribution over time.

## Finding Description

The vulnerability stems from three interconnected issues in the consensus round generation logic:

**1. Fallback Logic Bias:**

When generating the next round, the contract calculates which miner should be the extra block producer and searches for a miner with that order. If no miner has the calculated order, it falls back to selecting the first miner in dictionary iteration order: [1](#0-0) 

Since miners are inserted into `nextRound` in ascending `FinalOrderOfNextRound` order, the `.First()` call systematically returns the miner with the lowest `FinalOrderOfNextRound`: [2](#0-1) 

**2. Unvalidated TuneOrderInformation Application:**

When miners call `UpdateValue`, they provide `TuneOrderInformation` which is applied directly to other miners' `FinalOrderOfNextRound` values without validation: [3](#0-2) 

A malicious miner can exploit this by:
- Setting their own `FinalOrderOfNextRound` to a low value (line 247)
- Providing `TuneOrderInformation` that creates duplicates by setting another miner's `FinalOrderOfNextRound` to the same or conflicting values (line 260)

While `ExtractInformationToUpdateConsensus` shows the intended use of `TuneOrderInformation` for communicating legitimate conflict resolutions: [4](#0-3) 

The contract accepts any `TuneOrderInformation` values without verifying their correctness.

**3. Gap Creation from Duplicates:**

When duplicate `FinalOrderOfNextRound` values exist, the logic for determining available orders creates gaps. The `occupiedOrders` list contains the duplicate values, but when assigning orders to miners who didn't mine, some orders are skipped: [5](#0-4) 

If two miners both have `FinalOrderOfNextRound = 3`, then order 3 appears twice in `occupiedOrders`, but other orders (e.g., 5) might not be assigned to anyone in `nextRound`, creating a gap. When `CalculateNextExtraBlockProducerOrder()` returns a gap order, `expectedExtraBlockProducer` becomes `null`, triggering the biased fallback.

**4. Inadequate Validation:**

The `NextRoundMiningOrderValidationProvider` fails to detect duplicate `FinalOrderOfNextRound` values because it uses `.Distinct()` on entire `MinerInRound` protobuf objects: [6](#0-5) 

Since protobuf-generated classes compare all fields in their `Equals()` implementation, two miners with the same `FinalOrderOfNextRound` but different pubkeys are considered distinct, allowing the validation to pass.

**5. Natural Occurrence via Conflict Resolution:**

The conflict resolution logic in `ApplyNormalConsensusData` can also fail to reassign conflicting orders if all positions are occupied: [7](#0-6) 

If the loop completes without finding an available order (lines 31-40), both the conflicted miner and the new miner retain the same `FinalOrderOfNextRound` value (lines 42-44), creating duplicates naturally.

## Impact Explanation

**Direct Reward Misallocation:**
- The extra block producer receives an additional block production reward at the end of each round
- When the `.First()` fallback is triggered, miners with lower `FinalOrderOfNextRound` values are systematically favored
- Over multiple rounds, this creates cumulative reward imbalance

**Consensus Fairness Violation:**
- The extra block producer role is intended to be fairly distributed based on cryptographic randomness from miner signatures
- The fallback mechanism violates this fairness principle by introducing deterministic bias based on insertion order
- This undermines the security assumption that consensus rewards are distributed fairly among all honest miners

**Long-term Impact:**
- Miners who can consistently maintain low `FinalOrderOfNextRound` values (either through luck or manipulation) accumulate unfair advantages
- This weakens the economic incentive structure that ensures consensus security
- Network decentralization is compromised if certain miners consistently receive disproportionate rewards

## Likelihood Explanation

**Natural Occurrence: Low-Medium**
- Order collisions can occur naturally when multiple miners' signatures map to the same order via modulo operation
- The probability increases with the number of active miners and rounds
- The conflict resolution can fail when all orders are occupied, though this is rare

**Malicious Exploitation: Medium-High**
- Any valid miner can call `UpdateValue` with manipulated `TuneOrderInformation`
- The attack requires being a legitimate miner (passes authorization checks at line 28 in ProcessConsensusInformation)
- The manipulation is visible on-chain but appears as normal consensus behavior
- Multiple miners can independently create duplicates, amplifying the effect

**Detection Difficulty: High**
- The issue manifests as legitimate consensus operation
- No explicit validation catches the duplicate orders
- The bias accumulates gradually over many rounds, making it difficult to detect without statistical analysis
- Since miners rotate through the extra block producer role naturally, the bias may not be immediately apparent

**Overall Assessment:**
The vulnerability is feasible to trigger (both naturally and maliciously), has measurable impact on reward distribution, and evades existing validation mechanisms.

## Recommendation

**1. Validate TuneOrderInformation:**
Add validation in `ProcessUpdateValue` to ensure `TuneOrderInformation` values don't create duplicates:

```csharp
// After line 247, before line 259:
var proposedOrders = new Dictionary<int, string>();
proposedOrders[updateValueInput.SupposedOrderOfNextRound] = _processingBlockMinerPubkey;

foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    if (proposedOrders.ContainsKey(tuneOrder.Value))
    {
        Assert(false, $"Duplicate FinalOrderOfNextRound {tuneOrder.Value} detected");
    }
    proposedOrders[tuneOrder.Value] = tuneOrder.Key;
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**2. Fix Validation Provider:**
Update `NextRoundMiningOrderValidationProvider` to check for duplicate `FinalOrderOfNextRound` values specifically:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
    
var minersWithOrderCount = providedRound.RealTimeMinersInformation.Values
    .Count(m => m.FinalOrderOfNextRound > 0);
    
if (distinctOrderCount != minersWithOrderCount)
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

**3. Improve Fallback Logic:**
Instead of using `.First()`, use a deterministic but fair selection based on the calculated order with wraparound:

```csharp
if (expectedExtraBlockProducer == null)
{
    // Find the next available miner in circular order
    var availableMiners = nextRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    var startIndex = extraBlockProducerOrder % availableMiners.Count;
    availableMiners[startIndex].IsExtraBlockProducer = true;
}
```

## Proof of Concept

```csharp
[Fact]
public void Test_DuplicateOrderCreatesUnfairExtraBlockProducerSelection()
{
    // Setup: 5 miners in current round
    var currentRound = GenerateTestRound(5);
    
    // Miner 1 produces block, gets FinalOrderOfNextRound = 1
    currentRound.ApplyNormalConsensusData("Miner1", Hash.Empty, Hash.Empty, GenerateSignatureForOrder(1, 5));
    
    // Miner 2 produces block, maliciously sets TuneOrderInformation
    var updateInput = new UpdateValueInput
    {
        SupposedOrderOfNextRound = 1,  // Conflicts with Miner1
        TuneOrderInformation = {}, // Omits conflict resolution
        // ... other required fields
    };
    
    // Process UpdateValue - both miners now have FinalOrderOfNextRound = 1
    // This creates a gap in the order sequence
    
    // Generate next round
    currentRound.GenerateNextRoundInformation(
        Context.CurrentBlockTime,
        blockchainStartTime,
        out var nextRound,
        false
    );
    
    // Verify gap exists (e.g., order 5 is unassigned)
    var hasOrderFive = nextRound.RealTimeMinersInformation.Values.Any(m => m.Order == 5);
    Assert.False(hasOrderFive);
    
    // CalculateNextExtraBlockProducerOrder might return 5
    // If so, expectedExtraBlockProducer will be null
    // And .First() fallback selects miner with lowest FinalOrderOfNextRound
    
    var extraBlockProducer = nextRound.GetExtraBlockProducerInformation();
    
    // Assert: Extra block producer is systematically the miner with order 1
    // (the miner with lowest FinalOrderOfNextRound from current round)
    Assert.Equal(1, extraBlockProducer.Order);
    
    // This demonstrates the bias: when gaps exist, .First() favors low orders
}
```

## Notes

This vulnerability represents a fairness violation in the consensus mechanism rather than a direct fund theft. The impact is cumulative over time as biased miners accumulate extra block rewards. While the manipulation requires being a valid miner, it can be combined with strategic timing to maximize unfair advantage. The lack of validation on `TuneOrderInformation` is the primary exploitable vector, though natural collisions can also trigger the issue. The fix requires both validation improvements and a more robust fallback mechanism.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L59-65)
```csharp
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-260)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L28-44)
```csharp
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
