### Title
Missing Validation of Mining Order Values Allows Consensus Timing Manipulation

### Summary
A malicious miner can submit arbitrary `FinalOrderOfNextRound` values through `UpdateValueInput` that bypass validation and corrupt the consensus state. When these invalid orders (e.g., 1, 2, 100, 101 for 4 miners) are used to generate the next round, they cause severe timing disruptions with miners scheduled hundreds of seconds late, breaking consensus liveness and potentially causing array index exceptions.

### Finding Description

**Root Cause**: The `ProcessUpdateValue` method directly writes user-provided `SupposedOrderOfNextRound` and `TuneOrderInformation` values to state without validating they match the expected calculation or are within valid range. [1](#0-0) [2](#0-1) 

**Missing Validation**: The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, but does NOT check that `SupposedOrderOfNextRound` or `TuneOrderInformation` are correct: [3](#0-2) 

**Expected Calculation**: The correct `FinalOrderOfNextRound` should be calculated by `ApplyNormalConsensusData`, which ensures orders are in range [1, minersCount]: [4](#0-3) 

However, a miner can bypass this by providing modified values directly in their transaction.

**Impact on Round Generation**: When `GenerateNextRoundInformation` uses corrupted `FinalOrderOfNextRound` values, it causes multiple failures:

1. **Timing Corruption** - Expected mining times calculated using invalid orders: [5](#0-4) 

If order=100, `ExpectedMiningTime = currentBlockTimestamp + miningInterval * 100`, resulting in delays of hundreds of seconds instead of the expected 4-16 seconds.

2. **Order Assignment Failure** - Available orders calculation breaks with out-of-range values: [6](#0-5) 

With orders [1, 2, 100, 101] and minersCount=4, `ableOrders` becomes [3, 4], causing `IndexOutOfRangeException` if more than 2 miners need reassignment.

3. **BreakContinuousMining Logic Failure** - Cannot find expected order positions: [7](#0-6) 

Searching for order==minersCount returns null when orders are [1, 2, 100, 101], breaking the continuous mining prevention logic.

**Inadequate NextRound Validation**: The `NextRoundMiningOrderValidationProvider` has a flawed check that calls `.Distinct().Count()` on miner objects rather than order values, failing to detect duplicate or invalid orders: [8](#0-7) 

### Impact Explanation

**Consensus Disruption**: 
- Round timing becomes completely invalid, with miners scheduled minutes late instead of seconds
- Consensus cannot progress normally when expected mining times are corrupted
- Subsequent rounds inherit the corruption, causing cascading failures

**Operational Impact**:
- Array index exceptions during order assignment crash the round generation
- Time slot validation fails for subsequent blocks due to incorrect schedules  
- LIB (Last Irreversible Block) calculations may stall

**Liveness Loss**:
- Network cannot produce blocks at expected intervals
- Cross-chain indexing breaks due to timing assumptions
- Entire blockchain halts if critical order positions (first, last, extra block producer) cannot be located

**Affected Parties**: All network participants suffer from consensus degradation. No direct fund loss, but protocol becomes unusable.

### Likelihood Explanation

**Attacker Capabilities**: Any active miner in the current round can exploit this. Miners are trusted to validate blocks but not to arbitrarily set consensus parameters.

**Attack Complexity**: LOW
1. Miner constructs `UpdateValueInput` with manipulated `SupposedOrderOfNextRound` (e.g., 100 instead of expected 1-4)
2. Or includes malicious `TuneOrderInformation` to corrupt other miners' orders
3. Submits transaction through normal `UpdateValue` method
4. Validation passes because `UpdateValueValidationProvider` doesn't check order values
5. Corrupted orders written to state immediately affect next round generation

**Execution Practicality**: The attack is straightforward - modify order values in the transaction input before signing. No special timing or state conditions required.

**Detection Difficulty**: Corrupted orders persist in state and affect subsequent rounds. Detection requires monitoring for orders outside [1, minersCount] range, which is not currently implemented.

**Economic Rationality**: A malicious miner could execute this to disrupt competitors, extort the network, or as griefing with minimal cost (normal transaction fee).

### Recommendation

**Immediate Fix**: Add validation in `ProcessUpdateValue` to verify provided order values match expected calculation:

```csharp
// In ProcessUpdateValue, after line 240:
var expectedRound = currentRound.Clone();
expectedRound.ApplyNormalConsensusData(_processingBlockMinerPubkey, 
    updateValueInput.PreviousInValue, 
    updateValueInput.OutValue, 
    updateValueInput.Signature);

Assert(
    updateValueInput.SupposedOrderOfNextRound == 
    expectedRound.RealTimeMinersInformation[_processingBlockMinerPubkey].SupposedOrderOfNextRound,
    "Invalid SupposedOrderOfNextRound"
);

foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(
        expectedRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound == tuneOrder.Value,
        $"Invalid FinalOrderOfNextRound for {tuneOrder.Key}"
    );
}
```

**Additional Validations**:
1. Add range check: All `FinalOrderOfNextRound` values must be in [1, minersCount]
2. Add distinctness check: Fix `NextRoundMiningOrderValidationProvider` to check distinct ORDER VALUES:
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // SELECT THE ORDER VALUE
    .Distinct().Count();
```

**Test Cases**:
- Attempt UpdateValue with SupposedOrderOfNextRound outside [1, minersCount] → should fail
- Attempt UpdateValue with conflicting TuneOrderInformation → should fail  
- Verify NextRound generation with valid orders [1,2,3,4] → should succeed
- Verify NextRound fails if current round has invalid orders [1,2,100,101]

### Proof of Concept

**Initial State**:
- 4 active miners in current round
- Mining interval = 4000ms
- Current block time = T

**Attack Steps**:
1. Malicious Miner A produces block at their time slot
2. Instead of letting contract calculate `SupposedOrderOfNextRound` normally (e.g., value 2), Miner A constructs `UpdateValueInput` with:
   - `SupposedOrderOfNextRound = 100`
   - `TuneOrderInformation = { "MinerB": 101, "MinerC": 1, "MinerD": 2 }`
3. Miner A submits `UpdateValue(modifiedInput)`
4. Validation passes because `UpdateValueValidationProvider` doesn't check order values
5. State updated with corrupted orders: [1, 2, 100, 101]

**Expected vs Actual Result**:

Expected: Orders remain in valid range [1,2,3,4], next round generates correctly

Actual: 
- Round transitions to next round using corrupted orders
- Miner with order 100: `ExpectedMiningTime = T + (4000ms * 100) = T + 400 seconds`
- Miner with order 101: `ExpectedMiningTime = T + 404 seconds`  
- Normal miners scheduled at T+4s, T+8s
- Round timing completely broken - 6+ minute gap before last miners
- `ableOrders` calculation produces only [3,4], insufficient for reassignments
- Subsequent round generation may crash with `IndexOutOfRangeException`

**Success Condition**: State contains `FinalOrderOfNextRound` values outside valid range [1, minersCount], and next round generation uses these invalid values, causing timing corruption observable in block production delays.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-56)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L93-95)
```csharp
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;
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
