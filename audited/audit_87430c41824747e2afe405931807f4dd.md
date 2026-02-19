### Title
Ineffective Duplicate Detection Allows Mining Order Manipulation via Unchecked TuneOrderInformation

### Summary
The `NextRoundMiningOrderValidationProvider` validation fails to detect duplicate `FinalOrderOfNextRound` values because it calls `Distinct()` on `MinerInRound` objects rather than on the order values themselves. Combined with the lack of validation on `TuneOrderInformation` in `UpdateValue`, this allows miners to inject duplicate mining orders, breaking consensus round generation and causing multiple miners to be assigned the same mining slot.

### Finding Description

The vulnerability exists in the validation logic at [1](#0-0) 

The code calls `Distinct()` on a collection of `MinerInRound` objects. Since `MinerInRound` is a protobuf-generated class with value-based equality [2](#0-1) , `Distinct()` only filters out objects that are completely identical across all fields. However, each miner has a unique `pubkey` field [3](#0-2) , meaning no two `MinerInRound` objects will ever be considered duplicates regardless of whether they share the same `FinalOrderOfNextRound` value.

The attack vector exists because `TuneOrderInformation` is applied without validation at [4](#0-3) 

The `UpdateValueValidationProvider` performs no checks on `TuneOrderInformation` content [5](#0-4) , allowing miners to provide arbitrary order assignments.

When the next round is generated, duplicate orders cause critical failures at [6](#0-5)  and [7](#0-6) . The `OrderBy` will arbitrarily sequence miners with duplicate orders, and `occupiedOrders` will contain duplicates, causing incorrect order assignment for miners who missed their slots.

### Impact Explanation

This vulnerability directly compromises consensus integrity by allowing creation of invalid mining schedules where multiple miners are assigned the same order in the next round. This causes:

1. **Consensus breakdown**: Multiple miners attempting to mine at the same time slot violate the fundamental DPoS consensus invariant
2. **Chain fork potential**: Competing blocks produced simultaneously at the same order position
3. **DoS of consensus mechanism**: Invalid round state prevents normal block production
4. **Miner scheduling corruption**: Miners who missed slots get assigned incorrect orders due to duplicate values in `occupiedOrders`

The attack affects all network participants by disrupting block production and potentially causing chain reorganization or consensus halt.

### Likelihood Explanation

**Attacker capabilities**: Any active miner in the current round can execute this attack by including malicious `TuneOrderInformation` when calling `UpdateValue`.

**Attack complexity**: Low. The attacker simply needs to:
1. Wait for other miners to update their consensus values
2. Call `UpdateValue` with crafted `TuneOrderInformation` dictionary assigning duplicate `FinalOrderOfNextRound` values to multiple miners
3. The validation at both `UpdateValue` and `NextRound` will pass

**Feasibility**: Highly feasible. The conflict resolution logic at [8](#0-7)  only prevents conflicts during normal `ApplyNormalConsensusData` execution, but `TuneOrderInformation` bypasses this entirely.

**Detection**: The malicious values persist in state and will cause observable failures when `NextRound` attempts to generate the next mining schedule.

### Recommendation

**Primary fix**: Modify the validation to check distinct order VALUES:

In `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()`, change lines 15-16 to:
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

**Secondary protection**: Add validation for `TuneOrderInformation` to ensure:
1. All assigned order values are unique (no duplicates)
2. Order values are within valid range (1 to minersCount)
3. The tune information matches what conflict resolution would have produced

**Test cases**:
1. Test that validation rejects rounds with duplicate `FinalOrderOfNextRound` values
2. Test that `UpdateValue` with duplicate orders in `TuneOrderInformation` is rejected
3. Test that `GenerateNextRoundInformation` produces valid round with unique orders

### Proof of Concept

**Initial state**: Current round with 5 miners (M1-M5), all having mined blocks with `OutValue != null`.

**Attack sequence**:
1. Miners M1-M4 call `UpdateValue`, each getting assigned unique `FinalOrderOfNextRound` values (1,2,3,4) through normal flow
2. Malicious miner M5 calls `UpdateValue` with:
   - `SupposedOrderOfNextRound`: 5
   - `TuneOrderInformation`: `{ "M3_pubkey": 2, "M4_pubkey": 2 }` (assigns duplicate order 2 to both M3 and M4)
3. `ProcessUpdateValue` applies the malicious tuning at lines 259-260, setting both M3 and M4 to `FinalOrderOfNextRound = 2`
4. Current round state now has: M1=1, M2=2, M3=2, M4=2, M5=5
5. When `NextRound` is called, validation checks `Distinct()` count of MinerInRound objects (5 distinct objects) == miners with OutValue (5), passes
6. `GenerateNextRoundInformation` processes miners ordered by `FinalOrderOfNextRound`: M1(1), M2/M3/M4 all (2), M5(5)
7. Multiple miners get assigned `Order=2` in next round
8. Next round state is invalid with duplicate mining orders

**Expected result**: Validation should reject duplicate `FinalOrderOfNextRound` values
**Actual result**: Validation passes, creating corrupted next round with duplicate orders

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** test/AElf.Types.Tests/HashTests.cs (L85-95)
```csharp
    public void Dictionary_Test()
    {
        var dict = new Dictionary<Hash, string>();
        var hash = HashHelper.ComputeFrom(new byte[] { 10, 14, 1, 15 });
        dict[hash] = "test";

        var anotherHash = HashHelper.ComputeFrom(new byte[] { 10, 14, 1, 15 });

        Assert.True(dict.TryGetValue(anotherHash, out var test));
        test.ShouldBe("test");
    }
```

**File:** protobuf/aedpos_contract.proto (L284-284)
```text
    string pubkey = 9;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-40)
```csharp
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
```
