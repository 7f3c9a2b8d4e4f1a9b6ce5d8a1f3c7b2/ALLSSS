### Title
Missing Validation of TuneOrderInformation Allows Miners to Corrupt Next Round Mining Schedule

### Summary
The `ProcessUpdateValue` function applies `TuneOrderInformation` from `UpdateValueInput` to miners' `FinalOrderOfNextRound` values without validating that the order values are within valid range [1, minersCount] or checking for duplicates. A malicious miner can inject arbitrary order values during their time slot, which then become `Order` values in the next round, corrupting the mining schedule and potentially causing consensus failures or denial of service.

### Finding Description

The vulnerability exists in the consensus update mechanism, specifically in how mining order information is processed: [1](#0-0) 

The `ProcessUpdateValue` function directly applies order values from `UpdateValueInput.TuneOrderInformation` to `currentRound.RealTimeMinersInformation[key].FinalOrderOfNextRound` without any validation. The `UpdateValueInput` message structure allows arbitrary integer values in the `tune_order_information` map: [2](#0-1) 

When `UpdateValue` behavior is validated, only basic checks are performed: [3](#0-2) 

The `UpdateValueValidationProvider` only validates OutValue, Signature, and PreviousInValue: [4](#0-3) 

No validation exists for the range or uniqueness of `TuneOrderInformation` values. When the next round is generated, these corrupted `FinalOrderOfNextRound` values become `Order` values: [5](#0-4) 

The `Order` field directly determines `ExpectedMiningTime` calculation, making it critical for mining schedule integrity. The `occupiedOrders` calculation assumes valid order values: [6](#0-5) 

Even the `NextRoundMiningOrderValidationProvider` does not properly detect duplicate order values, as it calls `.Distinct()` on `MinerInRound` objects rather than on the order values themselves: [7](#0-6) 

### Impact Explanation

This vulnerability allows a malicious miner to corrupt the mining schedule for all subsequent rounds, with severe consensus implications:

1. **Duplicate Order Values**: If multiple miners are assigned the same order (e.g., two miners with Order=3), the `OrderBy` operation in `GenerateNextRoundInformation` produces non-deterministic ordering across nodes. Different nodes would generate different `nextRound` objects with different hash values, causing block consensus to fail.

2. **Out-of-Range Order Values**: If order values exceed `minersCount` (e.g., Order=999 when there are 7 miners), the `ExpectedMiningTime` calculation pushes that miner's time slot far into the future (hours or days), effectively preventing them from mining. The `ableOrders` calculation would also fail to properly assign orders to miners who missed their slots.

3. **Mining Schedule Integrity**: The `BreakContinuousMining` logic expects specific order values (1, 2, minersCount-1, minersCount) to exist. Invalid order assignments could cause this logic to fail or behave incorrectly.

4. **Denial of Service**: Once the round state is corrupted, all nodes would either fail to generate the next round or generate inconsistent rounds, halting block production and consensus progression.

The attack affects all miners and nodes in the network, not just the attacker, making this a protocol-level vulnerability with high severity.

### Likelihood Explanation

The vulnerability is highly exploitable with the following characteristics:

**Attacker Capabilities**: The attacker must be an elected miner, which requires being in the current miner list. This is verified by `PreCheck()`: [8](#0-7) 

**Attack Complexity**: Low. The attacker simply needs to:
1. Modify their node's consensus client code to craft a custom `UpdateValueInput`
2. Submit the malicious `UpdateValue` transaction during their legitimate time slot
3. The `TimeSlotValidationProvider` ensures they can only execute during their designated slot, but does not prevent the attack

**Feasibility**: The `UpdateValue` method is publicly accessible: [9](#0-8) 

Any miner can submit a custom `UpdateValueInput` with arbitrary `TuneOrderInformation` values instead of using the auto-generated transaction.

**Detection**: The attack would be evident after execution when the next round fails to generate properly or generates inconsistent results across nodes, but by then the damage is done.

**Probability**: High. Any malicious miner can execute this attack during every round they participate in, with minimal cost (just the transaction fee).

### Recommendation

Add comprehensive validation for `TuneOrderInformation` in the `UpdateValueValidationProvider` or directly in `ProcessUpdateValue`:

1. **Range Validation**: Ensure all order values in `TuneOrderInformation` are within [1, minersCount]:
   ```csharp
   var minersCount = currentRound.RealTimeMinersInformation.Count;
   foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
   {
       Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
              $"Order value {tuneOrder.Value} out of valid range [1, {minersCount}]");
   }
   ```

2. **Duplicate Detection**: After applying tune orders, verify no two miners have the same `FinalOrderOfNextRound`:
   ```csharp
   var finalOrders = currentRound.RealTimeMinersInformation.Values
       .Where(m => m.FinalOrderOfNextRound > 0)
       .Select(m => m.FinalOrderOfNextRound)
       .ToList();
   Assert(finalOrders.Distinct().Count() == finalOrders.Count, 
          "Duplicate FinalOrderOfNextRound values detected");
   ```

3. **Completeness Check**: Verify all orders from 1 to minersCount are assigned exactly once among miners who produced blocks:
   ```csharp
   var minedMinersCount = currentRound.RealTimeMinersInformation.Values
       .Count(m => m.OutValue != null);
   var expectedOrders = Enumerable.Range(1, minersCount).Take(minedMinersCount).ToHashSet();
   var actualOrders = finalOrders.Where(o => o > 0).ToHashSet();
   Assert(expectedOrders.SetEquals(actualOrders), "Order sequence incomplete or invalid");
   ```

4. **Fix NextRoundMiningOrderValidationProvider**: Change the duplicate detection to check order values, not object references:
   ```csharp
   var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
       .Where(m => m.FinalOrderOfNextRound > 0)
       .Select(m => m.FinalOrderOfNextRound)
       .Distinct()
       .Count();
   ```

### Proof of Concept

**Initial State**:
- 7 miners in current round with proper Order values [1-7]
- Miner A is malicious and scheduled to mine at order 3
- All other miners have calculated their `SupposedOrderOfNextRound` based on signatures

**Attack Sequence**:

1. Miner A's time slot arrives, node calls `GetConsensusExtraData` to generate consensus data
2. Instead of using the auto-generated transaction, Miner A crafts malicious `UpdateValueInput`:
   ```
   UpdateValueInput {
       OutValue: (valid hash)
       Signature: (valid signature)
       SupposedOrderOfNextRound: 4
       TuneOrderInformation: {
           "MinerB": 4,  // Duplicate with A's supposed order
           "MinerC": 999, // Out of range
           "MinerD": 4    // Another duplicate
       }
   }
   ```

3. Miner A submits `UpdateValue` transaction with crafted input
4. Validation passes (no order validation in `UpdateValueValidationProvider`)
5. `ProcessUpdateValue` executes, applying invalid orders:
   - MinerB.FinalOrderOfNextRound = 4
   - MinerC.FinalOrderOfNextRound = 999
   - MinerD.FinalOrderOfNextRound = 4

**Expected Result**: Transaction should be rejected due to invalid order values

**Actual Result**: Transaction succeeds, corrupting the round state:
- Multiple miners now have FinalOrderOfNextRound = 4 (duplicates)
- MinerC has FinalOrderOfNextRound = 999 (out of range)
- When NextRound is triggered, `GenerateNextRoundInformation` produces inconsistent results across nodes
- Block consensus fails, halting the chain

**Success Condition**: The attack succeeds when the malicious `UpdateValue` transaction is accepted and the round state is corrupted with invalid `FinalOrderOfNextRound` values, leading to consensus failure in the next round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
