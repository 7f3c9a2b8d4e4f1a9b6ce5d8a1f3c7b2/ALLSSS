### Title
Insufficient Validation of Mining Order Uniqueness Allows Next Round Schedule Corruption

### Summary
The `NextRoundMiningOrderValidationProvider` incorrectly uses `Distinct()` on `MinerInRound` objects instead of their `FinalOrderOfNextRound` values, failing to detect duplicate mining orders. This allows a malicious extra block producer to submit NextRound consensus data with multiple miners assigned identical orders, corrupting the next round's miner schedule and breaking consensus integrity.

### Finding Description

The vulnerability exists in the validation logic that checks mining order assignments for the next round: [1](#0-0) 

The code calls `Distinct()` on `MinerInRound` objects, which are protobuf-generated classes that implement field-by-field equality. Since each `MinerInRound` has a unique `Pubkey`, `OutValue`, `Signature`, and other fields, `Distinct()` will never filter out miners with duplicate `FinalOrderOfNextRound` values. The check effectively becomes: "count of miners with orders > 0 equals count of miners who mined," completely failing to validate order uniqueness.

The validation service conditionally adds this provider only for NextRound behavior: [2](#0-1) 

When the malicious NextRound data passes validation and executes, `GenerateNextRoundInformation` processes the duplicate orders: [3](#0-2) 

Multiple miners with the same `FinalOrderOfNextRound` value will be assigned the same `Order` in the next round, creating time slot conflicts since `ExpectedMiningTime` is calculated from the order value.

### Impact Explanation

**Consensus Integrity Breach**: An attacker can corrupt the next round's miner schedule by assigning duplicate orders. For example, setting all miners to `FinalOrderOfNextRound = 1` causes all miners to attempt mining at the same time slot, while leaving other time slots empty.

**Time Slot Conflicts**: Multiple miners with identical orders will have the same `ExpectedMiningTime`, causing only one to successfully produce blocks while others miss their "slots," incorrectly incrementing their `MissedTimeSlots` counter. [4](#0-3) 

**Schedule Corruption**: The logic for assigning orders to miners who didn't mine assumes unique occupied orders. With duplicates, some order values are "consumed" multiple times while others remain unused, breaking the round-robin mining schedule fundamental to AEDPoS consensus.

**Affected Parties**: All network participants are affected as consensus cannot proceed correctly. Miners are denied their fair mining slots, block production becomes unpredictable, and chain finality is compromised.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be the extra block producer for the current round, which rotates among all miners. In a network with N miners, each miner becomes the extra block producer approximately every N rounds, providing regular attack opportunities. [5](#0-4) 

**Attack Complexity**: Low. The attacker simply crafts a custom `AElfConsensusHeaderInformation` with their NextRound data containing duplicate `FinalOrderOfNextRound` values instead of using the legitimate `GetConsensusBlockExtraData` output. This bypasses the proper order assignment logic: [6](#0-5) 

**Feasibility**: The validation runs before every block execution and the flawed validator allows the attack: [7](#0-6) 

**Detection**: The attack may go undetected initially as the block appears to follow consensus rules, only revealing corruption when the next round begins and time slot conflicts emerge.

### Recommendation

Replace the object-level `Distinct()` with value-level uniqueness validation:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    
    // Get miners who determined next round order
    var minersWithOrders = providedRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0).ToList();
    
    // Get miners who mined
    var minersWhoMined = providedRound.RealTimeMinersInformation.Values
        .Count(m => m.OutValue != null);
    
    // Check counts match
    if (minersWithOrders.Count != minersWhoMined)
    {
        validationResult.Message = "Invalid FinalOrderOfNextRound count.";
        return validationResult;
    }
    
    // Check order values are unique
    var orderValues = minersWithOrders.Select(m => m.FinalOrderOfNextRound).ToList();
    if (orderValues.Distinct().Count() != orderValues.Count)
    {
        validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
        return validationResult;
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

Add invariant check: All `FinalOrderOfNextRound` values must be unique and within range [1, minerCount].

Add regression test: Verify validation fails when NextRound data contains duplicate order assignments.

### Proof of Concept

**Initial State:**
- Current round has 5 miners: [A, B, C, D, E]
- Miner E is the extra block producer
- All miners have mined successfully with unique `FinalOrderOfNextRound` values

**Attack Steps:**
1. Miner E (extra block producer) should generate NextRound data via legitimate path but instead crafts custom `AElfConsensusHeaderInformation`
2. Sets `Behaviour = AElfConsensusBehaviour.NextRound`
3. Creates Round data where all miners have `FinalOrderOfNextRound = 1` (or any duplicate values)
4. Submits block with this crafted consensus extra data

**Validation Flow:**
1. `ValidateConsensusBeforeExecution` calls `HeaderInformationValidationService`
2. `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` executes
3. Line 15-16: `Distinct()` on MinerInRound objects returns all 5 objects (different Pubkeys)
4. Line 17: Check passes: 5 (distinctCount) == 5 (miners who mined)
5. Validation succeeds despite duplicate order values

**Execution Result:**
1. `NextRound` transaction executes via `ProcessNextRound`
2. `GenerateNextRoundInformation` processes the malicious Round data
3. All 5 miners assigned `Order = 1` in next round
4. All miners have identical `ExpectedMiningTime`
5. Only one miner successfully produces blocks; others incorrectly marked as missing time slots
6. Orders 2-5 remain empty, breaking the mining schedule

**Expected vs Actual:**
- Expected: Validation rejects duplicate `FinalOrderOfNextRound` values
- Actual: Validation passes, allowing consensus corruption

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L94-103)
```csharp
        var service = new HeaderInformationValidationService(validationProviders);

        Context.LogDebug(() => $"Validating behaviour: {extraData.Behaviour.ToString()}");

        var validationResult = service.ValidateInformation(validationContext);

        if (validationResult.Success == false)
            Context.LogDebug(() => $"Consensus Validation before execution failed : {validationResult.Message}");

        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-55)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-44)
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

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```
