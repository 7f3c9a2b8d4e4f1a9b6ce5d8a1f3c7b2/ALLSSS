### Title
Unvalidated FinalOrderOfNextRound Values Enable Consensus Disruption via TuneOrderInformation Manipulation

### Summary
The `ProcessUpdateValue` function accepts arbitrary `TuneOrderInformation` values without validating they fall within the valid range [1, minersCount], allowing any miner to set other miners' `FinalOrderOfNextRound` to out-of-range values. When `GenerateNextRoundInformation` subsequently uses these unvalidated values to assign mining orders for the next round, the consensus mechanism breaks down completely, halting the blockchain's ability to produce blocks correctly.

### Finding Description

**Root Cause:** The vulnerability exists in the consensus round generation logic where miner order values are not validated against valid bounds.

In `ProcessUpdateValue`, the `TuneOrderInformation` dictionary from `UpdateValueInput` is directly applied to miners' `FinalOrderOfNextRound` fields without any range validation: [1](#0-0) 

The protobuf definition shows `tune_order_information` is a simple `map<string, int32>` with no constraints: [2](#0-1) 

When `GenerateNextRoundInformation` is called during round transitions, it directly uses these `FinalOrderOfNextRound` values as the `Order` for the next round without validation: [3](#0-2) 

The subsequent logic at lines 40-41 attempts to determine available orders, but this logic fails when `FinalOrderOfNextRound` values are out-of-range: [4](#0-3) 

The `occupiedOrders` list will contain the out-of-range values (e.g., 100, -5, 0), but `ableOrders` only generates values in [1, minersCount]. This means:
1. Miners with out-of-range orders are assigned those invalid orders
2. The available orders don't account for the invalid assignments
3. Mining schedule integrity is destroyed

**Why Existing Protections Fail:**

The `NextRoundMiningOrderValidationProvider` only checks distinctness, not range bounds: [5](#0-4) 

No validation provider checks that order values are within [1, minersCount].

### Impact Explanation

**Consensus Integrity Destruction:**
- Miners are assigned invalid orders (0, negative values, or values exceeding minersCount)
- Expected mining times are calculated incorrectly, causing miners to mine at wrong times or not at all
- The `BreakContinuousMining` function will fail when trying to find miners with order 1 or order minersCount if those orders don't exist [6](#0-5) [7](#0-6) 

**Operational Halt:**
- Round transitions fail or produce invalid states
- Block production stops as miners have incorrect time slots
- Consensus mechanism cannot recover without manual intervention
- The entire blockchain halts

**Severity Justification:** HIGH - Complete consensus disruption affecting all network participants, requiring emergency intervention to restore chain operation.

### Likelihood Explanation

**Attacker Capabilities:** Any miner in the current round can execute this attack by submitting a single `UpdateValue` transaction.

**Attack Complexity:** Trivial - the attacker only needs to:
1. Craft an `UpdateValueInput` with malicious `TuneOrderInformation` entries
2. Submit it via the public `UpdateValue` method [8](#0-7) 

**Feasibility Conditions:** 
- Attacker must be a current miner (authorized to call UpdateValue)
- No additional preconditions required
- No economic cost beyond transaction fees

**Detection/Operational Constraints:**
- Attack executes in a single transaction
- No anomalous behavior until round transition occurs
- Difficult to detect before impact manifests

**Probability:** High - any miner can execute this attack at any time during normal operations.

### Recommendation

**Immediate Fix:** Add range validation in `ProcessUpdateValue` before applying `TuneOrderInformation`:

```csharp
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Validate order is within valid range
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
           $"Invalid order {tuneOrder.Value}, must be in range [1, {minersCount}]");
    
    // Validate no duplicate orders
    Assert(currentRound.RealTimeMinersInformation.Values
           .Where(m => m.Pubkey != tuneOrder.Key)
           .All(m => m.FinalOrderOfNextRound != tuneOrder.Value),
           $"Order {tuneOrder.Value} is already occupied");
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Additional Safeguards:**
1. Add defensive validation in `GenerateNextRoundInformation` to reject out-of-range orders:
   - Before line 28, verify: `Assert(order >= 1 && order <= minersCount, "Order out of valid range")`

2. Enhance validation provider to check order ranges:
   - Modify `NextRoundMiningOrderValidationProvider` to verify all orders are in [1, minersCount]

3. Add unit tests covering:
   - Out-of-range positive orders (> minersCount)
   - Zero and negative orders
   - Duplicate order assignments
   - Full round generation with invalid orders

### Proof of Concept

**Initial State:**
- Network has 5 miners (minersCount = 5): A, B, C, D, E
- Current round in progress
- All miners have valid FinalOrderOfNextRound values [1-5]

**Attack Execution:**

Step 1: Malicious Miner A submits UpdateValue with crafted TuneOrderInformation:
```
UpdateValueInput {
    ... (normal consensus fields)
    TuneOrderInformation: {
        "B": 100,    // Far exceeds minersCount
        "C": 0,      // Invalid (below minimum)
        "D": -5      // Negative (invalid)
    }
}
```

Step 2: ProcessUpdateValue executes without validation, corrupting state:
- Miner B: FinalOrderOfNextRound = 100
- Miner C: FinalOrderOfNextRound = 0
- Miner D: FinalOrderOfNextRound = -5

Step 3: NextRound is triggered, GenerateNextRoundInformation executes:
- Line 26-36: Assigns invalid orders to next round
  - Miner B gets Order = 100
  - Miner C gets Order = 0
  - Miner D gets Order = -5
- Line 33: ExpectedMiningTime calculations produce incorrect timestamps
  - Miner B's time is far in the future
  - Miner D's time is in the past

Step 4: Consensus breaks down:
- BreakContinuousMining fails to find miners with valid orders
- Mining schedule is corrupted
- No miner can produce blocks at correct times
- Chain halts or produces invalid blocks

**Expected Result:** UpdateValue transaction should be rejected with validation error.

**Actual Result:** Transaction succeeds, consensus state is corrupted, chain operation fails.

**Success Condition:** After attack, querying next round information shows miners with invalid Order values (0, -5, 100), and subsequent block production attempts fail.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** protobuf/aedpos_contract.proto (L30-31)
```text
    rpc UpdateValue (UpdateValueInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-86)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L93-107)
```csharp
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;

        var extraBlockProducerOfNextRound = nextRound.GetExtraBlockProducerInformation();
        if (lastMinerOfNextRound.Pubkey == extraBlockProducerOfNextRound.Pubkey)
        {
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
            lastButOneMinerOfNextRound.Order = minersCount;
            lastMinerOfNextRound.Order = minersCount.Sub(1);
            var tempTimestamp = lastButOneMinerOfNextRound.ExpectedMiningTime;
            lastButOneMinerOfNextRound.ExpectedMiningTime = lastMinerOfNextRound.ExpectedMiningTime;
            lastMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
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
