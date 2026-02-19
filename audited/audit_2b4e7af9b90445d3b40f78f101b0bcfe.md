### Title
Unvalidated TuneOrderInformation Allows Arbitrary Order Manipulation Breaking Consensus Timing and Continuous Mining Prevention

### Summary
The `ProcessUpdateValue` function accepts arbitrary `FinalOrderOfNextRound` values through `TuneOrderInformation` without validating they are within the valid range [1, minersCount]. This allows any miner to assign invalid orders (e.g., 1000 when minersCount is 10) to themselves or other miners, breaking consensus timing calculations, bypassing continuous mining prevention, and violating order uniqueness invariants.

### Finding Description

**Root Cause:**
The vulnerability exists in the `ProcessUpdateValue` function where `TuneOrderInformation` values are directly applied to miners' `FinalOrderOfNextRound` without validation: [1](#0-0) 

The `UpdateValueInput` message accepts a map of miner pubkey to order values: [2](#0-1) 

**Why Existing Protections Fail:**

1. **UpdateValueValidationProvider** only validates cryptographic fields (OutValue, Signature, PreviousInValue) but does not check TuneOrderInformation values: [3](#0-2) 

2. **NextRoundMiningOrderValidationProvider** only checks that distinct count matches mined miners count, not that orders are within valid range or unique: [4](#0-3) 

**Execution Path:**

When `GenerateNextRoundInformation` processes the invalid `FinalOrderOfNextRound` (e.g., 1000): [5](#0-4) 

The invalid order is assigned directly to the next round, and `occupiedOrders` calculation fails to prevent this: [6](#0-5) 

### Impact Explanation

**Concrete Harms:**

1. **Consensus Timing Manipulation**: ExpectedMiningTime calculation multiplies order by miningInterval. An order of 1000 instead of valid [1,10] pushes the miner's time slot far into the future (1000x the intended interval), completely breaking round timing: [7](#0-6) 

2. **BreakContinuousMining Bypass**: The function looks for `lastMinerOfNextRound` with `Order == minersCount`. When no miner has this order (one has 1000 instead), it returns null and exits early, failing to prevent the same miner from producing the last block and extra block consecutively: [8](#0-7) 

3. **Extra Block Timing Corruption**: The calculation uses the miner with highest order value. An invalid order of 1000 causes incorrect extra block timing: [9](#0-8) 

4. **Order Uniqueness Violation**: Multiple miners can be assigned identical orders, violating the fundamental invariant that each miner has a unique sequential order.

**Severity**: HIGH - Breaks critical consensus invariants including miner schedule integrity and time-slot validation, enabling continuous mining attacks and consensus disruption.

### Likelihood Explanation

**Attacker Capabilities**: Any active miner in the current round can execute this attack. The miner simply needs to:
- Wait for their designated time slot
- Call `UpdateValue` with a crafted `UpdateValueInput` containing malicious `TuneOrderInformation`

**Attack Complexity**: LOW - The attack requires no special privileges beyond being in the active miner list. The attacker constructs a single transaction with arbitrary order values in `TuneOrderInformation`.

**Feasibility Conditions**: 
- Attacker is in current round's miner list (realistic - miners rotate)
- No additional barriers or checks exist

**Detection**: Difficult to detect proactively as the transaction appears valid to all existing validation providers.

**Probability**: HIGH - Active miners have regular opportunities to execute this during normal operation.

### Recommendation

**Code-Level Mitigation:**

Add validation in `ProcessUpdateValue` before applying `TuneOrderInformation`:

```csharp
// After line 258, before line 259
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Validate order is within valid range
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
        $"Invalid order {tuneOrder.Value} for miner {tuneOrder.Key}. Must be in range [1, {minersCount}]");
    
    // Validate no duplicate orders
    var existingMiner = currentRound.RealTimeMinersInformation.Values
        .FirstOrDefault(m => m.Pubkey != tuneOrder.Key && m.FinalOrderOfNextRound == tuneOrder.Value);
    Assert(existingMiner == null, 
        $"Order {tuneOrder.Value} already assigned to miner {existingMiner?.Pubkey}");
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Invariant Checks:**

Add validation in `NextRoundMiningOrderValidationProvider` to ensure:
- All `FinalOrderOfNextRound` values are in range [1, minersCount]
- All `FinalOrderOfNextRound` values are unique
- Orders form a valid sequence for the next round

**Test Cases:**
1. Test UpdateValue with order > minersCount (should reject)
2. Test UpdateValue with order < 1 (should reject)
3. Test UpdateValue creating duplicate orders (should reject)
4. Test NextRound validation catches invalid order ranges
5. Verify BreakContinuousMining functions correctly with valid orders only

### Proof of Concept

**Initial State:**
- Current round has 10 miners with orders [1-10]
- Miner A is at order position 5
- minersCount = 10

**Attack Steps:**

1. **Miner A produces block during their time slot and calls UpdateValue with:**
```
UpdateValueInput {
    OutValue: <valid_hash>,
    Signature: <valid_signature>,
    TuneOrderInformation: {
        "MinerB_Pubkey": 1000,  // Invalid: > minersCount
        "MinerC_Pubkey": 1000   // Duplicate: same as MinerB
    },
    ... // other valid fields
}
```

2. **Transaction executes successfully:**
   - Line 260 sets `currentRound.RealTimeMinersInformation["MinerB"].FinalOrderOfNextRound = 1000`
   - Line 260 sets `currentRound.RealTimeMinersInformation["MinerC"].FinalOrderOfNextRound = 1000`
   - No validation prevents this

3. **When NextRound is called, GenerateNextRoundInformation executes:**
   - MinerB receives `Order = 1000` in next round
   - MinerC receives `Order = 1000` in next round (duplicate)
   - MinerB's `ExpectedMiningTime = currentBlockTimestamp + (miningInterval * 1000)` (far future)
   - `BreakContinuousMining` fails to find miner with `Order == 10`, returns early
   - `GetExtraBlockMiningTime` uses miner with Order=1000 as "last" miner

**Expected Result:**
Transaction should be rejected with validation error: "Invalid order values in TuneOrderInformation"

**Actual Result:**
Transaction succeeds, next round has invalid orders [1000, 1000, ...], breaking consensus timing and continuous mining prevention.

**Success Condition:**
After the attack, querying next round information shows miners with Order values outside [1, minersCount] and/or duplicate orders, confirming consensus schedule corruption.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L93-95)
```csharp
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L119-121)
```csharp
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
```
