### Title
Critical Consensus Manipulation via Unchecked FinalOrderOfNextRound Duplicates

### Summary
The `ValidateHeaderInformation()` method in `NextRoundMiningOrderValidationProvider` fails to validate that `FinalOrderOfNextRound` values are unique across miners. N-1 colluding miners can exploit this by setting identical `FinalOrderOfNextRound` values via `TuneOrderInformation`, causing multiple miners to be assigned the same `Order` in the next round, breaking the consensus mining schedule and potentially excluding or disadvantaging the honest miner.

### Finding Description

**Root Cause - Incorrect Distinct Check:**

The validation performs `.Distinct()` on `MinerInRound` objects rather than on the `FinalOrderOfNextRound` values themselves: [1](#0-0) 

This only verifies that the count of distinct miner objects with `FinalOrderOfNextRound > 0` equals the count of miners who mined. Since each miner is a separate object in the dictionary, this check does NOT detect when multiple miners have the **same** `FinalOrderOfNextRound` value.

**Attack Vector - TuneOrderInformation Manipulation:**

During the `UpdateValue` phase, any miner can arbitrarily modify any other miner's `FinalOrderOfNextRound` via the `TuneOrderInformation` dictionary: [2](#0-1) 

The `TuneOrderInformation` is populated from miners whose `FinalOrderOfNextRound` differs from `SupposedOrderOfNextRound`: [3](#0-2) 

However, there is no validation that the values in `TuneOrderInformation` are unique or within valid bounds. The last miner to update in a round can overwrite all previous tuning.

**Exploitation Path:**

When generating the next round, miners are ordered by their `FinalOrderOfNextRound` and assigned corresponding `Order` values: [4](#0-3) 

If N-1 colluding miners all have `FinalOrderOfNextRound = 1`, they will all be assigned `Order = 1` in the next round. The honest miner with `FinalOrderOfNextRound = 2` gets `Order = 2`, but the consensus schedule is broken because multiple miners claim the same time slot.

**Why Validation Fails:**

Additionally, the validation checks `providedRound` (the next round being proposed) rather than `baseRound` (the current round). The next round has all `FinalOrderOfNextRound` and `OutValue` initialized to 0/null: [5](#0-4) 

This means the validation trivially passes with `0 == 0`, regardless of the actual duplicate values in the current round.

### Impact Explanation

**Consensus Schedule Integrity Violation:**

Multiple miners assigned the same `Order` in a round fundamentally breaks the deterministic mining schedule that AEDPoS consensus relies upon. The system cannot determine which miner should produce a block at a given time slot when multiple miners claim the same order.

**Honest Miner Exclusion:**

By manipulating orders, colluding miners can:
- Force all colluding miners into early positions (Order 1-N+1), relegating the honest miner to a later position
- Create undefined behavior where multiple miners attempt to mine simultaneously
- Potentially exclude the honest miner from block rewards if the round terminates before their turn

**Chain Halting Risk:**

The undefined behavior from duplicate orders could cause:
- Block validation failures
- Consensus deadlock where no valid next block can be produced  
- Chain reorganization if different nodes interpret the schedule differently

**Severity: Critical** - This violates the core invariant that "miner schedule integrity" must be maintained. N-1 of N miners (a realistic adversarial threshold for Byzantine fault tolerance) can completely break the consensus mechanism.

### Likelihood Explanation

**Attacker Capabilities Required:**
- N-1 colluding miners (realistic Byzantine fault assumption)
- Ability to coordinate their `UpdateValue` transactions
- No special privileges beyond being active miners

**Attack Complexity:**
- Low - Simply coordinate to include malicious `TuneOrderInformation` in their UpdateValue calls
- The last colluding miner to mine can ensure their tuning is final

**Execution Practicality:**
- The attack uses standard consensus contract methods (`UpdateValue`, `NextRound`)
- No exploitation of VM bugs or undefined behavior required
- All steps execute within normal AElf contract semantics

**Economic Rationality:**
- Attack cost: negligible (just transaction fees)
- Potential gain: block rewards redistribution, censorship capability, chain disruption
- Detection: difficult until the next round begins and schedule is broken

**Probability: High** - The vulnerability is easily exploitable by any N-1 mining coalition without requiring sophisticated techniques or special access.

### Recommendation

**Immediate Fix - Validate Unique FinalOrderOfNextRound Values:**

Replace the validation logic to check that `FinalOrderOfNextRound` values themselves are distinct, not just the miner objects:

```csharp
var minersWithOrder = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0).ToList();
var distinctOrderCount = minersWithOrder
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
var minedCount = providedRound.RealTimeMinersInformation.Values
    .Count(m => m.OutValue != null);

if (distinctOrderCount != minedCount || minersWithOrder.Count != minedCount)
{
    validationResult.Message = "Invalid or duplicate FinalOrderOfNextRound values.";
    return validationResult;
}
```

**Check Correct Round:**

The validation should check `baseRound` (current round) instead of `providedRound` (next round) since `FinalOrderOfNextRound` is set during the current round.

**Validate TuneOrderInformation Bounds:**

Add validation in `ProcessUpdateValue` to ensure:
- `FinalOrderOfNextRound` values are within valid range [1, minersCount]
- No duplicate values are introduced
- Only miners who actually mined can have their orders tuned

**Test Cases:**

1. Test that miners cannot set duplicate `FinalOrderOfNextRound` values
2. Test that `TuneOrderInformation` with out-of-range values is rejected
3. Test that NextRound validation fails when duplicate orders exist
4. Test legitimate order conflict resolution still works correctly

### Proof of Concept

**Initial State:**
- Round N with 5 miners (A, B, C, D, E)
- Miners A, B, C, D are colluding; Miner E is honest
- All 5 miners produce blocks during Round N

**Attack Sequence:**

1. **Miners A, B, C produce blocks** with `UpdateValue` calls, each setting:
   - Their own `SupposedOrderOfNextRound` calculated from signature
   - Their own `FinalOrderOfNextRound` initially set to `SupposedOrderOfNextRound`

2. **Honest miner E produces block** with normal `UpdateValue`, gets `FinalOrderOfNextRound = 3`

3. **Miner D produces block last** with malicious `TuneOrderInformation`:
   ```
   TuneOrderInformation = {
     "MinerA": 1,
     "MinerB": 1,
     "MinerC": 1,
     "MinerD": 1,
     "MinerE": 2
   }
   ```

4. **Current Round N state after all updates:**
   - Miners A, B, C, D: `FinalOrderOfNextRound = 1` (duplicate!)
   - Miner E: `FinalOrderOfNextRound = 2`
   - All miners: `OutValue != null` (all mined)

5. **Miner D calls NextRound:**
   - Validation in `NextRoundMiningOrderValidationProvider` checks `providedRound` (Round N+1)
   - Round N+1 has all `FinalOrderOfNextRound = 0`, all `OutValue = null`
   - Check: `0 == 0` → Validation passes ✓

6. **GenerateNextRoundInformation executes:**
   - Orders miners by their Round N `FinalOrderOfNextRound`
   - Assigns Round N+1 orders:
     - Miners A, B, C, D: `Order = 1` (all the same!)
     - Miner E: `Order = 2`

**Expected vs Actual Result:**

**Expected:** Each miner should have a unique `Order` in Round N+1 (values 1, 2, 3, 4, 5)

**Actual:** Four miners have `Order = 1`, one miner has `Order = 2` - consensus schedule is broken

**Success Condition:** 
Query Round N+1 information and observe that miners A, B, C, and D all have `Order = 1`, violating the uniqueness invariant required for deterministic mining schedule.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
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
