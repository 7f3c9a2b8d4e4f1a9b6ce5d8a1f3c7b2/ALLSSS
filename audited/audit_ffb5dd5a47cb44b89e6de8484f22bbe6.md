### Title
Missing Validation of FinalOrderOfNextRound Allows Consensus Round Corruption via Malicious TuneOrderInformation

### Summary
The consensus contract lacks proper validation of `FinalOrderOfNextRound` values set through `TuneOrderInformation` in `UpdateValue` transactions. A malicious miner can inject duplicate or out-of-range order values that corrupt the next round's miner schedule, causing missing time slots, failed order lookups, and consensus disruption. The existing `NextRoundMiningOrderValidationProvider` is only applied to `NextRound` behavior, not `UpdateValue`, and even its validation logic is flawed.

### Finding Description

**Root Cause:**

The vulnerability exists in three interconnected flaws:

1. **Validation Provider Not Applied to UpdateValue**: The `NextRoundMiningOrderValidationProvider` is only added for `NextRound` behavior, not for `UpdateValue` behavior where `TuneOrderInformation` is actually applied. [1](#0-0) 

2. **Flawed Validation Logic**: The validation in `NextRoundMiningOrderValidationProvider` checks distinct *miners*, not distinct *order values*. It calls `.Distinct()` on the miner collection, not on the `FinalOrderOfNextRound` values themselves. [2](#0-1) 

3. **Unvalidated TuneOrderInformation Application**: In `ProcessUpdateValue`, the `TuneOrderInformation` map is blindly applied without any validation of the order values (range checks, uniqueness checks, or contiguity checks). [3](#0-2) 

**Attack Path:**

A malicious miner submits an `UpdateValue` transaction with crafted `TuneOrderInformation`: [4](#0-3) 

The attacker sets invalid values such as duplicate orders (e.g., multiple miners with order 1) or out-of-range orders (e.g., order 1000 when only 5 miners exist). These values are directly applied to miners' `FinalOrderOfNextRound` fields without validation.

**Why Protections Fail:**

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` - it does not check `TuneOrderInformation` at all: [5](#0-4) 

**Impact on Next Round Generation:**

When `GenerateNextRoundInformation` is called, it uses these corrupted `FinalOrderOfNextRound` values to assign orders in the next round. The `occupiedOrders` list will contain duplicates and out-of-range values, leading to incorrect `ableOrders` calculation and missing time slots. [6](#0-5) 

### Impact Explanation

**Consensus Integrity Compromise:**

1. **Duplicate Orders**: Multiple miners assigned the same order value leads to time slot conflicts. Functions like `FirstMiner()` will arbitrarily return one miner, breaking determinism. [7](#0-6) 

2. **Missing Time Slots**: Valid orders (e.g., 2, 3, 4) have no assigned miner, causing missed blocks and reduced chain throughput.

3. **GetMiningInterval Failure**: This function expects exactly miners with orders 1 and 2. With duplicates or missing orders, the interval calculation becomes incorrect or may crash with index out of bounds. [8](#0-7) 

4. **BreakContinuousMining Logic Breaks**: Functions that search for specific order values will fail or behave incorrectly with duplicate/missing orders. [9](#0-8) 

**Severity**: HIGH - A single malicious miner can disrupt consensus for an entire round, affecting all miners and potentially halting block production.

### Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an active miner in the current round
- Attacker must be able to produce a block (have their time slot)

**Attack Complexity**: LOW
- No special privileges needed beyond being a miner
- Attack is a single transaction with manipulated `TuneOrderInformation`
- No complex state setup or timing requirements

**Feasibility**: HIGH
- Entry point is the public `UpdateValue` method: [10](#0-9) 
- Miners regularly call `UpdateValue` during normal operation
- The input structure is well-defined and easily craftable
- No additional checks prevent this attack

**Detection Difficulty**: MEDIUM
- The corrupted round will be visible in the next round's structure
- However, by the time it's detected, the damage is done
- The attack is subtle enough that it might be mistaken for a bug

**Economic Rationality**: HIGH
- Low cost (just transaction fees)
- High impact (disrupts entire consensus round)
- Could be used for griefing, DoS, or to create chaos for competitive advantage

### Recommendation

**Immediate Fix - Add Comprehensive Validation:**

1. Apply `NextRoundMiningOrderValidationProvider` to `UpdateValue` behavior in the validation pipeline: [1](#0-0) 

2. Fix the validation logic to check distinct *order values* instead of distinct *miners*: [2](#0-1) 

   Replace:
   ```csharp
   var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
       .Distinct().Count();
   ```
   
   With:
   ```csharp
   var distinctOrderValues = providedRound.RealTimeMinersInformation.Values
       .Where(m => m.FinalOrderOfNextRound > 0)
       .Select(m => m.FinalOrderOfNextRound)
       .Distinct()
       .ToList();
   var distinctCount = distinctOrderValues.Count;
   ```

3. Add explicit validation checks:
   - All `FinalOrderOfNextRound` values must be in range [1, minersCount]
   - All `FinalOrderOfNextRound` values must be unique
   - The set of values should form a contiguous sequence or be a valid subset

4. Add validation in `ProcessUpdateValue` before applying `TuneOrderInformation`: [3](#0-2) 

**Additional Safeguards:**

- Add range validation: `Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount)`
- Add uniqueness checks before application
- Consider limiting which miners can tune which orders (e.g., only tune your own order)

**Test Cases:**

1. Test UpdateValue with duplicate FinalOrderOfNextRound values - should fail
2. Test UpdateValue with out-of-range orders - should fail
3. Test UpdateValue with non-contiguous sequence - should fail
4. Test NextRound generation with corrupted orders - should have defensive checks

### Proof of Concept

**Initial State:**
- 5 active miners in current round: Alice, Bob, Charlie, Dave, Eve
- All miners successfully mined blocks in current round
- Current round number: N

**Attack Steps:**

1. Alice constructs malicious `UpdateValueInput` with:
   - Valid `OutValue`, `Signature`, `PreviousInValue` (passes UpdateValueValidationProvider)
   - Malicious `TuneOrderInformation`:
     - Bob: FinalOrderOfNextRound = 1
     - Charlie: FinalOrderOfNextRound = 1 (duplicate!)
     - Dave: FinalOrderOfNextRound = 1000 (out of range!)
     - Eve: FinalOrderOfNextRound = 2 (valid)

2. Alice submits transaction calling `UpdateValue(maliciousInput)`

3. Validation passes because:
   - `UpdateValueValidationProvider` doesn't check `TuneOrderInformation`
   - `NextRoundMiningOrderValidationProvider` is not applied to UpdateValue behavior

4. `ProcessUpdateValue` applies the malicious orders: [3](#0-2) 

**Expected Result:**
- Transaction should be rejected
- Round orders remain valid and contiguous

**Actual Result:**
- Transaction succeeds
- Current round now has corrupted FinalOrderOfNextRound values
- When NextRound is triggered:
  - Bob and Charlie both have Order = 1 in next round
  - Dave has Order = 1000 in next round
  - Orders 3, 4, 5 are missing (no miners assigned)
  - `FirstMiner()` returns either Bob or Charlie non-deterministically
  - `GetMiningInterval()` may fail or calculate wrong interval
  - Time slots 3, 4, 5 produce no blocks

**Success Condition:**
The attack succeeds if the malicious `TuneOrderInformation` is applied without validation, resulting in a next round with duplicate orders, out-of-range orders, or missing order slots.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-56)
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

        // Set miners' information of miners missed their time slot in current round.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L73-108)
```csharp
    private void BreakContinuousMining(ref Round nextRound)
    {
        var minersCount = RealTimeMinersInformation.Count;
        if (minersCount <= 1) return;

        // First miner of next round != Extra block producer of current round
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }

        // Last miner of next round != Extra block producer of next round
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L142-148)
```csharp
    public MinerInRound FirstMiner()
    {
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1)
            // Unlikely.
            : new MinerInRound();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
```
