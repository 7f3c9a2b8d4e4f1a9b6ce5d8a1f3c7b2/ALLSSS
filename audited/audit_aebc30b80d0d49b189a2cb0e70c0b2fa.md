### Title
Duplicate Mining Order Validation Bypass in NextRound Consensus Validation

### Summary
The `NextRoundMiningOrderValidationProvider` validation uses `Distinct().Count()` on entire `MinerInRound` objects instead of their `FinalOrderOfNextRound` values, allowing duplicate mining orders to pass validation. This enables malicious miners to create invalid rounds where multiple miners are assigned the same mining position, breaking consensus integrity and causing time slot conflicts in block production.

### Finding Description

The validation logic in `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` contains a critical flaw: [1](#0-0) 

The `Distinct()` method compares entire `MinerInRound` protobuf objects, which implement equality based on ALL 17 fields including the unique `pubkey` field: [2](#0-1) 

This means two different miners with the SAME `FinalOrderOfNextRound` value (e.g., both have order 3) but different pubkeys will always be counted as distinct, completely bypassing the duplicate order detection.

**Attack Path:**

1. During `UpdateValue` phase, miners can manipulate `FinalOrderOfNextRound` via `TuneOrderInformation`: [3](#0-2) 

2. The `UpdateValueValidationProvider` does NOT validate for duplicate orders in tune information: [4](#0-3) 

3. When `NextRound` is triggered, `GenerateNextRoundInformation` sorts miners by their `FinalOrderOfNextRound` and assigns duplicates the same `Order`: [5](#0-4) 

4. The flawed validation fails to detect the duplicate orders, and the invalid round is accepted: [6](#0-5) 

### Impact Explanation

**Consensus Integrity Violation:**
- Multiple miners receive identical `Order` values in the next round, assigned directly from duplicate `FinalOrderOfNextRound` values
- Both miners have the same `ExpectedMiningTime` (calculated as `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`)
- Two miners attempt to produce blocks at the same time slot, causing consensus confusion

**Block Production Disruption:**
- When calculating available orders for miners who didn't mine, the system uses `occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound)`: [7](#0-6) 

- Duplicate orders cause one legitimate time slot to remain unassigned
- Results in missed blocks and reduced network throughput

**Affected Parties:**
- All network participants suffer from consensus instability
- Miners lose block production opportunities
- Network security degraded with unpredictable block production

### Likelihood Explanation

**Reachable Entry Point:** The vulnerability is triggered through standard consensus transactions:
1. Malicious miner sends `UpdateValue` transaction with crafted `TuneOrderInformation` setting duplicate `FinalOrderOfNextRound` values
2. Later, when `NextRound` is executed, the flawed validation accepts the invalid round

**Feasible Preconditions:**
- Attacker must be an active miner in the current round (standard consensus participation)
- No special privileges required beyond being in the miner list
- Attack can be executed during any round transition

**Execution Practicality:**
- The `TuneOrderInformation` field accepts arbitrary order values without validation
- The protobuf structure allows easy manipulation in a modified client
- The validation runs in `ValidateBeforeExecution`, so invalid data reaches the validation logic: [8](#0-7) 

**Detection/Operational Constraints:**
- The attack is subtle—duplicate orders may not be immediately obvious
- Network would experience timing conflicts and missed blocks before detection
- No existing monitoring specifically checks for duplicate `FinalOrderOfNextRound` values

### Recommendation

**Immediate Fix:** Modify the validation to check for duplicate `FinalOrderOfNextRound` VALUES, not duplicate miner objects:

```csharp
var minersWithOrders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0).ToList();
var orders = minersWithOrders.Select(m => m.FinalOrderOfNextRound).ToList();
var distinctOrderCount = orders.Distinct().Count();

if (distinctOrderCount != orders.Count)
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}

if (minersWithOrders.Count != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound count.";
    return validationResult;
}
```

**Additional Validation:** Add duplicate order checking in `UpdateValueValidationProvider` to prevent malicious `TuneOrderInformation`:

```csharp
// After applying tune orders, check for duplicates
var allOrders = validationContext.ProvidedRound.RealTimeMinersInformation.Values
    .Select(m => m.FinalOrderOfNextRound)
    .Where(o => o > 0)
    .ToList();
if (allOrders.Distinct().Count() != allOrders.Count)
    return new ValidationResult { Message = "TuneOrderInformation creates duplicate orders." };
```

**Test Cases:**
1. Test with two miners having identical `FinalOrderOfNextRound` values
2. Test `UpdateValue` with `TuneOrderInformation` that creates duplicates
3. Test `NextRound` validation rejects rounds with duplicate orders
4. Test round generation with pre-existing duplicate orders in state

### Proof of Concept

**Initial State:**
- Round N with 5 miners: A, B, C, D, E
- All miners have mined blocks (OutValue != null)
- Miners have unique FinalOrderOfNextRound: 1, 2, 3, 4, 5

**Attack Steps:**

1. Malicious miner B produces `UpdateValue` block with crafted `TuneOrderInformation`:
   - Sets miner C's `FinalOrderOfNextRound = 2` (same as B's)
   - Transaction data: `{ "OutValue": "...", "TuneOrderInformation": { "C": 2 } }`

2. UpdateValue validation passes (no duplicate check in `UpdateValueValidationProvider`)

3. State after UpdateValue execution:
   - Miner B: FinalOrderOfNextRound = 2
   - Miner C: FinalOrderOfNextRound = 2 (DUPLICATE)
   - Others: 1, 4, 5

4. Next miner triggers `NextRound` behavior
   - `GenerateNextRoundInformation` creates round with miners B and C both assigned Order = 2
   - NextRound validation called with this invalid round

5. **Expected Result:** Validation should reject duplicate orders
   **Actual Result:** Validation passes because:
   - `Distinct()` counts B and C as distinct objects (different pubkeys)
   - `distinctCount = 5` (all miners counted as distinct)
   - `Count(m => m.OutValue != null) = 5`
   - Validation succeeds: `5 == 5`

6. Invalid round accepted into state with miners B and C both having Order = 2

7. **Impact:** In next round, miners B and C both attempt to mine at the same time slot, causing consensus confusion and one legitimate time slot (order 3) remains empty.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-301)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```
