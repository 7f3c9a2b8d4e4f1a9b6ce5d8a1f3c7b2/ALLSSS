### Title
Consensus Integrity Violation: Duplicate Mining Order Detection Bypass via Incorrect Distinct() Usage

### Summary
The `NextRoundMiningOrderValidationProvider` uses `Distinct()` on entire `MinerInRound` objects instead of checking for duplicate `FinalOrderOfNextRound` values specifically. Since `MinerInRound` is a protobuf-generated class comparing all 17 fields, two different miners with the same `FinalOrderOfNextRound` value are not deduplicated. This allows malicious miners to inject duplicate mining orders via unchecked `TuneOrderInformation`, causing multiple miners to claim the same time slot in the next round and breaking consensus integrity.

### Finding Description

**Root Cause:**

The validation logic in `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` incorrectly uses `Distinct()` on the entire `MinerInRound` object collection: [1](#0-0) 

Since `MinerInRound` is a protobuf-generated message with 17 fields (including `pubkey`, `in_value`, `out_value`, `signature`, etc.): [2](#0-1) 

The protobuf-generated `Equals()` method compares ALL fields, not just `FinalOrderOfNextRound`. Therefore, two miners with different pubkeys but the same `FinalOrderOfNextRound` are considered distinct objects and won't be deduplicated by `Distinct()`.

**Attack Vector:**

During `UpdateValue` processing, miners can inject arbitrary `TuneOrderInformation` values that directly modify `FinalOrderOfNextRound` for any miner: [3](#0-2) 

The `UpdateValueValidationProvider` does not validate `TuneOrderInformation` entries: [4](#0-3) 

**Why Protections Fail:**

When the extra block producer creates a `NextRound` transaction, the faulty validation passes even with duplicate orders:

- **Scenario**: Miners A, B, C all mined. Attacker sets B and C to both have `FinalOrderOfNextRound = 1`.
- **Left side**: `Where(m => m.FinalOrderOfNextRound > 0).Distinct().Count()` returns 3 (A, B, C are all distinct objects).
- **Right side**: `Count(m => m.OutValue != null)` returns 3.
- **Result**: 3 == 3, validation passes despite duplicate order value 1.

**Downstream Impact:**

When `GenerateNextRoundInformation()` processes the validated round with duplicate orders: [5](#0-4) 

Multiple miners are assigned the same `Order` in the next round dictionary. The `occupiedOrders` calculation becomes corrupted: [6](#0-5) 

When looking up miners by order, `FirstOrDefault` returns ambiguous results: [7](#0-6) 

### Impact Explanation

**Consensus Integrity Violation (CRITICAL):**

1. **Multiple Miners, Same Time Slot**: Two or more miners believe they have the same mining order in the next round, leading to conflicting block production attempts or confusion about who should mine.

2. **Chain Halt Risk**: If miners with duplicate orders both attempt to produce blocks, validation conflicts arise. If both hesitate, time slots are missed, potentially stalling the chain.

3. **Fork Risk**: Different nodes may accept different blocks from miners claiming the same order, causing chain forks.

4. **Incorrect Order Assignment**: The `occupiedOrders` list contains duplicates, causing the `ableOrders` calculation to incorrectly assign orders to miners who didn't mine, potentially overwriting existing assignments.

5. **Extra Block Producer Ambiguity**: When `FirstOrDefault` finds a miner by order, it returns an arbitrary miner if duplicates exist, breaking the deterministic extra block producer selection.

**Severity Justification:**
This violates the fundamental AEDPoS invariant that each miner has a unique, deterministic time slot. The consensus mechanism's correctness depends on this ordering being unambiguous. A successful attack causes immediate consensus failure affecting all network participants.

### Likelihood Explanation

**HIGH Likelihood:**

1. **Reachable Entry Point**: Any miner during their scheduled time slot can call the public `UpdateValue` method with arbitrary `UpdateValueInput`: [8](#0-7) 

2. **No Validation Barrier**: The `TuneOrderInformation` field in `UpdateValueInput` is processed without any validation checks on the order values or duplicate detection: [9](#0-8) 

3. **Minimal Attacker Capabilities**: The attacker only needs to be a miner in the current round (elected through normal mechanisms). They can inject malicious `TuneOrderInformation` during their legitimate mining time slot.

4. **Guaranteed Detection Bypass**: The faulty `Distinct()` logic mathematically guarantees that duplicate `FinalOrderOfNextRound` values won't be detected when miners have different pubkeys or other field values.

5. **No Cost to Exploit**: The attack requires no additional resources beyond normal block production. The attacker suffers no penalty if detected.

6. **Detection Difficulty**: The malicious `TuneOrderInformation` is embedded in normal UpdateValue transactions and may appear legitimate unless all order values are manually inspected.

### Recommendation

**Immediate Fix:**

Replace the faulty `Distinct()` call with duplicate detection on the `FinalOrderOfNextRound` value specifically:

```csharp
// Current (VULNERABLE):
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Distinct().Count();

// Fixed Option 1 - Using Select + Distinct:
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();

// Fixed Option 2 - Using DistinctBy (C# 6.0+):
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .DistinctBy(m => m.FinalOrderOfNextRound)
    .Count();
```

**Additional Hardening:**

1. **Validate TuneOrderInformation**: Add validation in `UpdateValueValidationProvider` to ensure:
   - Order values are within valid range [1, minersCount]
   - No duplicate order values are being assigned
   - Changes are only made to miners who haven't finalized their orders

2. **Explicit Duplicate Check**: Add an additional validation in `NextRoundMiningOrderValidationProvider`:
```csharp
var orders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
if (orders.Count != orders.Distinct().Count())
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

3. **Test Coverage**: Add test cases covering:
   - Multiple miners with same `FinalOrderOfNextRound`
   - Malicious `TuneOrderInformation` injection
   - Edge cases with all miners having same order

### Proof of Concept

**Initial State:**
- Round with 3 miners: Alice, Bob, Charlie (all elected, legitimate miners)
- Current round in progress, all miners have produced blocks

**Attack Sequence:**

1. **Alice's Turn**: During Alice's scheduled time slot, she produces a block with malicious `UpdateValueInput`:
   ```
   UpdateValueInput {
     OutValue: <Alice's valid OutValue>,
     Signature: <Alice's valid Signature>,
     TuneOrderInformation: {
       "Bob_Pubkey": 1,      // Set Bob to order 1
       "Charlie_Pubkey": 1,  // Set Charlie to SAME order 1
       "Alice_Pubkey": 2     // Set Alice to order 2
     },
     // ... other valid fields
   }
   ```

2. **Processing**: The contract processes Alice's UpdateValue:
   - No validation rejects the malicious `TuneOrderInformation`
   - Bob's `FinalOrderOfNextRound` set to 1
   - Charlie's `FinalOrderOfNextRound` set to 1 (DUPLICATE)
   - Alice's `FinalOrderOfNextRound` set to 2

3. **NextRound Creation**: Extra block producer creates NextRound transaction with current round state containing duplicates.

4. **Faulty Validation**:
   - **Filter**: All 3 miners have `FinalOrderOfNextRound > 0`
   - **Distinct()**: Returns 3 (Alice, Bob, Charlie are different objects despite duplicate orders)
   - **Count comparison**: 3 == 3 (all mined)
   - **Result**: Validation PASSES ✓ (INCORRECT)

5. **Next Round Generation**:
   - Both Bob and Charlie assigned `Order = 1` in next round
   - When looking up "miner with order 1", `FirstOrDefault` returns arbitrary choice
   - Consensus breaks: either both try to mine simultaneously or both wait for the other

**Expected vs Actual:**
- **Expected**: Validation should FAIL with "Duplicate FinalOrderOfNextRound values detected"
- **Actual**: Validation PASSES, allowing consensus corruption

**Success Condition:**
The attack succeeds when the NextRound validation passes despite duplicate `FinalOrderOfNextRound` values, resulting in multiple miners assigned the same mining order in the next round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L60-61)
```csharp
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
