### Title
Insufficient Validation Allows Duplicate Mining Orders in Consensus Round Transitions

### Summary
The `NextRoundMiningOrderValidationProvider` uses `Distinct()` on `MinerInRound` objects to validate uniqueness, but since protobuf-generated classes use field-by-field equality, this checks if entire miner objects are duplicates rather than checking if `FinalOrderOfNextRound` values are unique. This allows malicious miners to propose consensus rounds with duplicate mining orders, violating consensus schedule integrity.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**

The validation calls `Distinct()` on `MinerInRound` objects without a custom comparer. Since `MinerInRound` is a protobuf-generated message type [2](#0-1) , it uses Google.Protobuf's default equality implementation which compares all fields (order, is_extra_block_producer, in_value, out_value, signature, expected_mining_time, produced_blocks, missed_time_slots, pubkey, previous_in_value, supposed_order_of_next_round, final_order_of_next_round, actual_mining_times, encrypted_pieces, decrypted_pieces, produced_tiny_blocks, implied_irreversible_block_height).

**Why Protections Fail:**

The current validation logic:
1. Filters miners where `FinalOrderOfNextRound > 0`
2. Calls `Distinct()` which uses value equality across ALL fields
3. Since each miner in `RealTimeMinersInformation` dictionary [3](#0-2)  has a unique `pubkey` key, two miners with duplicate `FinalOrderOfNextRound` values but different pubkeys will have different overall object equality
4. `Distinct()` will NOT filter them out, allowing both to be counted
5. The validation passes even though there are duplicate mining orders

**Execution Path:**

This validator is invoked during NextRound behavior validation [4](#0-3)  before block execution. While normal block production includes conflict resolution [5](#0-4) , a malicious miner proposing a NextRound can craft a round structure with pre-set duplicate `FinalOrderOfNextRound` values that bypass this validation.

### Impact Explanation

**Consensus Integrity Violation:**
- Duplicate `FinalOrderOfNextRound` values create ambiguity in the next round's mining schedule
- Multiple miners assigned the same mining order could attempt to mine simultaneously
- This violates the fundamental AEDPoS assumption that each miner has a unique, deterministic time slot
- Could lead to consensus forks, block production conflicts, or denial of service

**Affected Parties:**
- All network participants suffer from consensus instability
- Honest miners may lose block rewards due to scheduling conflicts
- Network reliability and finality guarantees are compromised

**Severity Justification:**
Critical - This directly undermines consensus schedule integrity, a core invariant of the AEDPoS mechanism. The validation is specifically designed to prevent this scenario but fails to do so due to incorrect equality semantics.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a miner eligible to propose NextRound (typically the extra block producer)
- Can craft malicious `NextRoundInput` with duplicate `FinalOrderOfNextRound` assignments

**Attack Complexity:**
- Low - Simply requires constructing a Round message with duplicate orders
- No complex cryptographic operations or timing requirements needed
- The flawed validation will accept the malicious round

**Feasibility Conditions:**
- Attacker needs to be selected as the miner responsible for NextRound transition
- This occurs regularly in normal consensus operation (every round transition)

**Detection Constraints:**
- The validation specifically checks for this condition but fails
- No subsequent validation catches duplicate orders
- The malicious round would be accepted into chain state

**Probability:**
Medium-High - While attacker must be a miner, miners rotate regularly and the exploit is straightforward once in position.

### Recommendation

**Code-Level Mitigation:**

Replace the validation logic to check distinct `FinalOrderOfNextRound` values rather than distinct `MinerInRound` objects:

```csharp
var minersWithOrder = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0).ToList();
var distinctOrdersCount = minersWithOrder
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();

if (distinctOrdersCount != minersWithOrder.Count ||
    distinctOrdersCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound: duplicate orders detected.";
    return validationResult;
}
```

**Invariant Checks:**
- Verify all `FinalOrderOfNextRound` values are unique among miners with orders > 0
- Verify the count of distinct orders equals the count of miners who produced blocks
- Verify orders form a contiguous sequence (1, 2, 3, ..., n) without gaps

**Test Cases:**
1. Test NextRound input with two miners having identical `FinalOrderOfNextRound` values - should fail validation
2. Test NextRound input with gaps in order sequence (e.g., 1, 2, 4, 5) - should fail validation  
3. Test valid NextRound input with unique sequential orders - should pass validation
4. Test edge case with all miners having `FinalOrderOfNextRound = 0` - should handle correctly

### Proof of Concept

**Initial State:**
- Current round has 5 miners (A, B, C, D, E) who all produced blocks (OutValue != null)
- Miner A is extra block producer eligible to propose NextRound

**Attack Steps:**
1. Miner A constructs malicious `NextRoundInput`:
   - Miner A: FinalOrderOfNextRound = 1
   - Miner B: FinalOrderOfNextRound = 2
   - Miner C: FinalOrderOfNextRound = 2 (duplicate!)
   - Miner D: FinalOrderOfNextRound = 3
   - Miner E: FinalOrderOfNextRound = 4

2. Submit NextRound transaction with this round data

3. ValidateBeforeExecution processes via `NextRoundMiningOrderValidationProvider`:
   - Filters miners: all 5 have FinalOrderOfNextRound > 0
   - Calls `Distinct()`: Since miners B and C have different pubkeys (and other fields), both are kept
   - distinctCount = 5 (not 4!)
   - Compares: 5 == 5 (miners with OutValue)
   - Validation passes ✓

**Expected Result:**
Validation should fail with "Invalid FinalOrderOfNextRound: duplicate orders detected"

**Actual Result:**
Validation passes, malicious round is accepted into consensus state, creating ambiguous mining schedule with miners B and C both assigned order 2 for next round.

**Success Condition:**
After the malicious NextRound is accepted, querying the current round shows two different miners with `FinalOrderOfNextRound = 2`, confirming the consensus schedule corruption.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L246-247)
```text
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-86)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-40)
```csharp
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
```
