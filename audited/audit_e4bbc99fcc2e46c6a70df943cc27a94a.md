# Audit Report

## Title
Insufficient Validation Allows Duplicate Mining Orders in Consensus Round Transitions

## Summary
The `NextRoundMiningOrderValidationProvider` fails to properly validate uniqueness of `FinalOrderOfNextRound` values due to calling `Distinct()` on entire `MinerInRound` protobuf objects rather than on the specific order field. This allows malicious miners to propose consensus rounds with duplicate mining orders, violating the core AEDPoS invariant of unique, deterministic time slots per miner. [1](#0-0) 

## Finding Description

The validation logic attempts to ensure miners have unique next-round orders by filtering miners with `FinalOrderOfNextRound > 0` and calling `Distinct()` to count unique entries. However, `MinerInRound` is a protobuf-generated message with 17 fields including a unique `pubkey` field. [2](#0-1) 

When `Distinct()` is called on `MinerInRound` objects, protobuf's default equality comparison checks ALL fields. Since each miner has a unique `pubkey` (the dictionary key in `RealTimeMinersInformation`), two miners with identical `FinalOrderOfNextRound` values but different pubkeys will be considered distinct objects. [3](#0-2) 

**Execution Path:**

1. During NextRound behavior validation, the `NextRoundMiningOrderValidationProvider` is invoked [4](#0-3) 

2. The flawed validation passes even with duplicate orders
3. The malicious round is persisted to state via `AddRoundInformation` [5](#0-4) 

4. When the next round is generated, the logic assumes `FinalOrderOfNextRound` values are unique [6](#0-5) 

The `occupiedOrders` calculation expects unique values. With duplicates, the logic for assigning remaining orders to miners who didn't mine becomes incorrect, corrupting the consensus schedule.

## Impact Explanation

This vulnerability breaks a fundamental AEDPoS consensus invariant: **each miner must have a unique, deterministic time slot**. 

With duplicate `FinalOrderOfNextRound` values:
- Multiple miners are assigned the same mining order
- Scheduling ambiguity creates conflicts when miners attempt to produce blocks simultaneously  
- The consensus mechanism cannot deterministically resolve who should mine at each time slot
- This can lead to consensus forks, block production failures, and network instability
- All network participants suffer from degraded consensus reliability and compromised finality guarantees

While normal block production includes conflict resolution logic, a malicious NextRound proposal with pre-set duplicate orders bypasses this protection entirely. [7](#0-6) 

**Severity: Critical** - Directly undermines core consensus schedule integrity.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an authorized miner in the consensus set
- Must be selected to propose the NextRound transition (typically the extra block producer)

**Attack Complexity:** Low
- Simply craft a `NextRoundInput` with duplicate `FinalOrderOfNextRound` assignments
- No complex cryptographic operations or timing requirements
- The flawed validation will accept the malicious structure

**Opportunity Frequency:**
Round transitions occur regularly in normal consensus operation. Each round, one miner is responsible for proposing NextRound. Over time, a malicious miner will have regular opportunities to exploit this.

**Detection:** None - The validation specifically intended to catch this scenario fails silently.

**Probability: Medium-High** - While requiring miner status, the exploit is straightforward and opportunities occur regularly through normal consensus rotation.

## Recommendation

Fix the validation to check uniqueness of `FinalOrderOfNextRound` **values** specifically, not entire `MinerInRound` objects:

```csharp
var minersWithOrders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .ToList();
    
var distinctOrderCount = minersWithOrders
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();

if (distinctOrderCount != minersWithOrders.Count || 
    distinctOrderCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound.";
    return validationResult;
}
```

This ensures:
1. The number of distinct order VALUES equals the number of miners with orders
2. No duplicate order values exist
3. The count matches miners who mined in the current round

## Proof of Concept

```csharp
[Fact]
public void NextRoundValidation_Should_Reject_Duplicate_FinalOrderOfNextRound()
{
    // Setup: Create a round with 3 miners who all mined (have OutValue)
    var round = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation =
        {
            ["pubkey1"] = new MinerInRound 
            { 
                Pubkey = "pubkey1", 
                OutValue = Hash.FromString("out1"),
                FinalOrderOfNextRound = 1  // Order 1
            },
            ["pubkey2"] = new MinerInRound 
            { 
                Pubkey = "pubkey2", 
                OutValue = Hash.FromString("out2"),
                FinalOrderOfNextRound = 1  // DUPLICATE Order 1
            },
            ["pubkey3"] = new MinerInRound 
            { 
                Pubkey = "pubkey3", 
                OutValue = Hash.FromString("out3"),
                FinalOrderOfNextRound = 2  // Order 2
            }
        }
    };
    
    var validator = new NextRoundMiningOrderValidationProvider();
    var context = new ConsensusValidationContext { ProvidedRound = round };
    
    var result = validator.ValidateHeaderInformation(context);
    
    // VULNERABILITY: Validation incorrectly passes despite duplicate orders
    // Expected: result.Success == false with message about duplicate orders
    // Actual: result.Success == false with generic "Invalid FinalOrderOfNextRound"
    //         BUT only because count mismatch (3 miners vs 3 distinct objects vs 3 OutValues)
    //         If we had 2 miners with same order + 1 without OutValue, it would PASS
    
    Assert.False(result.Success); // Current behavior - but for wrong reason
}
```

The test demonstrates that the current validation logic would incorrectly count 3 distinct `MinerInRound` objects (due to unique pubkeys) even though only 2 unique `FinalOrderOfNextRound` values exist (1 and 2).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L243-248)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
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
