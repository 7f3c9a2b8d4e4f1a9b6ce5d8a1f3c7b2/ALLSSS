# Audit Report

## Title
Duplicate FinalOrderOfNextRound Values Bypass Validation Due to Incorrect Distinct() Usage

## Summary
The `NextRoundMiningOrderValidationProvider` incorrectly validates mining order uniqueness by applying `.Distinct()` to `MinerInRound` protobuf message objects instead of their `FinalOrderOfNextRound` values. This allows a malicious miner to submit a NextRound block with duplicate order assignments, causing multiple miners to attempt block production at identical time slots, resulting in consensus failure and blockchain forks.

## Finding Description

The vulnerability exists in the validation logic that ensures all miners have unique mining orders for the next round.

**Root Cause:** [1](#0-0) 

The code applies `.Distinct()` to a collection of `MinerInRound` objects. Since `MinerInRound` is a protobuf message with multiple fields (pubkey, OutValue, Signature, InValue, Order, ExpectedMiningTime, etc.): [2](#0-1) 

Protobuf equality compares ALL fields, not just `FinalOrderOfNextRound`. Therefore, two miners with identical `FinalOrderOfNextRound` values (e.g., both have order 3) but different pubkeys are considered distinct objects, and the validation incorrectly passes.

**Attack Vector:**
A malicious miner producing a NextRound block can craft a `NextRoundInput` with duplicate `FinalOrderOfNextRound` values. When validated: [3](#0-2) 

The flawed validation allows the malicious data through. The corrupted round is then processed and stored in state: [4](#0-3) 

**Consensus Corruption:**
When the next round is generated from this corrupted data, the `GenerateNextRoundInformation` method directly assigns each miner's `Order` from their `FinalOrderOfNextRound`: [5](#0-4) 

Miners with duplicate `FinalOrderOfNextRound` values receive identical `Order` and `ExpectedMiningTime` values, causing them to attempt block production at the exact same time slot, violating the fundamental consensus invariant of one miner per time slot.

## Impact Explanation

**Consensus Integrity Violation:**
Multiple miners receive identical time slots, causing:
- Simultaneous block production attempts by different miners
- Different nodes may accept different valid blocks from different miners
- Blockchain forks as the network diverges on the canonical chain
- Complete consensus mechanism breakdown
- Potential network partition into incompatible states

**Severity Justification - HIGH:**
1. Directly violates the critical "unique mining time slot" consensus invariant
2. Causes immediate, network-wide consensus failure
3. Affects all participants - validators cannot reach agreement
4. No built-in recovery mechanism once corrupted round data is in immutable state
5. Disrupts chain finality, affecting all dependent applications and cross-chain operations

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner in the current consensus round
- Must have the opportunity to produce a NextRound block (when terminating a round)
- Can construct arbitrary `NextRoundInput` data for their block

**Attack Complexity - LOW:**
The attacker only needs to:
1. Wait for their turn to produce a NextRound block
2. Generate normal consensus extra data for NextRound behavior
3. Manually modify the `RealTimeMinersInformation` dictionary to assign duplicate `FinalOrderOfNextRound` values to multiple miners
4. Submit the block - the flawed validation guarantees it passes

**Feasibility - HIGH:**
- NextRound blocks are produced regularly (at least once per round, typically every few minutes)
- Any miner in the consensus set can exploit this during their NextRound turn
- No additional privileges required beyond being a current miner
- The exploit is deterministic - the validation flaw guarantees success
- Attack is repeatable and causes immediate observable impact

**Detection Difficulty:**
- The validation returns success for malicious data, providing no warning
- Corruption only manifests when the subsequent round is generated
- By that time, the corrupted round data is already persisted in blockchain state

## Recommendation

Change the validation to check uniqueness of the `FinalOrderOfNextRound` VALUES rather than the `MinerInRound` objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Select the values
    .Distinct()
    .Count();
```

This ensures that duplicate `FinalOrderOfNextRound` values are properly detected regardless of differences in other fields like pubkey, OutValue, or Signature.

## Proof of Concept

```csharp
// Test demonstrating the validation flaw
[Fact]
public void NextRound_WithDuplicateFinalOrderOfNextRound_ShouldFail_ButPasses()
{
    // Setup: Initialize a round with 5 miners
    var currentRound = GenerateRoundWithMiners(5);
    
    // Malicious miner crafts NextRoundInput with duplicate orders
    var maliciousNextRoundInput = new NextRoundInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        RealTimeMinersInformation = 
        {
            // Miner Alice gets order 3
            ["Alice"] = new MinerInRound 
            { 
                Pubkey = "Alice",
                FinalOrderOfNextRound = 3,
                OutValue = HashHelper.ComputeFrom("alice_data")
            },
            // Miner Bob ALSO gets order 3 (duplicate!)
            ["Bob"] = new MinerInRound 
            { 
                Pubkey = "Bob", 
                FinalOrderOfNextRound = 3,  // Same as Alice!
                OutValue = HashHelper.ComputeFrom("bob_data")
            },
            // Other miners with valid unique orders
            ["Charlie"] = new MinerInRound { Pubkey = "Charlie", FinalOrderOfNextRound = 1, OutValue = Hash.FromString("c") },
            ["David"] = new MinerInRound { Pubkey = "David", FinalOrderOfNextRound = 2, OutValue = Hash.FromString("d") },
            ["Eve"] = new MinerInRound { Pubkey = "Eve", FinalOrderOfNextRound = 4, OutValue = Hash.FromString("e") }
        }
    };
    
    // Run validation
    var provider = new NextRoundMiningOrderValidationProvider();
    var context = new ConsensusValidationContext 
    { 
        ProvidedRound = maliciousNextRoundInput.ToRound() 
    };
    var result = provider.ValidateHeaderInformation(context);
    
    // BUG: Validation passes despite duplicate FinalOrderOfNextRound values!
    Assert.True(result.Success);  // This passes when it should fail
    
    // Verify the consensus corruption:
    // Generate next round from corrupted data
    var nextRound = new Round();
    maliciousNextRoundInput.ToRound().GenerateNextRoundInformation(
        Timestamp.FromDateTime(DateTime.UtcNow), 
        Timestamp.FromDateTime(DateTime.UtcNow),
        out nextRound
    );
    
    // Both Alice and Bob have identical Order and ExpectedMiningTime!
    var aliceOrder = nextRound.RealTimeMinersInformation["Alice"].Order;
    var bobOrder = nextRound.RealTimeMinersInformation["Bob"].Order;
    var aliceTime = nextRound.RealTimeMinersInformation["Alice"].ExpectedMiningTime;
    var bobTime = nextRound.RealTimeMinersInformation["Bob"].ExpectedMiningTime;
    
    Assert.Equal(aliceOrder, bobOrder);  // Both have Order = 3
    Assert.Equal(aliceTime, bobTime);    // Both have same mining time
    
    // This causes consensus failure - two miners mine simultaneously!
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-290)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
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
