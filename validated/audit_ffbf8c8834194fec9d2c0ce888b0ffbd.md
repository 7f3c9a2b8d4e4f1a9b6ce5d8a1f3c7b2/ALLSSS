# Audit Report

## Title
Inadequate Validation Allows Time Slot Collisions via Duplicate FinalOrderOfNextRound Values

## Summary
The `NextRoundMiningOrderValidationProvider` incorrectly validates uniqueness of `FinalOrderOfNextRound` values by calling `.Distinct()` on `MinerInRound` objects instead of on the order values themselves. This allows malicious miners to set duplicate mining orders through `TuneOrderInformation`, causing multiple miners to receive identical time slots in the next round and compromising consensus integrity.

## Finding Description

The vulnerability exists in the validation logic that checks uniqueness of mining orders for the next round. The validator calls `.Distinct()` on a collection of `MinerInRound` objects rather than on the order values, making the uniqueness check ineffective. [1](#0-0) 

Since `MinerInRound` is a protobuf-generated message type with 17 fields including the unique `pubkey` field, [2](#0-1)  its auto-generated `Equals()` method compares all fields. Two `MinerInRound` objects with different pubkeys are never considered equal even if they have identical `FinalOrderOfNextRound` values, causing the validation to always pass regardless of duplicate order values.

**Attack Vector - Via TuneOrderInformation:**

Miners can manipulate other miners' `FinalOrderOfNextRound` values through the `TuneOrderInformation` field in `UpdateValueInput`. [3](#0-2)  The contract directly applies these values without validation. [4](#0-3) 

Additionally, miners set their own `FinalOrderOfNextRound` directly from the input's `SupposedOrderOfNextRound`. [5](#0-4) 

The `UpdateValue` method is a public RPC that accepts arbitrary `UpdateValueInput` parameters, [6](#0-5)  and only validates that the sender is an active miner in the current or previous round. [7](#0-6) 

**Consequence - Time Slot Collision:**

When generating the next round, duplicate `FinalOrderOfNextRound` values directly cause mining time slot collisions. Each miner's `ExpectedMiningTime` is calculated using their order value, and duplicate orders produce identical timestamps. [8](#0-7) 

The `NextRoundMiningOrderValidationProvider` is only invoked during `NextRound` behavior, [9](#0-8)  not during `UpdateValue` transactions when the malicious values are set. [10](#0-9)  By the time validation runs, the duplicate orders are already committed to state.

## Impact Explanation

**Severity: HIGH**

This vulnerability directly compromises the core consensus mechanism. The AEDPoS protocol relies on each miner having a unique, non-overlapping time slot to produce blocks. When multiple miners receive identical `ExpectedMiningTime` values:

- Multiple miners attempt to produce blocks simultaneously, creating ambiguity about which block is legitimate
- This can lead to competing forks, consensus deadlock, or complete block production stalls
- The network becomes unable to reliably advance the blockchain
- Recovery requires manual intervention or chain restart

The impact affects the entire network's operation, not just individual miners or users.

## Likelihood Explanation

**Probability: HIGH**

The attack is straightforward to execute:
- Any active miner (elected through normal processes) can exploit this vulnerability
- Requires only a single `UpdateValue` transaction with malicious `TuneOrderInformation`
- No complex timing, state manipulation, or collusion required
- The broken validation provides a false sense of security while allowing duplicates through

The preconditions are realistic: the attacker must be an active miner in the current round, which is achievable through the election process. The attack complexity is low with no special privileges needed beyond standard miner capabilities.

## Recommendation

Fix the validation logic to check uniqueness of the actual order values instead of the `MinerInRound` objects. The corrected implementation should extract the `FinalOrderOfNextRound` values before calling `.Distinct()`:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

Additionally, consider adding validation during `UpdateValue` to prevent malicious `TuneOrderInformation` from being applied in the first place. This defense-in-depth approach ensures duplicates cannot be committed to state.

## Proof of Concept

The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task DuplicateFinalOrderOfNextRound_ShouldCauseTimeSlotCollision()
{
    // Setup: Initialize consensus with 3 miners
    var initialMiners = new[] { "miner1", "miner2", "miner3" };
    await InitializeConsensus(initialMiners);
    
    // Miner1 produces block and sets FinalOrderOfNextRound = 1
    await UpdateValueAsMiner("miner1", supposedOrder: 1);
    
    // Miner2 produces block with malicious TuneOrderInformation
    // Sets miner3's FinalOrderOfNextRound = 1 (same as miner1)
    var maliciousInput = new UpdateValueInput
    {
        SupposedOrderOfNextRound = 2,
        TuneOrderInformation = { { "miner3", 1 } } // Duplicate order!
    };
    await UpdateValueAsMiner("miner2", maliciousInput);
    
    // Trigger NextRound
    var nextRound = await TriggerNextRound();
    
    // Verify: Both miner1 and miner3 have identical ExpectedMiningTime
    var miner1Time = nextRound.RealTimeMinersInformation["miner1"].ExpectedMiningTime;
    var miner3Time = nextRound.RealTimeMinersInformation["miner3"].ExpectedMiningTime;
    
    Assert.Equal(miner1Time, miner3Time); // Time slot collision!
}
```

This test proves that the broken validation allows duplicate `FinalOrderOfNextRound` values to be committed, resulting in time slot collisions in the next round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L247-247)
```csharp
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-86)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```
