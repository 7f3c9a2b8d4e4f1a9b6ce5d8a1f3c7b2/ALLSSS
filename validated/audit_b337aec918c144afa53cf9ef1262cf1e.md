# Audit Report

## Title
Flawed Mining Order Validation Allows Duplicate FinalOrderOfNextRound Values in NextRound Consensus

## Summary
The `NextRoundMiningOrderValidationProvider` incorrectly validates mining orders by calling `.Distinct()` on `MinerInRound` protobuf objects instead of on `FinalOrderOfNextRound` integer values. This allows multiple miners to be assigned identical mining orders, bypassing validation and corrupting the next round's mining schedule, causing consensus disruption and potential chain liveness issues.

## Finding Description

The validation logic contains a critical flaw in how it verifies uniqueness of mining orders. [1](#0-0) 

The code calls `.Distinct()` on an `IEnumerable<MinerInRound>` collection, not on the `FinalOrderOfNextRound` integer values themselves. Since `MinerInRound` is a protobuf-generated class [2](#0-1)  that implements value-based equality comparing all 17 fields (including the unique `Pubkey` field), two different miners with identical `FinalOrderOfNextRound` but different pubkeys are counted as distinct objects.

The validation compares the count of distinct `MinerInRound` objects against the count of miners who mined. [3](#0-2)  If you have 3 miners who mined with FinalOrderOfNextRound values [1, 1, 3], the validation sees 3 distinct `MinerInRound` objects and compares this to 3 miners who mined - the check passes despite having duplicate order value 1.

When a malicious NextRound block passes this flawed validation, the validation is triggered during ValidateBeforeExecution [4](#0-3)  and the validation service executes all registered providers. [5](#0-4) 

The corrupted round data is then persisted via `AddRoundInformation`. [6](#0-5)  which stores it in blockchain state. [7](#0-6) 

The corrupted round data subsequently affects next round generation. When `GenerateNextRoundInformation` processes miners, it iterates over them ordered by `FinalOrderOfNextRound` and assigns each miner their `FinalOrderOfNextRound` value as their order in the next round. [8](#0-7) 

Multiple miners with the same `FinalOrderOfNextRound` will both be assigned the same `Order` value in the next round. Additionally, the `occupiedOrders` list will contain duplicate values [9](#0-8)  causing the calculation of available orders for non-mining miners to potentially skip some valid order slots.

## Impact Explanation

**Consensus Integrity Violation**: The AEDPoS consensus mechanism relies on the invariant that each miner has a unique, sequential mining order within a round. When multiple miners are assigned to the same order slot:
- Two or more miners expect to produce blocks at the same expected mining time (calculated from their order)
- Time slot collisions cause block production conflicts or failures
- Mining schedule corruption persists until a proper NextRound or NextTerm transition corrects it

**Chain Liveness Risk**: If critical miners (e.g., the extra block producer responsible for finalizing rounds) are assigned duplicate orders or their intended slots are occupied, the chain may fail to progress during affected rounds. The consensus mechanism's core assumption of unique, sequential mining orders is fundamentally violated.

**Operational Disruption**: Nodes following the corrupted mining schedule will have inconsistent views of which miner should produce blocks at what time, potentially causing network disagreements, failed block propagation, or consensus timeouts.

## Likelihood Explanation

**Reachable Entry Point**: Any consensus miner can construct a malicious block header when assigned to produce the NextRound block. They control the `AElfConsensusHeaderInformation` structure [10](#0-9)  containing the `Round` data with `FinalOrderOfNextRound` values.

**Execution Practicality**: The attacker simply sets duplicate `FinalOrderOfNextRound` values in the round data (e.g., MinerA and MinerB both set to order 1). The flawed validation counts 2 distinct `MinerInRound` objects and compares against 2 miners who mined - the check passes. The corrupted round is then stored.

**Detection Difficulty**: The validation appears to pass normally - the count equality check succeeds because it's counting objects instead of values. Only inspection of actual `FinalOrderOfNextRound` integer values (not performed by the validator) would reveal duplicates.

## Recommendation

Fix the validation to check uniqueness of the integer values, not the protobuf objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Extract integer values first
    .Distinct()
    .Count();
```

## Proof of Concept

A test demonstrating the vulnerability would:
1. Create a round with 3 miners (A, B, C) where A and B have `FinalOrderOfNextRound = 1` and C has `FinalOrderOfNextRound = 2`
2. Call the `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation` with this round
3. Verify the validation incorrectly passes (returns `Success = true`)
4. Verify that when `GenerateNextRoundInformation` processes this round, both A and B are assigned `Order = 1` in the next round, breaking the unique order invariant

## Notes

The vulnerability is in production consensus code and directly exploitable by any consensus miner when they produce a NextRound block. The flawed `.Distinct()` call on protobuf objects rather than integer values is the root cause, and protobuf's value-based equality semantics across all fields (including unique `Pubkey`) means duplicate order values go undetected.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L17-17)
```csharp
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L18-23)
```csharp
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```
