### Title
Flawed Mining Order Validation Allows Duplicate FinalOrderOfNextRound Values in NextRound Consensus

### Summary
The `NextRoundMiningOrderValidationProvider` uses `.Distinct()` on `MinerInRound` objects instead of `FinalOrderOfNextRound` values, counting distinct miner objects rather than distinct order values. This allows multiple miners to have identical `FinalOrderOfNextRound` values, which passes validation but corrupts the next round's mining schedule, causing consensus disruption and potential chain liveness issues.

### Finding Description

The validation logic in `NextRoundMiningOrderValidationProvider` contains a critical flaw: [1](#0-0) 

The code calls `.Distinct()` on an `IEnumerable<MinerInRound>` (the result of `.Values.Where(...)`), not on the `FinalOrderOfNextRound` integer values themselves. Since `MinerInRound` is a protobuf-generated class that compares all fields for equality (including different `Pubkey` values), two miners with identical `FinalOrderOfNextRound` but different pubkeys are counted as distinct objects. [2](#0-1) 

The validation should verify that all `FinalOrderOfNextRound` **values** are unique, but instead it only verifies that all `MinerInRound` **objects** are distinct - which they always are since each miner has a unique pubkey.

When a malicious NextRound block passes validation with duplicate orders, it gets stored in state: [3](#0-2) 

The corrupted round data then affects next round generation. When `GenerateNextRoundInformation` processes miners ordered by `FinalOrderOfNextRound`: [4](#0-3) 

Multiple miners with the same order create undefined ordering behavior (LINQ `OrderBy` stability), and the `occupiedOrders` list contains duplicate values, causing some valid orders (1 to minersCount) to be incorrectly classified as occupied while others are skipped entirely.

### Impact Explanation

**Consensus Integrity Violation**: Multiple miners assigned to the same mining order slot means:
- Two or more miners expect to produce blocks at the same expected mining time
- Time slot collisions cause block production failures or conflicts
- Some miners receive no valid time slot (their intended orders are marked as occupied by duplicates)
- Mining schedule corruption persists across subsequent rounds

**Chain Liveness Risk**: If critical miners (e.g., extra block producer) are assigned duplicate orders or no orders, the chain may fail to progress during affected rounds. The consensus mechanism's assumption of unique, sequential mining orders is violated.

**Operational Disruption**: Nodes following the corrupted mining schedule will have inconsistent views of who should produce blocks when, potentially causing network splits or block proposal conflicts.

**Attack Surface**: Any miner producing a NextRound block can inject this vulnerability. With typical miner rotation, opportunities arise multiple times per term.

### Likelihood Explanation

**Reachable Entry Point**: The validation is triggered during `ValidateBeforeExecution` for any block with `AElfConsensusBehaviour.NextRound`: [5](#0-4) 

**Attacker Capabilities**: Any consensus miner can construct a malicious block header when they are assigned to produce the NextRound block. They control the `AElfConsensusHeaderInformation` structure that contains the `Round` data with `FinalOrderOfNextRound` values.

**Execution Practicality**: The attacker crafts a block header where `ProvidedRound.RealTimeMinersInformation` contains duplicate `FinalOrderOfNextRound` values (e.g., Miner A and Miner B both set to order 1). The flawed validation passes because it counts 2 distinct `MinerInRound` objects. The transaction then stores this corrupted round.

**Detection Difficulty**: The validation appears to pass normally - the count equality check succeeds. Only careful inspection of actual `FinalOrderOfNextRound` values (not performed by validators) would reveal the duplicates. Post-execution effects (mining schedule chaos) may be attributed to other issues.

**Economic Rationality**: Attack cost is zero beyond normal mining. Motivation includes: griefing competitors, disrupting consensus to delay governance actions, or creating mining schedule chaos for strategic advantage.

### Recommendation

**Fix the Validation Logic**: Change the distinctness check to validate `FinalOrderOfNextRound` values instead of `MinerInRound` objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Add this line
    .Distinct()
    .Count();
```

**Add Range Validation**: Verify that all `FinalOrderOfNextRound` values are within valid range [1, minersCount]:

```csharp
var orders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();

if (orders.Any(o => o < 1 || o > providedRound.RealTimeMinersInformation.Count))
{
    validationResult.Message = "FinalOrderOfNextRound out of valid range.";
    return validationResult;
}

if (orders.Distinct().Count() != orders.Count)
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

**Add Test Cases**: Create regression tests that attempt NextRound with duplicate orders and verify validation rejection.

### Proof of Concept

**Initial State**:
- Current round has 5 miners (A, B, C, D, E)
- Miners A, B, C produced blocks (have `OutValue != null`)
- Miner A is designated to produce NextRound block

**Attack Sequence**:
1. Miner A constructs NextRound block header with malicious `Round`:
   - Miner A: `FinalOrderOfNextRound = 1`
   - Miner B: `FinalOrderOfNextRound = 1` (duplicate!)
   - Miner C: `FinalOrderOfNextRound = 2`
   - Miners D, E: `FinalOrderOfNextRound = 0` (didn't mine)

2. Block enters validation at `NextRoundMiningOrderValidationProvider`:
   - Filters where `FinalOrderOfNextRound > 0`: [Miner A object, Miner B object, Miner C object]
   - Calls `.Distinct()` on objects: Count = 3 (all objects are distinct)
   - Counts miners with `OutValue != null`: 3 (A, B, C)
   - Validation PASSES (3 == 3)

3. `ProcessNextRound` executes, storing the corrupted round in state

4. **Expected Result**: Validation should fail with "Duplicate FinalOrderOfNextRound values"

5. **Actual Result**: Validation passes, and next round generation assigns:
   - Both Miner A and Miner B get Order = 1 (or undefined order due to LINQ sort instability)
   - Mining schedule corrupted with colliding time slots
   - Some valid orders (2, 3, 4, or 5) incorrectly marked as occupied
   - Miners D and E assigned to wrong slots due to incorrect `ableOrders` calculation

**Success Condition**: The block is accepted by validators despite containing duplicate mining orders, leading to consensus schedule corruption in the next round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-41)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```
