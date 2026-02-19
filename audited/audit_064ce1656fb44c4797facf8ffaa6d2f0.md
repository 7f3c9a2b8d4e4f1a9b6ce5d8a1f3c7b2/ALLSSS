### Title
Broken Order Uniqueness Validation Allows Consensus Disruption via Duplicate Mining Orders

### Summary
The `NextRoundMiningOrderValidationProvider` validation logic uses `Distinct()` on `MinerInRound` objects instead of their `FinalOrderOfNextRound` values. Since `MinerInRound` is a protobuf-generated class without custom equality implementation, the validation always passes even when multiple miners have duplicate order values, allowing malicious miners to corrupt round scheduling and disrupt consensus.

### Finding Description

The validation occurs in `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` where the code attempts to verify that miners have unique next-round orders: [1](#0-0) 

The `Distinct()` method operates on `MinerInRound` objects, which are protobuf-generated classes defined at: [2](#0-1) 

Protobuf-generated C# classes do not override `Equals()` and `GetHashCode()` by default, causing `Distinct()` to use reference equality. This means every `MinerInRound` object in the collection is considered distinct regardless of field values, so the validation never detects duplicate `FinalOrderOfNextRound` values.

The vulnerable validation is invoked during `NextRound` behavior processing: [3](#0-2) 

When validation incorrectly passes, the corrupted round information is stored: [4](#0-3) 

The next round generation logic then uses these duplicate orders to assign mining time slots: [5](#0-4) 

When duplicate `FinalOrderOfNextRound` values exist, multiple miners get assigned the same `Order` in the next round, causing them to attempt block production at identical time slots while leaving other slots empty.

The `NextRound` method is publicly callable with only a basic permission check: [6](#0-5) [7](#0-6) 

The only authorization requirement is that the caller is in the current or previous miner list—the input data itself is not validated for correctness beyond the broken order uniqueness check.

### Impact Explanation

**Consensus Disruption**: Multiple miners assigned identical orders will attempt to produce blocks simultaneously at the same time slot, causing block production conflicts. Meanwhile, other time slots remain unassigned, leaving gaps in the block production schedule.

**Chain Halt Risk**: If duplicate orders are assigned to a significant portion of miners, the consensus round cannot complete properly. The chain may experience degraded block production or complete halts if critical time slots become contested or empty.

**Sustained Attack**: Once corrupted round information is stored in state, subsequent rounds may propagate the corruption since order assignments build on previous round data. The attacker only needs to execute one successful malicious `NextRound` transaction.

**Attack Scope**: Any miner in the current miner list can execute this attack against the entire network. With typical configurations of 17-21 initial miners, the attack has a low authorization barrier.

The severity is **Critical** because it directly breaks the core consensus invariant of unique miner scheduling, affecting all network participants and potentially causing chain-wide operational failure.

### Likelihood Explanation

**Reachable Entry Point**: The `NextRound` method is a public RPC endpoint directly callable by any miner. No special privileges beyond being in the active miner list are required.

**Feasible Preconditions**: The attacker must be an active miner (in current or previous round's miner list). This is a realistic attacker profile since miners are elected participants who may turn malicious or be compromised.

**Low Attack Complexity**: The exploit requires only:
1. Crafting a `NextRoundInput` protobuf message with duplicate `FinalOrderOfNextRound` values across multiple `MinerInRound` entries
2. Submitting a single transaction calling `NextRound` with this input
3. The broken validation allows it through, and `ProcessNextRound` stores the corrupted data

**No Detection Barrier**: The validation is designed to catch this exact attack pattern but fails due to the implementation bug. No other code path validates order uniqueness before storage.

**Economic Rationality**: The attack costs only transaction fees (minimal) but can disrupt the entire network's consensus. A malicious miner could execute this to:
- Sabotage competitors
- Manipulate block production timing
- Create conditions for other attacks during consensus instability

The likelihood is **High** given the low technical barrier, realistic attacker profile, and absence of effective countermeasures.

### Recommendation

**Immediate Fix**: Modify the validation to check uniqueness of `FinalOrderOfNextRound` values, not object references:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Extract the order value
    .Distinct()
    .Count();
```

**Additional Validation**: Add explicit duplicate detection:

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

**Invariant Check**: Verify that all orders form a contiguous sequence from 1 to N (number of miners who mined):

```csharp
var expectedOrders = Enumerable.Range(1, distinctCount).ToList();
var actualOrders = orders.OrderBy(o => o).ToList();
if (!expectedOrders.SequenceEqual(actualOrders))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound sequence.";
    return validationResult;
}
```

**Test Cases**: Add unit tests that:
1. Submit NextRoundInput with two miners having identical FinalOrderOfNextRound
2. Verify validation fails with appropriate error message
3. Test edge cases: all miners same order, gaps in order sequence, orders exceeding miner count

### Proof of Concept

**Initial State**:
- Blockchain running with 5 active miners (Miner A, B, C, D, E)
- Current round in progress with all miners having mined blocks

**Attack Sequence**:

1. Attacker (Miner A) observes current round where miners have assigned FinalOrderOfNextRound values:
   - Miner A: FinalOrderOfNextRound = 1
   - Miner B: FinalOrderOfNextRound = 2  
   - Miner C: FinalOrderOfNextRound = 3
   - Miner D: FinalOrderOfNextRound = 4
   - Miner E: FinalOrderOfNextRound = 5

2. Attacker crafts malicious `NextRoundInput` with duplicate orders:
   - Miner A: FinalOrderOfNextRound = 1
   - Miner B: FinalOrderOfNextRound = 1  // DUPLICATE
   - Miner C: FinalOrderOfNextRound = 3
   - Miner D: FinalOrderOfNextRound = 4
   - Miner E: FinalOrderOfNextRound = 5
   - (Order 2 is missing)

3. Attacker submits transaction: `NextRound(maliciousInput)`

4. Validation executes:
   - `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` runs
   - `Distinct()` operates on 5 distinct `MinerInRound` object references
   - `distinctCount = 5`
   - Comparison: `5 == 5` (number of miners with OutValue != null)
   - Validation PASSES (incorrectly)

5. `ProcessNextRound` executes:
   - Stores corrupted round information to state
   - `GenerateNextRoundInformation` assigns Order values based on corrupted FinalOrderOfNextRound

**Expected Result**: Validation should fail with "Invalid FinalOrderOfNextRound" error, transaction rejected.

**Actual Result**: Validation passes, transaction executes successfully, next round has:
- Miner A assigned Order = 1
- Miner B assigned Order = 1 (DUPLICATE - both at same time slot)
- Miner C assigned Order = 3  
- Miner D assigned Order = 4
- Miner E assigned Order = 5
- Order 2 time slot is EMPTY

**Consensus Impact**: In next round, Miners A and B simultaneously attempt block production at time slot 1, causing conflicts. Time slot 2 never produces a block. Round cannot complete properly, disrupting consensus.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
