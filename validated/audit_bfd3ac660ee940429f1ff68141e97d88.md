# Audit Report

## Title
Time Slot Collision Vulnerability Due to Incomplete Conflict Resolution and Flawed Validation

## Summary
The AEDPoS consensus contract contains two critical bugs that allow multiple miners to be assigned identical time slots in subsequent rounds: (1) the conflict resolution loop in `ApplyNormalConsensusData` fails to check order `minersCount` as a reassignment candidate when `supposedOrderOfNextRound` equals `minersCount`, and (2) the validation logic incorrectly validates object distinctness rather than `FinalOrderOfNextRound` value uniqueness. Together, these bugs enable time slot collisions that violate core consensus invariants.

## Finding Description

**Bug 1: Incomplete Conflict Resolution Loop**

The `ApplyNormalConsensusData` method attempts to resolve conflicts when multiple miners calculate the same `supposedOrderOfNextRound` value. However, the conflict resolution loop contains an off-by-one error. [1](#0-0) 

When `supposedOrderOfNextRound = minersCount` (e.g., 5 in a 5-miner round), the loop iterates `i = 6, 7, 8, 9`. The modulo calculation on line 33 produces `maybeNewOrder` values of 1, 2, 3, 4 respectively - never checking order 5 itself. If orders 1-4 are already occupied, the loop exits without reassigning the conflicted miner, leaving both miners with `FinalOrderOfNextRound = 5`.

The supposed order is calculated via: [2](#0-1) 

**Bug 2: Flawed Validation Logic**

The `NextRoundMiningOrderValidationProvider` is intended to validate that miners have unique `FinalOrderOfNextRound` values, but it incorrectly calls `.Distinct()` on the `MinerInRound` objects themselves: [3](#0-2) 

Since `MinerInRound` is a protobuf-generated class [4](#0-3) , it uses value equality across all fields. Two miners with different `Pubkey` values are considered distinct even if they share the same `FinalOrderOfNextRound`, allowing duplicate orders to pass validation.

**Execution Flow:**

1. During block production with `UpdateValue` behavior, `GetConsensusExtraDataToPublishOutValue` invokes `ApplyNormalConsensusData`: [5](#0-4) 

2. The round with duplicate `FinalOrderOfNextRound` values is returned in the consensus header: [6](#0-5) 

3. During `ProcessUpdateValue`, the round is persisted to state: [7](#0-6) 

4. The flawed validation only runs for `NextRound` behavior (not `UpdateValue`): [8](#0-7) 

5. When `NextRound` occurs, `GenerateNextRoundInformation` orders miners by `FinalOrderOfNextRound` and assigns time slots: [9](#0-8) 

Miners with duplicate `FinalOrderOfNextRound` receive identical `Order` and `ExpectedMiningTime` values, creating time slot collisions.

## Impact Explanation

This vulnerability breaks a fundamental consensus invariant: each miner must have a unique time slot. The consequences include:

- **Consensus Integrity Violation:** Multiple miners assigned to the same time slot creates ambiguity about which miner should produce blocks at specific times
- **Block Production Conflicts:** Two miners simultaneously attempting to produce blocks can lead to chain forks or consensus deadlock
- **Reduced Finality:** Competing blocks at the same time slot delay block finalization and LIB progression
- **Network Instability:** The corrupted order propagates to subsequent rounds, creating cascading disruption

The severity is **HIGH** because it compromises the core consensus mechanism that ensures deterministic, sequential block production. All network participants are affected as consensus disruption impacts transaction finality and network stability.

## Likelihood Explanation

**Reachability:** The vulnerability is triggered through the standard `UpdateValue` RPC method that any miner calls during normal block production. No special privileges are required beyond being an active miner.

**Preconditions:**
1. In a 5-miner round, 4 miners have already claimed orders 1-4
2. Two miners independently calculate `supposedOrderOfNextRound = 5` via `GetAbsModulus(signature, minersCount) + 1`
3. The second miner publishes after the first

**Feasibility:** While signature hash collisions are probabilistically uncommon, the specific scenario where `supposedOrderOfNextRound = minersCount` occurs with ~20% probability (1 out of 5 possible orders). Over many rounds, natural occurrence becomes likely. Additionally, an adversarial miner could potentially time their block production to increase collision probability.

**Detection:** The flawed validation fails to detect duplicate orders, allowing the vulnerability to persist undetected until actual time slot conflicts manifest during next-round mining.

The attack complexity is **LOW to MEDIUM** - no special capabilities or coordination required, just normal miner operations under specific but realistic conditions.

## Recommendation

**Fix 1: Correct the Conflict Resolution Loop**

Modify the loop to include `supposedOrderOfNextRound` itself as a reassignment candidate:

```csharp
for (var i = supposedOrderOfNextRound; i < supposedOrderOfNextRound + minersCount; i++)
{
    var maybeNewOrder = ((i - 1) % minersCount) + 1; // Ensure 1-based orders
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
        break;
    }
}
```

**Fix 2: Correct the Validation Logic**

Validate `FinalOrderOfNextRound` values directly, not the miner objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

**Additional Safeguard:** Consider adding validation during `UpdateValue` behavior to catch duplicates earlier in the execution flow.

## Proof of Concept

```csharp
[Fact]
public void TimeSlotCollision_DuplicateOrders_Test()
{
    // Setup: 5 miners, 4 have already claimed orders 1-4
    var round = new Round { RoundNumber = 1 };
    
    // Add miners A, B, C, D with FinalOrderOfNextRound 1-4
    for (int i = 1; i <= 4; i++)
    {
        var pubkey = $"miner{i}";
        round.RealTimeMinersInformation[pubkey] = new MinerInRound
        {
            Pubkey = pubkey,
            FinalOrderOfNextRound = i,
            OutValue = Hash.FromString($"out{i}")
        };
    }
    
    // Create signatures that result in supposedOrderOfNextRound = 5
    // GetAbsModulus(sig, 5) should return 4, so +1 = 5
    var signatureE = Hash.FromRawBytes(new byte[] { 0x04 }); // 4 % 5 = 4
    var signatureF = Hash.FromRawBytes(new byte[] { 0x09 }); // 9 % 5 = 4
    
    // Miner E publishes - gets order 5
    round.ApplyNormalConsensusData("minerE", Hash.Empty, 
        Hash.FromString("outE"), signatureE);
    Assert.Equal(5, round.RealTimeMinersInformation["minerE"].FinalOrderOfNextRound);
    
    // Miner F publishes - should trigger conflict resolution
    round.ApplyNormalConsensusData("minerF", Hash.Empty, 
        Hash.FromString("outF"), signatureF);
    
    // BUG: Both miners have FinalOrderOfNextRound = 5
    var minerE = round.RealTimeMinersInformation["minerE"];
    var minerF = round.RealTimeMinersInformation["minerF"];
    
    Assert.Equal(5, minerE.FinalOrderOfNextRound);
    Assert.Equal(5, minerF.FinalOrderOfNextRound); // Duplicate order!
    
    // Validation incorrectly passes
    var provider = new NextRoundMiningOrderValidationProvider();
    var context = new ConsensusValidationContext { ProvidedRound = round };
    var result = provider.ValidateHeaderInformation(context);
    
    // BUG: Validation passes despite duplicate orders
    Assert.True(result.Success); // Should fail but doesn't!
    
    // Verify time slot collision would occur in next round
    var minersWithOrder5 = round.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound == 5).ToList();
    Assert.Equal(2, minersWithOrder5.Count); // Two miners, same order
}
```

## Notes

This vulnerability demonstrates a critical flaw in the AEDPoS consensus mechanism's order assignment and validation logic. The combination of an incomplete conflict resolution algorithm and ineffective validation creates a realistic path to consensus disruption. The fix requires addressing both the algorithmic error in conflict resolution and the logical error in validation to ensure the consensus invariant of unique time slots is properly maintained.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L31-40)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L128-133)
```csharp
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
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
