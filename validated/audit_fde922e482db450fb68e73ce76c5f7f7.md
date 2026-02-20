# Audit Report

## Title
Incomplete Conflict Resolution in Miner Order Assignment Leads to Duplicate Orders and Non-Deterministic Consensus

## Summary
The `ApplyNormalConsensusData()` function's conflict resolution loop contains an off-by-one error that prevents it from checking position `minersCount` when reassigning conflicted miners. When two miners' signatures both hash to order `minersCount` and all lower positions are occupied, both miners receive duplicate `FinalOrderOfNextRound` values. This bypasses validation and propagates into the next round, where both miners are assigned identical mining timeslots, violating the fundamental consensus invariant of unique order per miner.

## Finding Description

The vulnerability exists in the conflict resolution logic executed during normal block production when miners calculate their next round mining order.

**Root Cause - Incomplete Search Space:** [1](#0-0) 

The conflict resolution loop iterates from `supposedOrderOfNextRound + 1` to `minersCount * 2 - 1`. When `supposedOrderOfNextRound = minersCount`, the modulo arithmetic generates positions 1 through `minersCount - 1`, but never checks position `minersCount` itself.

**Mathematical Proof:** With 21 miners and `supposedOrderOfNextRound = 21`:
- Loop range: i = 22 to 41
- For i = 22: `maybeNewOrder = 22 % 21 = 1`
- For i = 41: `maybeNewOrder = 41 % 21 = 20`
- Position 21 is never checked

**Execution Flow:**

1. Miner A produces a block with signature mapping to order 21 [2](#0-1) 

2. Miner B later produces a block with signature also mapping to order 21

3. Conflict detection finds Miner A at position 21 [3](#0-2) 

4. If positions 1-20 are occupied, the loop completes without finding an available position for Miner A

5. Both miners retain `FinalOrderOfNextRound = 21` [4](#0-3) 

**Validation Bypass:**

The `NextRoundMiningOrderValidationProvider` uses `.Distinct()` on `MinerInRound` objects, not on their `FinalOrderOfNextRound` values: [5](#0-4) 

Since each miner has a unique `pubkey`, they are treated as distinct objects even with duplicate order values. [6](#0-5) 

The `TuneOrderInformation` mechanism only includes miners where `FinalOrderOfNextRound != SupposedOrderOfNextRound`: [7](#0-6) 

Both conflicted miners have Final = Supposed = 21, so they're excluded from tuning adjustments. [8](#0-7) 

**Propagation to Next Round:**

When generating the next round, miners are ordered by `FinalOrderOfNextRound`: [9](#0-8) 

Both miners receive `Order = 21` and identical `ExpectedMiningTime`, creating a race condition where both believe they should mine at the same instant.

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant that each miner must have a unique mining order and timeslot.

**Consensus Non-Determinism**: Two miners attempting to produce blocks at the same time creates a race condition where network propagation timing determines acceptance, potentially causing temporary forks across different network partitions.

**Unfair Miner Penalties**: One miner will be incorrectly marked as having "missed" their slot despite following their assigned schedule, affecting reputation scores and reward distribution.

**Round Transition Instability**: Duplicate orders persist through round boundaries, potentially cascading into subsequent rounds until miner set changes or the conflict naturally resolves.

**Network-Wide Inconsistency**: Different nodes may have different views of which miner should produce at a given time, causing inconsistent block validation.

The impact is **HIGH** because it degrades consensus integrity during normal operation without requiring any malicious actor, undermining the blockchain's fundamental security guarantees.

## Likelihood Explanation

This vulnerability has **MEDIUM-HIGH** likelihood:

**No Attacker Required**: Triggers through natural signature hash distribution. The order is calculated as `GetAbsModulus(sigNum, minersCount) + 1`, where `GetAbsModulus` returns values 0 to `minersCount - 1`: [10](#0-9) 

This means orders range from 1 to `minersCount`, making collisions at `minersCount` equally probable as any other position (1/21 per miner).

**Realistic Preconditions**: Requires high participation (minersCount - 1 miners having produced blocks), which is expected in a well-functioning consensus network. The vulnerability specifically triggers at the edge position (order = minersCount).

**Silent Failure**: No error is thrown when conflict resolution fails, and the duplicate persists through validation designed to prevent it.

**Cumulative Risk**: Each round with high participation increases probability. With 21 miners producing blocks, birthday paradox makes collisions statistically likely over multiple rounds.

## Recommendation

Fix the conflict resolution loop to include position `minersCount` in its search space:

```csharp
for (var i = supposedOrderOfNextRound + 1; i <= supposedOrderOfNextRound + minersCount; i++)
{
    var maybeNewOrder = ((i - 1) % minersCount) + 1;
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
        break;
    }
}
```

Additionally, strengthen validation to check distinct order values:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

## Proof of Concept

```csharp
[Fact]
public void ApplyNormalConsensusData_DuplicateOrders_WhenCollisionAtMaxPosition()
{
    // Setup: 21 miners, 20 have already mined (positions 1-20 occupied)
    var round = GenerateRoundWith21Miners();
    FillPositions1Through20(round);
    
    // Miner A produces block with signature mapping to position 21
    var minerA = "MinerA";
    var signatureA = GenerateSignatureMappingToOrder21(minersCount: 21);
    round.ApplyNormalConsensusData(minerA, Hash.Empty, Hash.Empty, signatureA);
    
    Assert.Equal(21, round.RealTimeMinersInformation[minerA].FinalOrderOfNextRound);
    
    // Miner B produces block with signature also mapping to position 21
    var minerB = "MinerB";
    var signatureB = GenerateSignatureMappingToOrder21(minersCount: 21);
    round.ApplyNormalConsensusData(minerB, Hash.Empty, Hash.Empty, signatureB);
    
    // BUG: Both miners have FinalOrderOfNextRound = 21
    Assert.Equal(21, round.RealTimeMinersInformation[minerA].FinalOrderOfNextRound);
    Assert.Equal(21, round.RealTimeMinersInformation[minerB].FinalOrderOfNextRound);
    
    // Verify duplicate orders cause identical timeslots in next round
    round.GenerateNextRoundInformation(
        currentBlockTimestamp: Timestamp.FromDateTime(DateTime.UtcNow),
        blockchainStartTimestamp: Timestamp.FromDateTime(DateTime.UtcNow.AddHours(-1)),
        out var nextRound);
    
    var minerAInNextRound = nextRound.RealTimeMinersInformation[minerA];
    var minerBInNextRound = nextRound.RealTimeMinersInformation[minerB];
    
    // Both miners get the same order and expected mining time
    Assert.Equal(21, minerAInNextRound.Order);
    Assert.Equal(21, minerBInNextRound.Order);
    Assert.Equal(minerAInNextRound.ExpectedMiningTime, minerBInNextRound.ExpectedMiningTime);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-26)
```csharp
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L284-290)
```text
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```
