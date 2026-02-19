# Audit Report

## Title
Conflict Resolution Fails When Current Miner's Old Order is Not Considered Available, Causing Duplicate Mining Order Assignments

## Summary
The `ApplyNormalConsensusData` function's conflict resolution logic fails to recognize that the current miner is vacating their old order position. When all N mining orders are occupied and a miner's calculated order conflicts with another miner, the reassignment algorithm cannot find an available slot because it checks the current state where the initiating miner's old order still appears occupied. This results in duplicate `FinalOrderOfNextRound` assignments, causing two miners to be scheduled for the same mining time slot in the subsequent round.

## Finding Description

The vulnerability exists in the order conflict resolution mechanism within the consensus round update logic. When a miner produces a block, their signature deterministically calculates a `supposedOrderOfNextRound` value. [1](#0-0) 

If another miner already occupies this calculated order as their `FinalOrderOfNextRound`, the algorithm identifies them as conflicted and attempts reassignment. [2](#0-1) 

The critical flaw occurs in the availability check for reassignment candidates. [3](#0-2)  The algorithm verifies whether a candidate order is available by checking if any miner currently has that order assigned. However, this check examines the state **before** the current miner's order update is applied.

**Scenario illustrating the bug:**
- Initial state: N=3 miners, all orders (1,2,3) occupied
- Miner A: FinalOrderOfNextRound = 1
- Miner B: FinalOrderOfNextRound = 2  
- Miner C: FinalOrderOfNextRound = 3

When Miner A produces a block and their signature calculates to order 2:
1. Conflict detected: Miner B occupies order 2
2. Reassignment loop attempts to find new order for B (lines 31-40)
3. Checks order 3: Occupied by C (unavailable)
4. Checks order 1: **Still shows as occupied by A** (unavailable)
5. Checks order 2: Occupied by B (unavailable)
6. Loop completes without finding available order
7. B's FinalOrderOfNextRound remains at 2
8. A's FinalOrderOfNextRound is set to 2 [4](#0-3) 
9. **Result: Both A and B have FinalOrderOfNextRound = 2**

The existing validation mechanisms fail to prevent this:

**UpdateValueValidationProvider** only verifies that OutValue and Signature fields are properly populated, without checking for duplicate order assignments. [5](#0-4) 

**NextRoundMiningOrderValidationProvider** uses `.Distinct()` on `MinerInRound` objects themselves. [6](#0-5)  Since each miner is a distinct object, this validation passes even when their `FinalOrderOfNextRound` values are duplicated.

The duplicate assignments flow through the state update mechanism. [7](#0-6)  The modified round information is extracted [8](#0-7)  and applied to state during block execution. [9](#0-8) 

When the next round is generated, both miners with duplicate orders are processed sequentially. [10](#0-9)  Each receives the same `Order` value and identical `ExpectedMiningTime` calculated from that order, resulting in a mining slot collision.

## Impact Explanation

**HIGH Severity - Consensus Protocol Integrity Violation**

This vulnerability directly breaks the fundamental AEDPoS consensus invariant that each validator must have a unique mining time slot. When `GenerateNextRoundInformation` processes miners with duplicate `FinalOrderOfNextRound` values, both receive identical `Order` assignments and `ExpectedMiningTime` values. [11](#0-10) 

**Consensus Disruption:**
- **Mining Slot Collision**: Two validators scheduled to produce blocks simultaneously
- **Abandoned Time Slot**: The vacated order position remains unassigned
- **Chain Liveness Risk**: Conflicting block production attempts may cause forks or chain halt
- **Schedule Chaos**: Mining order integrity compromised for the entire round

**Affected Parties:**
- All network participants experience consensus instability
- Validators face ambiguous block production responsibilities  
- Chain may fail to progress if mining conflicts cannot be resolved

The severity is HIGH because this compromises the core consensus mechanism that ensures orderly, sequential block production. Unlike vulnerabilities requiring specific attack vectors, this degrades fundamental protocol correctness during normal operation.

## Likelihood Explanation

**HIGH Likelihood - Occurs in Normal Operation**

**Triggering Conditions:**
1. **Steady State Operation**: All N validators have produced blocks in current round (all orders 1-N occupied) - this is the expected normal state
2. **Hash Collision**: A validator's signature hash modulo N produces a value conflicting with another validator's current order
3. **No Malicious Action**: Occurs through legitimate mining operations

**Entry Point:**
The vulnerability is reachable through the public `UpdateValue` method called during normal block production. [12](#0-11) 

**Probability Analysis:**
With N validators and signature-based order calculation using modulo arithmetic [1](#0-0) , hash collisions occur with probability 1/N per block. In steady-state operation where all orders are occupied (the normal condition), any collision between a validator's new calculated order and another validator's existing assignment triggers this bug.

**Feasibility:**
- No special setup required beyond normal network operation
- No adversarial behavior needed
- Difficult to detect before impact as validation doesn't catch duplicate assignments
- Reproducible whenever preconditions align (regularly in practice)

The likelihood is HIGH because this vulnerability manifests during routine consensus operation without requiring any attack vector or unusual network conditions.

## Recommendation

**Fix the availability check to exclude the current miner's old order:**

Modify the conflict resolution logic in `ApplyNormalConsensusData` to recognize that the current miner is vacating their existing order position. Before checking order availability, capture the current miner's existing `FinalOrderOfNextRound` and exclude it from the occupancy check:

```csharp
// Capture current miner's old order before updates
var currentMinerOldOrder = RealTimeMinersInformation[pubkey].FinalOrderOfNextRound;

// In the availability check loop, exclude the order being vacated:
if (RealTimeMinersInformation.Values.All(m => 
    m.FinalOrderOfNextRound != maybeNewOrder || 
    (m.Pubkey == pubkey && m.FinalOrderOfNextRound == currentMinerOldOrder)))
{
    // Order is available (either unoccupied or will be vacated by current miner)
    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
    break;
}
```

**Additionally, strengthen validation:**

Implement proper duplicate detection in `NextRoundMiningOrderValidationProvider` by checking distinct order values rather than distinct objects:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
    
if (distinctOrderCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound detected.";
    return validationResult;
}
```

## Proof of Concept

```csharp
[Fact]
public void ApplyNormalConsensusData_ShouldCauseDuplicateOrders_WhenAllOrdersOccupied()
{
    // Arrange: Create a round with 3 miners, all orders occupied (1, 2, 3)
    var round = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation =
        {
            ["MinerA"] = new MinerInRound
            {
                Pubkey = "MinerA",
                FinalOrderOfNextRound = 1,
                SupposedOrderOfNextRound = 1,
                OutValue = Hash.FromString("OutValueA"),
                Signature = Hash.FromString("SignatureA")
            },
            ["MinerB"] = new MinerInRound
            {
                Pubkey = "MinerB",
                FinalOrderOfNextRound = 2,
                SupposedOrderOfNextRound = 2,
                OutValue = Hash.FromString("OutValueB"),
                Signature = Hash.FromString("SignatureB")
            },
            ["MinerC"] = new MinerInRound
            {
                Pubkey = "MinerC",
                FinalOrderOfNextRound = 3,
                SupposedOrderOfNextRound = 3,
                OutValue = Hash.FromString("OutValueC"),
                Signature = Hash.FromString("SignatureC")
            }
        }
    };

    // Create a signature that will hash to order 2 (currently occupied by MinerB)
    // Using GetAbsModulus(signature.ToInt64(), 3) + 1 = 2
    // So signature.ToInt64() % 3 should equal 1
    var conflictingSignature = Hash.FromRawBytes(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 }); // value = 1
    
    // Act: MinerA updates with a signature that conflicts with MinerB's order
    var updatedRound = round.ApplyNormalConsensusData(
        "MinerA",
        Hash.FromString("PreviousInValue"),
        Hash.FromString("NewOutValue"),
        conflictingSignature
    );

    // Assert: Both MinerA and MinerB should have FinalOrderOfNextRound = 2 (duplicate)
    var minerAOrder = updatedRound.RealTimeMinersInformation["MinerA"].FinalOrderOfNextRound;
    var minerBOrder = updatedRound.RealTimeMinersInformation["MinerB"].FinalOrderOfNextRound;
    
    Assert.Equal(2, minerAOrder);
    Assert.Equal(2, minerBOrder); // BUG: Both miners have the same order
    
    // This violates consensus invariant: each miner should have unique order
    var allOrders = updatedRound.RealTimeMinersInformation.Values
        .Select(m => m.FinalOrderOfNextRound)
        .ToList();
    var distinctOrders = allOrders.Distinct().Count();
    
    Assert.NotEqual(allOrders.Count, distinctOrders); // Proves duplicate exists
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-26)
```csharp
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L34-34)
```csharp
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L44-44)
```csharp
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
```
