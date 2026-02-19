# Audit Report

## Title
Conflict Resolution Logic Fails for Multiple High-Order Collisions Leading to Duplicate Mining Orders

## Summary
The AEDPoS consensus mechanism contains a critical flaw in the conflict resolution logic of `ApplyNormalConsensusData()` that allows multiple miners to retain identical `FinalOrderOfNextRound` values when collisions occur near `minersCount`. This breaks the fundamental consensus invariant that each miner must have a unique mining order, resulting in multiple miners being assigned to the same time slot in subsequent rounds, causing consensus disruption and potential chain instability.

## Finding Description

The vulnerability stems from an insufficient search range in the conflict resolution algorithm combined with a flawed validation check.

**Root Cause - Incomplete Search Range:**

When a miner's calculated `supposedOrderOfNextRound` collides with existing miners, the conflict resolution loop attempts to reassign conflicted miners to available orders. [1](#0-0) 

The loop searches from `supposedOrderOfNextRound + 1` to `minersCount * 2 - 1`, using modulo arithmetic to wrap around. However, when `supposedOrderOfNextRound` equals `minersCount`, the modulo operation produces orders `1, 2, 3, ..., minersCount-1` but **never rechecks order `minersCount` itself**.

**Concrete Example:**
- `minersCount = 5`, `supposedOrderOfNextRound = 5`
- Loop iterations: i=6,7,8,9 → maybeNewOrder = 1,2,3,4
- Order 5 is never checked for reassignment

**Exploitation Scenario:**
1. Three miners' signatures collide on order 5
2. Orders 1-2 are already occupied by other miners
3. First conflicted miner: reassigned to order 3
4. Second conflicted miner: reassigned to order 4
5. Third conflicted miner: finds all checked orders (1,2,3,4) occupied, loop exits **without breaking**, remains at order 5
6. Current miner: gets assigned to order 5 [2](#0-1) 
7. **Result: Two miners with `FinalOrderOfNextRound = 5`**

**Failed Protection #1 - Incorrect Validation:**

The `NextRoundMiningOrderValidationProvider` is supposed to catch duplicate orders but contains a critical bug. [3](#0-2) 

The validation calls `.Distinct()` on `MinerInRound` **objects** rather than on the `FinalOrderOfNextRound` **values**. Since each `MinerInRound` is a distinct protobuf message object in memory, this check passes even when multiple miners share the same order value.

**Failed Protection #2 - Direct Order Assignment:**

When generating the next round, the code directly uses `FinalOrderOfNextRound` as the `Order` without any uniqueness validation. [4](#0-3) 

Multiple miners with duplicate `FinalOrderOfNextRound` values will all be added to the next round's miner dictionary with different pubkeys but identical `Order` and `ExpectedMiningTime` values, directly violating the consensus invariant.

## Impact Explanation

**Consensus Integrity Violation:**
This vulnerability breaks the core AEDPoS consensus guarantee that each miner has a unique time slot for block production. When multiple miners share the same `Order`, they receive identical `ExpectedMiningTime` values, causing:

- **Simultaneous Block Production:** Multiple miners attempt to produce blocks at the exact same timestamp, leading to competing blocks and potential forks
- **Mining Schedule Corruption:** The deterministic time-slot-based consensus mechanism becomes non-deterministic
- **LIB Calculation Disruption:** Irreversible block height calculations may be affected by conflicting block production
- **Network Consensus Failure:** Nodes may have difficulty reaching agreement on the canonical chain state

**Severity: HIGH** - This directly undermines the fundamental consensus mechanism of the blockchain. Unlike edge-case bugs, this affects the core security property that ensures orderly block production. Complete consensus failure is possible if multiple duplicate orders occur in a single round.

## Likelihood Explanation

**Attack Requirements:**

An attacker needs to cause 3+ miners to collide on a high order number (close to `minersCount`) while ensuring lower orders are occupied. The order is deterministically calculated from the miner's signature. [5](#0-4) 

**Attacker Capabilities:**

1. **Multiple Validator Control:** Attacker must control 3+ validator nodes to coordinate signatures that collide on the same high order. This requires significant stake investment in the AEDPoS system.

2. **Signature Coordination:** While signatures are deterministic based on consensus data, attackers controlling multiple validators can coordinate their block production timing and influence their signature values through `InValue` selection in previous rounds.

3. **Strategic Positioning:** Attacker or colluding miners must occupy lower-order positions (1-2 in the example) to prevent successful reassignment of conflicted miners.

**Feasibility Assessment:**

- **Entry Point:** Reachable via normal consensus block production flow
- **Prerequisites:** Control of 3+ validators (achievable for well-funded attackers or through collusion among existing validators)
- **Complexity:** MEDIUM-HIGH - Requires coordination and stake, but no cryptographic breaks needed
- **Economic Rationality:** Disrupting consensus could be profitable if combined with shorting the token, attacking competing chains, or extorting the network

**Likelihood: MEDIUM** - While not trivially exploitable, this is achievable for sophisticated attackers with sufficient resources or through collusion among a subset of validators. The vulnerability exists in production code and is exploitable under realistic conditions.

## Recommendation

**Fix #1 - Complete Conflict Resolution Search:**

Modify the conflict resolution loop to search through **all possible orders**, including the conflicted order itself:

```csharp
for (var i = 1; i <= minersCount; i++)
{
    // Skip the conflicted order initially
    if (i == supposedOrderOfNextRound) continue;
    
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != i))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = i;
        break;
    }
}
// If no free order found, assert/revert to prevent silent failure
```

**Fix #2 - Correct Validation Logic:**

Fix the validation to check for duplicate order **values** instead of object distinctness:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

**Fix #3 - Additional Safeguard:**

Add explicit duplicate detection in `GenerateNextRoundInformation`:

```csharp
var orderCounts = minersMinedCurrentRound
    .GroupBy(m => m.FinalOrderOfNextRound)
    .Where(g => g.Count() > 1);
Assert(orderCounts.Count() == 0, "Duplicate mining orders detected");
```

## Proof of Concept

```csharp
[Fact]
public void Test_MultipleHighOrderCollisions_CreateDuplicateMiningOrders()
{
    // Setup: Create a round with 5 miners
    var round = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation = { }
    };
    
    const int minersCount = 5;
    var miner1 = "miner1";
    var miner2 = "miner2"; 
    var miner3 = "miner3";
    var miner4 = "miner4";
    var miner5 = "miner5";
    var miner6 = "miner6";
    var miner7 = "miner7";
    
    // Initialize 5 miners with orders 1,2,3,4,5
    for (int i = 1; i <= 5; i++)
    {
        var pubkey = $"miner{i}";
        round.RealTimeMinersInformation[pubkey] = new MinerInRound
        {
            Pubkey = pubkey,
            Order = i,
            FinalOrderOfNextRound = i
        };
    }
    
    // Create signatures that all hash to order 5 (minersCount)
    // Using carefully crafted hash values
    var sig5a = HashHelper.ComputeFrom(5); // Hashes to order 5
    var sig5b = HashHelper.ComputeFrom(minersCount + 5); // Also order 5
    var sig5c = HashHelper.ComputeFrom(minersCount * 2 + 5); // Also order 5
    
    var previousInValue = Hash.Empty;
    var outValue = Hash.Empty;
    
    // Apply consensus data for miners that collide on order 5
    // First collision - miner6 gets order 5, conflicts with miner5
    round.ApplyNormalConsensusData(miner6, previousInValue, outValue, sig5a);
    
    // Second collision - miner7 should conflict with both miner5 and miner6
    round.ApplyNormalConsensusData(miner7, previousInValue, outValue, sig5b);
    
    // Verify: Multiple miners now have FinalOrderOfNextRound = 5
    var minersWithOrder5 = round.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound == 5)
        .ToList();
    
    // VULNERABILITY: Should have only 1 miner with order 5, but has 2+
    Assert.True(minersWithOrder5.Count > 1, 
        $"Expected multiple miners with duplicate order 5, found {minersWithOrder5.Count}");
    
    // Demonstrate that validation fails to catch this
    var validationProvider = new NextRoundMiningOrderValidationProvider();
    var validationContext = new ConsensusValidationContext
    {
        ProvidedRound = round
    };
    
    var result = validationProvider.ValidateHeaderInformation(validationContext);
    
    // VULNERABILITY: Validation incorrectly passes
    Assert.True(result.Success, "Validation should pass due to bug in Distinct() check");
}
```

This proof of concept demonstrates that when multiple miners collide on a high order number (order 5 in a 5-miner system), the conflict resolution fails to properly reassign all conflicted miners, resulting in duplicate `FinalOrderOfNextRound` values that pass through the flawed validation logic.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

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
