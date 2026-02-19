### Title
Conflict Resolution Logic Fails for Multiple High-Order Collisions Leading to Duplicate Mining Orders

### Summary
The conflict resolution logic in `ApplyNormalConsensusData()` has insufficient search range when `supposedOrderOfNextRound` is near `minersCount`, allowing multiple miners to retain duplicate `FinalOrderOfNextRound` values. [1](#0-0)  This violates the critical invariant that each miner must have a unique order, causing consensus disruption when the next round assigns multiple miners to the same time slot.

### Finding Description

**Root Cause:**

The conflict resolution loop at [2](#0-1)  searches for free orders starting from `supposedOrderOfNextRound + 1` up to `minersCount * 2 - 1`. When `supposedOrderOfNextRound` equals or is close to `minersCount`, the modulo wrapping logic significantly reduces the effective search range.

For example, with `minersCount = 5` and `supposedOrderOfNextRound = 5`:
- Loop checks orders: 1, 2, 3, 4 (via modulo wrapping from i=6,7,8,9)
- It never rechecks order 5 (the conflicted order)
- Only 4 positions are checked for reassignment

If there are 3+ conflicted miners all wanting order 5, and orders 1-2 are already occupied by other miners:
- First conflicted miner moves to order 3
- Second conflicted miner moves to order 4  
- Third conflicted miner finds all checked orders (1,2,3,4) occupied
- The inner for-loop completes without breaking, leaving this miner at order 5
- Current miner also gets assigned order 5 [3](#0-2) 
- **Result: Multiple miners with `FinalOrderOfNextRound = 5`**

**Why Existing Protections Fail:**

1. The validation in `NextRoundMiningOrderValidationProvider` calls `.Distinct()` on `MinerInRound` objects, not on the `FinalOrderOfNextRound` values themselves [4](#0-3) . Since each `MinerInRound` is a distinct object, this check passes even when multiple miners have the same order value.

2. When the next round is generated, `GenerateNextRoundInformation` directly uses `FinalOrderOfNextRound` as the `Order` in the next round without uniqueness validation [5](#0-4) . Multiple miners with duplicate orders will all be assigned to the dictionary with their respective pubkeys, resulting in multiple miners with the same `Order` and `ExpectedMiningTime`.

### Impact Explanation

**Consensus Integrity Violation:**
When multiple miners have identical `Order` values in a round, they receive the same `ExpectedMiningTime` [6](#0-5) . This causes:
- Two or more miners attempting to produce blocks at the same time slot
- Block production conflicts and potential chain forks
- Disruption of the deterministic time-slot-based consensus mechanism
- Violation of the miner schedule integrity invariant

**Operational Impact:**
- Consensus instability in affected rounds
- Potential for missed blocks or competing blocks
- Degraded chain finality and LIB calculation
- Network participants unable to determine canonical chain state

**Severity Justification:**
This is a HIGH severity issue because it directly violates the core consensus invariant of unique miner ordering, which is fundamental to AEDPoS time-slot-based block production. The impact escalates with the number of duplicate orders, potentially causing complete consensus failure for that round.

### Likelihood Explanation

**Attack Requirements:**

The vulnerability can be triggered when an attacker can cause multiple miners to collide on a high order number (close to `minersCount`) while ensuring lower orders are occupied. The attacker's signature determines their order via [7](#0-6) .

**Attacker Capabilities Needed:**

1. **Multiple Validator Control:** Attacker controls 3+ validator nodes, allowing them to coordinate signatures that collide on the same high order number. This requires significant stake investment.

2. **Signature Grinding (Limited):** While signatures are deterministic based on `previousInValue` and previous round signatures [8](#0-7) , attackers can select favorable `previousInValue` choices in the preceding round. However, they must commit via `OutValue = Hash(InValue)` before all previous round signatures are known [9](#0-8) .

3. **Strategic Position Filling:** Attacker or colluding miners must occupy lower-order positions to prevent successful reassignment of conflicted miners.

**Feasibility Assessment:**

- **Reachable Entry Point:** Yes, via normal block production flow
- **Complexity:** MEDIUM-HIGH - Requires multi-validator control or significant coordination/collusion
- **Economic Rationality:** MEDIUM - Disrupting consensus may harm token value, but could be profitable if combined with shorting or competing chain attacks
- **Detection:** MEDIUM - Unusual collision patterns on high orders might be detectable, but could appear as natural variance

**Overall Likelihood:** MEDIUM - While the vulnerability is real and exploitable, it requires substantial resources (multiple validators) or coordination (collusion), making it non-trivial but achievable for well-resourced attackers.

### Recommendation

**Immediate Fix:**

1. **Extend Search Range:** Modify the conflict resolution loop to guarantee checking all possible orders:

```csharp
for (var i = 1; i <= minersCount; i++)
{
    var maybeNewOrder = (supposedOrderOfNextRound + i - 1) % minersCount + 1;
    if (maybeNewOrder == supposedOrderOfNextRound) continue; // Skip conflicted order
    if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
    {
        RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
        break;
    }
}
```

Apply this fix at [2](#0-1) .

2. **Add Uniqueness Validation:** Fix the validation to check for duplicate order values:

```csharp
var finalOrders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
    
if (finalOrders.Count != finalOrders.Distinct().Count())
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

Apply this fix at [10](#0-9) .

3. **Add Assertion:** Add a safety check after conflict resolution to ensure no duplicates remain:

```csharp
// After line 44
Assert(
    RealTimeMinersInformation.Values.Select(m => m.FinalOrderOfNextRound).Distinct().Count() == 
    RealTimeMinersInformation.Values.Count(m => m.FinalOrderOfNextRound > 0),
    "Conflict resolution failed: duplicate orders detected"
);
```

**Test Cases:**

1. Test with 5 miners where 4 signatures collide on order 5, with order 1-2 occupied
2. Test maximum collision scenario: all miners targeting the same high order
3. Test wrap-around edge cases with various `supposedOrderOfNextRound` values near boundaries

### Proof of Concept

**Initial State:**
- 5 validators total: A, B, C, D, E
- Round N completes with all validators having produced blocks

**Attack Sequence:**

1. **Round N+1 Block Production (in order):**
   - Validator A produces block → gets `FinalOrderOfNextRound = 1`
   - Validator B produces block → gets `FinalOrderOfNextRound = 2`
   - Validator C produces block → signature maps to order 5 → gets `FinalOrderOfNextRound = 5`
   - Validator D produces block → signature also maps to order 5 (attacker-controlled)
     - Conflict with C detected
     - C reassigned: tries orders 1(taken), 2(taken), 3(free) → C moved to order 3
     - D gets `FinalOrderOfNextRound = 5`
   - Validator E produces block → signature also maps to order 5 (attacker-controlled)
     - Conflict with D detected
     - D reassignment: tries orders 1(A), 2(B), 3(C), 4(free) → D moved to order 4
     - E gets `FinalOrderOfNextRound = 5`

2. **Attacker F (controlling replacement validator) produces block → signature maps to order 5:**
   - Conflicts with E detected
   - E reassignment loop: tries orders 1(A), 2(B), 3(C), 4(D), wraps to 1(A), 2(B), 3(C), 4(D)
   - **Loop completes without finding free spot**
   - E remains at `FinalOrderOfNextRound = 5`
   - F gets assigned `FinalOrderOfNextRound = 5`

**Expected vs Actual Result:**
- **Expected:** Each miner has unique `FinalOrderOfNextRound` from 1-5
- **Actual:** Both E and F have `FinalOrderOfNextRound = 5`

**Success Condition:**
In Round N+2, both validators E and F are assigned `Order = 5` with identical `ExpectedMiningTime`, causing them to compete for the same time slot, violating consensus integrity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L28-40)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-21)
```csharp
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L67-69)
```csharp
        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
```
