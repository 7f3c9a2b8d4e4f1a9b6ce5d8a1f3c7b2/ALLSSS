### Title
Unbounded Nested Loop Complexity in Consensus Round Update Causes Block Production Denial of Service

### Summary
The `ApplyNormalConsensusData` function contains nested loops with O(c*n*m) complexity that can exceed AElf's execution branch threshold of 15,000, causing block production failures. When `MaximumMinersCount` is set to moderate-to-high values (100+) through governance and order conflicts occur among miners, the computational cost of conflict resolution can halt block generation, resulting in consensus disruption.

### Finding Description

The vulnerability exists in the consensus round update logic where miners' next-round order assignments are calculated and conflicts are resolved. [1](#0-0) 

The nested loop structure creates O(c*n*m) complexity where:
- Outer `foreach` iterates over `conflicts` (miners with duplicate `FinalOrderOfNextRound`)
- Inner `for` loop iterates up to `2*minersCount` to find available positions
- `All()` method checks all `minersCount` miners for each position candidate

This function is invoked during normal block production via the consensus extra data generation flow: [2](#0-1) [3](#0-2) 

The critical failure point is that `SetMaximumMinersCount` has no upper bound validation: [4](#0-3) 

AElf enforces execution limits through branch counting: [5](#0-4) [6](#0-5) 

When the nested loops execute, each iteration increments the branch counter. With `minersCount=100` and `conflicts=3`, the operation count reaches 3×100×100 = 30,000 branches, exceeding the 15,000 threshold and throwing `RuntimeBranchThresholdExceededException`.

### Impact Explanation

**Operational DOS of Consensus:**
- Miners unable to generate valid consensus extra data cannot produce blocks
- If multiple/all miners hit the threshold, the chain experiences block production delays or halts
- Consensus mechanism disrupted until miner count is reduced via governance

**Quantified Threshold Breach:**
- MinersCount=50, Conflicts=6: 15,000 branches (at limit)
- MinersCount=100, Conflicts=3: 30,000 branches (2x over)
- MinersCount=200, Conflicts=2: 80,000 branches (5.3x over)

**Affected Parties:**
- All block producers when miner count reaches critical threshold
- Chain operations dependent on timely block production
- Users experiencing transaction confirmation delays

**Severity Justification:**
High severity because it causes operational DOS of the core consensus mechanism, though requires governance to set parameters that enable the condition.

### Likelihood Explanation

**Preconditions:**
1. Governance must set `MaximumMinersCount` to 100+ through Parliament proposal (legitimate scaling action)
2. Order conflicts must occur among miners (either through natural hash collisions or coordination)

**Attack Complexity:**
- **Medium-High**: Does not require compromising governance, only legitimate parameter adjustment
- As the network scales, governance will naturally increase miner counts toward 100+
- Hash-based order assignment creates ~1/n collision probability per miner; with large n, conflicts accumulate
- Malicious miners could coordinate to amplify conflicts, but natural collisions suffice

**Feasibility Conditions:**
- Execution limits are enforced at runtime during block production
- No compensating controls exist (no complexity checks, no upper bounds on miner count)
- The condition is reachable through standard consensus flow without special permissions

**Detection/Operational Constraints:**
- Failure is deterministic once parameters cross threshold
- Would be detected immediately (failed block production)
- Recovery requires governance action to reduce `MaximumMinersCount`

**Probability Reasoning:**
Medium-to-High likelihood as chain matures. Early stage (17 miners) is safe, but scaling toward 50-100 miners creates risk zone. Natural evolution of the network makes this increasingly probable without fixes.

### Recommendation

**Code-Level Mitigation:**

1. Add upper bound validation in `SetMaximumMinersCount`:
```
Assert(input.Value > 0 && input.Value <= 128, "Invalid max miners count. Must be between 1 and 128.");
``` [7](#0-6) 

2. Optimize conflict resolution algorithm to O(n) complexity by maintaining an available positions set:
```csharp
// Pre-compute occupied positions in O(n)
var occupiedPositions = new HashSet<int>(
    RealTimeMinersInformation.Values.Select(m => m.FinalOrderOfNextRound)
);

// For each conflict, find first available position in O(n) worst case
foreach (var orderConflictedMiner in conflicts)
{
    for (var i = 1; i <= minersCount; i++)
    {
        if (!occupiedPositions.Contains(i))
        {
            occupiedPositions.Remove(orderConflictedMiner.FinalOrderOfNextRound);
            RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = i;
            occupiedPositions.Add(i);
            break;
        }
    }
}
```

**Invariant Checks:**
- Add complexity assertion: `Assert(conflicts.Count * minersCount < 10000, "Conflict resolution complexity exceeds safe threshold");`
- Monitor and alert when conflict count exceeds expected thresholds (>10% of miners)

**Test Cases:**
- Test with `MaximumMinersCount=100` and `conflicts=10` to verify execution succeeds
- Test that `MaximumMinersCount=200` is rejected or handled safely
- Measure branch count during conflict resolution with various parameters
- Test natural collision rates with realistic signature distributions

### Proof of Concept

**Initial State:**
1. Deploy AEDPoS consensus contract
2. Through Parliament governance, execute `SetMaximumMinersCount(100)`
3. Ensure actual miner count reaches 100 through election process
4. Wait for term transition to activate 100 miners

**Attack Sequence:**
1. Monitor current round state - identify miners' `FinalOrderOfNextRound` values
2. As miners produce blocks, conflicts naturally accumulate if 3+ miners' signatures hash to same position modulo 100
3. When a miner attempts block production with existing conflicts:
   - `GetConsensusExtraData` is called
   - `ApplyNormalConsensusData` executes nested loops
   - Branch count exceeds 15,000 threshold
   - `RuntimeBranchThresholdExceededException` is thrown
   - Block production fails

**Expected Result:**
- Miner successfully produces block with updated round information

**Actual Result:**
- Transaction fails with "Contract branch threshold 15000 exceeded"
- Block production halted for affected miner
- If pattern repeats across multiple miners, consensus stalls

**Success Condition:**
Chain experiences block production delays or halt when miner count reaches 100+ and conflicts occur, demonstrating the DOS vulnerability. Recovery requires governance intervention to reduce `MaximumMinersCount`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-40)
```csharp
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-28)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L29-36)
```csharp
    public void BranchCount()
    {
        if (_branchThreshold != -1 && _branchCount == _branchThreshold)
            throw new RuntimeBranchThresholdExceededException(
                $"Contract branch threshold {_branchThreshold} exceeded.");

        _branchCount++;
    }
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L1-10)
```csharp
namespace AElf.Kernel.SmartContract;

public class SmartContractConstants
{
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;

    public const int StateSizeLimit = 128 * 1024;

```
