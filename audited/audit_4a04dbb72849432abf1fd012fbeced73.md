### Title
Non-Deterministic FirstActualMiner() Can Cause Consensus Failure During Blockchain Initialization

### Summary
The `FirstActualMiner()` method uses `FirstOrDefault` on an unordered protobuf map without explicit sorting, causing non-deterministic results when multiple miners have set their `OutValue`. This leads to different nodes calculating different blockchain start timestamps during round 1 to round 2 transition, breaking consensus determinism and potentially forking the chain.

### Finding Description

The vulnerability exists in the `FirstActualMiner()` method: [1](#0-0) 

The method iterates over `RealTimeMinersInformation.Values` without ordering, where `RealTimeMinersInformation` is defined as a protobuf map: [2](#0-1) 

Protobuf maps are backed by `MapField<K,V>`, which internally uses `Dictionary<K,V>` in C#. Dictionary enumeration order is undefined and can vary between nodes, processes, or executions even with identical data.

This method is called during consensus processing when transitioning from round 1 to round 2: [3](#0-2) 

At this point, multiple miners would have already set their `OutValue` during round 1. Without explicit ordering, `FirstOrDefault(m => m.OutValue != null)` returns whichever miner appears first in the dictionary's iteration order, which is non-deterministic.

The codebase demonstrates awareness of this issue in similar code that correctly uses `OrderBy`: [4](#0-3) 

### Impact Explanation

**Consensus Integrity Violation**: Different nodes executing the same transactions will calculate different blockchain start timestamps. This breaks the fundamental requirement that all nodes must reach identical state from identical inputs.

**Chain Fork Risk**: When nodes disagree on blockchain start timestamp, subsequent time-based calculations (round transitions, term changes, election countdowns) will diverge, causing nodes to validate blocks differently and potentially fork the chain.

**Severity Justification**: This is a HIGH severity issue because:
- It affects consensus-critical state (blockchain start timestamp)
- All nodes are impacted during chain initialization
- The failure mode is silent - nodes won't detect the divergence until validation failures occur
- Recovery requires chain restart with fixed code

### Likelihood Explanation

**Occurrence**: This happens naturally during normal operation with HIGH probability:
1. During round 1, miners produce blocks sequentially, each setting their `OutValue`
2. When `ProcessNextRound` is called to transition to round 2, multiple miners will have `OutValue != null`
3. Each node deserializes the same Round state but may iterate the map in different order
4. Different nodes select different "first actual miners"

**No Attack Required**: This is not an attack vector but a determinism bug that manifests during normal blockchain initialization.

**Preconditions**: Only requires normal multi-miner blockchain operation, which is the intended use case.

**Detection**: The bug is difficult to detect in testing because:
- Single-node test environments won't expose the non-determinism
- Nodes may accidentally agree if they happen to iterate in the same order
- Divergence only becomes apparent when validation failures occur

### Recommendation

Add explicit ordering before using `FirstOrDefault`:

```csharp
public MinerInRound FirstActualMiner()
{
    return RealTimeMinersInformation.Count > 0
        ? RealTimeMinersInformation.Values
            .OrderBy(m => m.Order)  // Add explicit ordering
            .FirstOrDefault(m => m.OutValue != null)
        : null;
}
```

Alternative approach - find the miner with the earliest ActualMiningTime:

```csharp
public MinerInRound FirstActualMiner()
{
    return RealTimeMinersInformation.Count > 0
        ? RealTimeMinersInformation.Values
            .Where(m => m.ActualMiningTimes.Any())
            .OrderBy(m => m.ActualMiningTimes.First())
            .FirstOrDefault()
        : null;
}
```

**Test Cases**: Add multi-node integration tests that:
1. Initialize blockchain with multiple miners
2. Have all miners produce blocks in round 1
3. Verify all nodes calculate identical blockchain start timestamp
4. Test with different node startup orders and hash seed variations

### Proof of Concept

**Initial State**:
- Blockchain starting with 5 miners
- Round 1 in progress

**Transaction Sequence**:
1. Miner A produces block 1, sets OutValue_A via UpdateValue
2. Miner B produces block 2, sets OutValue_B via UpdateValue  
3. Miner C produces block 3, sets OutValue_C via UpdateValue
4. Miner D produces block 4, sets OutValue_D via UpdateValue
5. Miner E produces block 5, calls NextRound to transition to round 2

**Expected Result**: All nodes should compute the same blockchain start timestamp (e.g., Miner A's ActualMiningTime since Order=1)

**Actual Result**: 
- Node X's dictionary iterates: B, A, D, C, E → selects Miner B's timestamp
- Node Y's dictionary iterates: C, E, A, B, D → selects Miner C's timestamp
- Nodes now have divergent blockchain start timestamps
- Subsequent time-based consensus decisions differ
- Chain forks when nodes disagree on round transition timing

**Success Condition**: Without the fix, running identical transactions on multiple nodes with different dictionary iteration orders produces different blockchain start timestamps, demonstrating the consensus failure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L150-155)
```csharp
    public MinerInRound FirstActualMiner()
    {
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.OutValue != null)
            : null;
    }
```

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L117-123)
```csharp
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L112-113)
```csharp
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
```
