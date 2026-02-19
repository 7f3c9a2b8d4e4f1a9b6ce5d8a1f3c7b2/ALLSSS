### Title
3-Miner Configuration Creates Zero Fault Tolerance for Last Irreversible Block Advancement

### Summary
The `MinersCountOfConsent` formula requires unanimous consent (all 3 miners) when exactly 3 miners are configured, providing zero fault tolerance for Last Irreversible Block (LIB) height advancement. If any single miner goes offline, the LIB stops advancing indefinitely, halting transaction finality and blocking cross-chain operations that depend on irreversible block heights.

### Finding Description

The `MinersCountOfConsent` property calculates the Byzantine Fault Tolerance threshold as `RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1)`. [1](#0-0) 

For exactly 3 miners: 3 × 2 ÷ 3 + 1 = 2 + 1 = 3, requiring all 3 miners to participate for consensus operations.

The `LastIrreversibleBlockHeightCalculator` uses this threshold to determine LIB advancement. It retrieves miners who have mined in the current round and checks if the count meets `MinersCountOfConsent`. If not, it sets `libHeight = 0`, preventing any blocks from becoming irreversible. [2](#0-1) 

During block production in `ProcessUpdateValue`, the system calculates the new LIB height and only advances it if sufficient miners have participated. [3](#0-2) 

The system permits configuring the miner count to 3 (or any positive value) without minimum validation, as shown in `SetMaximumMinersCount` which only checks `input.Value > 0`. [4](#0-3) 

Tests explicitly include 3 miners as a valid configuration scenario. [5](#0-4) 

While `SolitaryMinerDetection` prevents a single miner from continuing indefinitely when others are offline, it doesn't resolve the LIB liveness issue when 2 out of 3 miners are still producing blocks but cannot reach the unanimous consensus threshold. [6](#0-5) 

### Impact Explanation

**Operational Denial of Service:**
- **Transaction Finality Halted**: When LIB stops advancing, no new blocks become irreversible, leaving transactions in an unfinalized state indefinitely
- **Cross-Chain Operations Blocked**: Cross-chain indexing and verification mechanisms rely on LIB heights for safety guarantees. The system uses `LibHeightOffsetForCrossChainIndex` to determine when cross-chain data can be safely indexed. [7](#0-6) 
- **Network Synchronization Issues**: Peer synchronization and block propagation protocols depend on LIB advancement for determining chain state consistency
- **Cascading Availability Impact**: While block production continues, the inability to finalize blocks creates operational uncertainty and can stall dependent protocols

**Affected Parties:**
- Users awaiting transaction finality confirmations
- Cross-chain bridges and protocols requiring irreversible block proofs
- Applications depending on finality guarantees for high-value operations

**Severity Justification**: Medium severity due to availability impact without direct fund loss. The system maintains safety (no invalid blocks accepted) but loses liveness (no blocks become final).

### Likelihood Explanation

**High Likelihood in 3-Miner Configurations:**

**Preconditions:**
- System configured with exactly 3 miners via `SetMaximumMinersCount` or initial configuration
- Normal operational conditions where miner availability is not guaranteed

**Trigger Scenarios:**
- Single miner crash or restart (software update, hardware failure)
- Network partition isolating one miner
- Scheduled maintenance on one node
- Resource exhaustion (CPU, memory, disk) on one node

**Feasibility:**
- The configuration is explicitly allowed without warnings or minimum validation
- Test cases demonstrate 3-miner setups as valid configurations
- In distributed systems, single-node failures are common operational events, not attacks
- No attacker capabilities required—natural operational failures trigger the issue

**Detection Constraints:**
- Issue manifests immediately when any miner goes offline
- Observable through monitoring: `ConfirmedIrreversibleBlockHeight` stops advancing
- No recovery until all 3 miners are back online and producing blocks

**Probability**: For production systems configured with 3 miners, this is a realistic operational risk with expected frequency based on typical system availability metrics.

### Recommendation

**Short-term Mitigation:**
1. Add minimum miner count validation in `SetMaximumMinersCount`:
```
Assert(input.Value >= 4, "Minimum of 4 miners required for fault tolerance.");
```

2. Document the operational risk clearly for 3-miner configurations in deployment guides

**Long-term Solution:**
1. Implement differentiated thresholds for liveness vs. safety:
   - Safety threshold (finality): maintain 2n/3+1 for Byzantine fault tolerance
   - Liveness threshold (LIB advancement): use n-f where f=1 for crash fault tolerance
   - For 3 miners: require 2 out of 3 for LIB advancement while maintaining safety properties

2. Add circuit breaker mechanism:
   - If LIB hasn't advanced for N rounds, temporarily reduce threshold
   - Log warnings and emit events for monitoring

3. Enhance `LastIrreversibleBlockHeightCalculator` to distinguish between:
   - Insufficient participation (< MinersCountOfConsent) 
   - Degraded operation (≥ n-1 but < MinersCountOfConsent)
   - Allow LIB advancement with reduced guarantees in degraded mode

**Test Cases:**
- Verify minimum miner count validation rejects values < 4
- Test LIB advancement with n-1 miners active for n > 3
- Verify degraded operation warnings and events

### Proof of Concept

**Initial State:**
- System configured with 3 miners: A, B, C
- All 3 miners initially online and producing blocks
- Current round: N, LIB advancing normally

**Exploitation Steps:**
1. Miner C goes offline (crash, network partition, or maintenance)
2. Round N+1 begins with only miners A and B producing blocks
3. `ProcessUpdateValue` is called when miner A produces a block:
   - `minedMiners = [A, B]` (count = 2)
   - `impliedIrreversibleHeights` contains 2 heights from previous round
   - Check: `2 < MinersCountOfConsent (3)` evaluates to true
   - `libHeight = 0` is returned
4. LIB does not advance; `ConfirmedIrreversibleBlockHeight` remains at previous value
5. Same occurs when miner B produces blocks in subsequent rounds
6. Cross-chain operations depending on LIB begin timing out or stalling

**Expected Behavior:**
- With 4+ miners: MinersCountOfConsent = 3, allowing 1 miner to be offline while LIB advances with 3 active miners

**Actual Behavior:**
- With 3 miners: MinersCountOfConsent = 3, requiring ALL miners online for LIB advancement, providing zero crash fault tolerance

**Success Condition:**
- Monitor `ConfirmedIrreversibleBlockHeight` via consensus contract view methods
- Observe it remains frozen while block production continues
- Verify cross-chain indexing operations stall or fail

### Notes

The mathematical formula `2n/3 + 1` is correct for Byzantine Fault Tolerance safety properties, ensuring no conflicting blocks are finalized. However, for exactly 3 miners, this creates a boundary condition where the safety threshold equals total miner count, eliminating crash fault tolerance for liveness properties. Byzantine fault tolerance distinguishes between safety (no disagreement) and liveness (making progress), and this configuration prioritizes safety at the complete expense of liveness resilience. The issue is compounded by the lack of minimum miner count validation, making this operational fragility easily reachable in practice.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-30)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-281)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L14-14)
```csharp
        Assert(input.Value > 0, "Invalid max miners count.");
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/MaximumMinersCountTests.cs (L28-28)
```csharp
    [InlineData(3)]
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L66-95)
```csharp
    private bool SolitaryMinerDetection(Round currentRound, string pubkey)
    {
        var isAlone = false;
        // Skip this detection until 4th round.
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
        {
            // Not single node.

            var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
            isAlone = minedMinersOfCurrentRound.Count == 0;

            // If only this node mined during previous round, stop mining.
            if (TryToGetPreviousRoundInformation(out var previousRound) && isAlone)
            {
                var minedMiners = previousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }

            // check one further round.
            if (isAlone && TryToGetRoundInformation(previousRound.RoundNumber.Sub(1),
                    out var previousPreviousRound))
            {
                var minedMiners = previousPreviousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }
        }

        return isAlone;
```

**File:** src/AElf.CrossChain.Core/CrossChainConstants.cs (L7-7)
```csharp
    public const int LibHeightOffsetForCrossChainIndex = 0;
```
