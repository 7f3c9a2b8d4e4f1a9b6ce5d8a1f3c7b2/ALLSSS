# Audit Report

## Title
3-Miner Configuration Creates Zero Fault Tolerance for Last Irreversible Block Advancement

## Summary
The AEDPoS consensus contract's `MinersCountOfConsent` formula requires unanimous participation from all 3 miners when exactly 3 miners are configured, providing zero fault tolerance for Last Irreversible Block (LIB) advancement. When any single miner experiences downtime, LIB height stops advancing indefinitely, halting transaction finality and blocking cross-chain operations.

## Finding Description

The consensus protocol calculates the Byzantine Fault Tolerance threshold using integer division. [1](#0-0) 

With exactly 3 miners, this formula yields: 3 × 2 ÷ 3 + 1 = 2 + 1 = 3, requiring all three miners to participate for LIB advancement. The integer division is critical here—any fractional result is truncated.

The `LastIrreversibleBlockHeightCalculator` enforces this threshold during LIB calculation. It retrieves miners who produced blocks in the current round via `GetMinedMiners()`, then checks if their count meets `MinersCountOfConsent`. If insufficient miners participated, it sets `libHeight = 0`, preventing blocks from becoming irreversible. [2](#0-1) 

The `GetMinedMiners()` method filters miners based on whether they produced blocks by checking `SupposedOrderOfNextRound != 0`. [3](#0-2) 

During block production, the system invokes this calculator to determine the new LIB height. If the calculated `libHeight` exceeds the current confirmed height, it fires an `IrreversibleBlockFound` event to advance finality. Otherwise, LIB remains frozen. [4](#0-3) 

The `SetMaximumMinersCount` method permits configuring any positive miner count, including 3, without enforcing a minimum threshold for fault tolerance. [5](#0-4) 

Test suites explicitly validate 3-miner configurations as acceptable scenarios, confirming this is not an edge case but a supported deployment model. [6](#0-5) 

While `SolitaryMinerDetection` prevents a single miner from producing blocks indefinitely when isolated, it only activates when exactly one miner mines alone for multiple consecutive rounds (checked via `isAlone` logic requiring single-miner operation). It does not address the LIB liveness issue when 2 out of 3 miners continue producing blocks but cannot satisfy the unanimous consensus requirement. [7](#0-6) 

## Impact Explanation

**Operational Denial of Service:**

When LIB advancement halts, the blockchain maintains safety properties (no invalid blocks accepted) but loses liveness guarantees:

- **Transaction Finality Blocked**: All transactions remain in an unfinalized state. Users and applications awaiting finality confirmations experience indefinite delays.

- **Cross-Chain Operations Stalled**: Cross-chain protocols verify data using irreversible block heights. With LIB frozen, cross-chain bridges cannot advance, blocking token transfers and message passing between chains.

- **Network Synchronization Degraded**: Peers use LIB as the authoritative checkpoint for chain state consistency. Without advancing LIB, nodes may diverge in their view of finalized state.

- **Cascading Protocol Impact**: While block production continues through DPoS consensus, dependent protocols requiring finality guarantees experience operational disruptions. High-value operations that mandate irreversible confirmations cannot complete.

**Affected Parties:**
- End users awaiting transaction finality for critical operations
- Cross-chain protocols requiring irreversible block proofs
- Applications with finality-dependent business logic
- Network operators monitoring chain health

**Severity Justification**: Medium severity reflects the availability impact without direct fund loss. The vulnerability affects liveness (transaction finality) rather than safety (fund security), but creates significant operational disruption for production networks.

## Likelihood Explanation

**Preconditions:**
- Blockchain configured with exactly 3 miners via `SetMaximumMinersCount` or genesis configuration
- Normal operational environment where 100% uptime is not guaranteed

**Trigger Scenarios (Common Operational Events):**
- Miner software crash or panic requiring restart
- Scheduled maintenance windows (software updates, hardware servicing)
- Network partitions isolating one miner from peers
- Resource exhaustion (memory leaks, disk space, CPU saturation)
- Infrastructure provider outages (cloud zone failures, ISP issues)

**Feasibility Analysis:**
- The 3-miner configuration is explicitly supported without warnings or constraints
- Test coverage validates this scenario as acceptable
- Single-node failures represent routine operational events, not sophisticated attacks
- No attacker privileges or capabilities required
- Industry-standard distributed systems experience single-node failures frequently (typical availability: 99.9% means ~8 hours downtime per year per node)

**Detection and Recovery:**
- Immediately observable through `ConfirmedIrreversibleBlockHeight` metric freezing
- Requires bringing the offline miner back online and resuming block production
- No automatic recovery mechanism exists

For production networks deployed with 3 miners, this represents a realistic and recurring operational risk rather than a theoretical vulnerability.

## Recommendation

Enforce a minimum miner count that provides meaningful fault tolerance. Modify `SetMaximumMinersCount` to reject configurations below a safe threshold:

```csharp
public override Empty SetMaximumMinersCount(Int32Value input)
{
    EnsureElectionContractAddressSet();
    
    Assert(input.Value > 0, "Invalid max miners count.");
    // Add minimum threshold check for fault tolerance
    Assert(input.Value >= 4, "Minimum 4 miners required for fault tolerance. With 3 miners, any single failure halts LIB advancement.");
    
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set max miners count.");
    // ... rest of implementation
}
```

Alternatively, if 3-miner deployments are intentionally supported for testing or specific use cases, document this limitation clearly and implement monitoring alerts when LIB advancement stalls.

## Proof of Concept

```csharp
[Fact]
public async Task ThreeMinerConfiguration_SingleFailure_HaltsLIBAdvancement()
{
    // Setup: Initialize chain with exactly 3 miners
    var threeMiners = InitialCoreDataCenterKeyPairs.Take(3).ToList();
    await InitializeConsensusWithMiners(threeMiners);
    
    // Round 1: All 3 miners produce blocks - LIB advances normally
    var round1 = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    foreach (var miner in round1.RealTimeMinersInformation.Values.OrderBy(m => m.Order))
    {
        await ProduceBlockForMiner(miner.Pubkey);
    }
    
    var libAfterRound1 = round1.ConfirmedIrreversibleBlockHeight;
    Assert.True(libAfterRound1 > 0, "LIB should advance when all miners participate");
    
    // Round 2: Only 2 miners produce blocks (miner 3 offline)
    await MoveToNextRound();
    var round2 = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var activeMiners = round2.RealTimeMinersInformation.Values.Take(2).OrderBy(m => m.Order);
    
    foreach (var miner in activeMiners)
    {
        await ProduceBlockForMiner(miner.Pubkey);
    }
    // Third miner does NOT produce block (simulating downtime)
    
    await MoveToNextRound();
    var round3 = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Verify: LIB remains frozen at previous height
    var libAfterRound2 = round3.ConfirmedIrreversibleBlockHeight;
    Assert.Equal(libAfterRound1, libAfterRound2); // LIB did NOT advance
    
    // Verify: MinersCountOfConsent = 3 (unanimous requirement)
    var minersCountOfConsent = round3.MinersCountOfConsent;
    Assert.Equal(3, minersCountOfConsent);
    
    // Verify: Only 2 miners mined in round 2
    var minedMiners = round2.GetMinedMiners();
    Assert.Equal(2, minedMiners.Count);
    Assert.True(minedMiners.Count < minersCountOfConsent, 
        "Insufficient miners participated, causing LIB to freeze");
}
```

## Notes

The mathematical core of this vulnerability lies in C# integer division: with 3 miners, `3 * 2 / 3 + 1 = 2 + 1 = 3` requires unanimous participation. With 4 miners, the same formula yields `4 * 2 / 3 + 1 = 2 + 1 = 3`, providing tolerance for 1 failure. This creates a specific edge case where the 3-miner configuration uniquely eliminates all fault tolerance.

The issue is exacerbated because there are no warnings, minimum threshold checks, or automatic recovery mechanisms to mitigate this configuration choice. While the system continues producing blocks (maintaining safety), the lack of LIB advancement (losing liveness) creates operational challenges for any protocol components depending on transaction finality.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-281)
```csharp
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

**File:** test/AElf.OS.Core.Tests/OSCoreTestAElfModule.cs (L39-39)
```csharp
            for (var i = 0; i < 3; i++) miners.Add(CryptoHelper.GenerateKeyPair().PublicKey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L66-96)
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
    }
```
