# Audit Report

## Title
Permanent Denial-of-Service Through Severe Status Rollback Cycle

## Summary
The AEDPoS consensus contract contains a critical design flaw where insufficient miner participation (< 2/3+1 threshold) causes the blockchain to enter an infinite rollback cycle with no automatic recovery mechanism, resulting in complete blockchain unavailability.

## Finding Description

The vulnerability arises from a fundamental mismatch between how consensus rounds advance (time-based) versus how the Last Irreversible Block (LIB) advances (participation-based), creating an infinite loop when miner participation is insufficient.

**Severe Status Detection:**
When the gap between current round number and LIB round number reaches 8 or more, the system enters "Severe" mining status. [1](#0-0)  The threshold is calculated as the maximum of 8 or `MaximumTinyBlocksCount`. [2](#0-1) 

**Throughput Reduction and Rollback Trigger:**
Upon entering Severe status, the maximum blocks count is reduced from 8 to 1 block per miner per time slot, and an `IrreversibleBlockHeightUnacceptable` event is fired. [3](#0-2)  This event triggers an automatic blockchain rollback to the LIB height through the kernel's event processor.

**Root Cause - LIB Advancement Requirements:**
The LIB can only advance when at least `MinersCountOfConsent` miners have recorded their `ImpliedIrreversibleBlockHeight` values. [4](#0-3)  The `MinersCountOfConsent` threshold is calculated as `Count * 2 / 3 + 1`, which equals 15 miners for a 21-miner configuration. [5](#0-4)  LIB advancement occurs during `UpdateValue` processing. [6](#0-5) 

**The Infinite Cycle:**
Consensus rounds increment based on time, not block production. [7](#0-6)  When generating a new round, the LIB information is copied forward unchanged if it hasn't advanced. [8](#0-7) 

**Why Existing Protections Fail:**
The `IsPreviousBlockInSevereStatus` flag only manages state transitions between normal and severe status. [9](#0-8)  It does not prevent re-entry into Severe status when the underlying participation problem persists.

**Complete Cycle Execution:**
1. When fewer than 15 out of 21 miners call `UpdateValue`, LIB cannot advance
2. Real-world time continues, causing round numbers to increment
3. The gap between `currentRoundNumber` and `libRoundNumber` grows beyond 8
4. System enters Severe status, reduces throughput to 1 block, fires rollback event
5. Blockchain resets to LIB height and round number
6. After rollback, if participation remains insufficient, rounds start incrementing again
7. Cycle repeats indefinitely with no automatic recovery mechanism

## Impact Explanation

**Critical Severity - Complete Blockchain Unavailability:**

This vulnerability causes complete denial-of-service with the following impacts:

1. **87.5% Throughput Reduction**: Block production drops from 8 to 1 block per miner per time slot, effectively halting normal transaction processing capacity.

2. **Loss of Transaction Finality**: Repeated rollbacks discard all blocks and transactions above LIB height. Users experience transactions being confirmed then invalidated, destroying any confidence in transaction finality.

3. **Network-Wide Operational Impossibility**: The entire blockchain becomes unusable for all participants simultaneously, affecting user transactions, smart contract interactions, cross-chain operations, and dApp functionality.

4. **No Automatic Recovery**: The system lacks any built-in mechanism to break the cycle. Recovery requires manual external coordination to restore sufficient miner participation (≥15/21), which may be impossible during actual infrastructure crises or network partitions.

## Likelihood Explanation

**Medium to High Likelihood:**

This vulnerability has realistic trigger conditions:

1. **No Attacker Required**: This is a design flaw that emerges from operational conditions, not malicious activity. It can occur naturally during infrastructure failures.

2. **Realistic Operational Triggers**: Requires fewer than 15 out of 21 miners to consistently produce blocks and call `UpdateValue`. This can occur due to:
   - Network partitions isolating multiple miners
   - Simultaneous infrastructure failures affecting 7+ miners
   - Coordinated maintenance windows
   - Economic disincentives during Severe status

3. **Self-Reinforcing Nature**: Once entered, Severe status reduces block production to 1 block per miner, potentially discouraging participation and making recovery harder.

4. **Time-Based Progression**: Since rounds advance based on time rather than block production, the vulnerability can manifest even when some miners are active, as long as fewer than the 2/3+1 threshold participate.

5. **Difficult Exit Conditions**: Breaking the cycle requires external coordination to restore sufficient miner participation, which becomes increasingly difficult during actual crises.

## Recommendation

Implement multiple layers of protection:

1. **Add Recovery Threshold Adjustment**: After detecting repeated Severe status entries (e.g., 3 consecutive cycles), temporarily reduce `MinersCountOfConsent` threshold or extend the severe status round gap threshold to allow LIB advancement with reduced participation.

2. **Implement Circuit Breaker**: After N rollback cycles, halt block production entirely and require governance intervention rather than continuing infinite rollbacks.

3. **Add Emergency Recovery Mechanism**: Allow the emergency response organization to manually advance LIB or adjust consensus parameters when the cycle is detected.

4. **Improve Monitoring**: Add events tracking the number of Severe status entries and rollback cycles to enable external monitoring and intervention.

Example modification to add cycle detection:

Add state variable to track consecutive rollbacks, and modify the severe status logic to adjust thresholds or halt after repeated cycles. Add governance method to reset the cycle and manually advance LIB during emergencies.

## Proof of Concept

A complete PoC would require a full AElf test environment with 21 miners. The test scenario would:

1. Initialize blockchain with 21 miners
2. Simulate only 14 miners calling `UpdateValue` consistently
3. Allow time to pass such that 8+ rounds increment without LIB advancing
4. Observe system entering Severe status and triggering rollback
5. After rollback, continue with same 14 miners participating
6. Verify the cycle repeats (gap grows again, severe status triggers again)
7. Demonstrate no automatic recovery occurs

The vulnerability can be confirmed by examining the code paths where:
- LIB calculation requires `MinersCountOfConsent` participation
- Round increment is time-based and independent of LIB advancement
- Rollback resets state but doesn't fix underlying participation problem
- No mechanism exists to break the cycle automatically

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-76)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }

        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-117)
```csharp
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L21-21)
```csharp
        nextRound.RoundNumber = RoundNumber + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```
