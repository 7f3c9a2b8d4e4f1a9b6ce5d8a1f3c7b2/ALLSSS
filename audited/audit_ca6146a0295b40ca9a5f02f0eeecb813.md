# Audit Report

## Title
LIB Calculation Fails When Insufficient Miners Participated in Previous Round

## Summary
The Last Irreversible Block (LIB) calculation can fail in the current round even when sufficient miners participate, if too few miners mined in the previous round. This occurs because the LIB algorithm retrieves miners who mined in the current round but evaluates their `ImpliedIrreversibleBlockHeight` values from the previous round, filtering out miners with zero heights who didn't participate previously.

## Finding Description

The AEDPoS consensus mechanism calculates LIB by examining miners who successfully mined in the current round and retrieving their implied irreversible block heights from the previous round. The vulnerability exists due to the interaction between several components:

**LIB Calculation Logic**: The `LastIrreversibleBlockHeightCalculator.Deconstruct()` method gets the list of miners who mined in the current round, then looks up their `ImpliedIrreversibleBlockHeight` values from the previous round stored in state. [1](#0-0) 

**Zero Height Filtering**: The `GetSortedImpliedIrreversibleBlockHeights` method explicitly filters out all miners with `ImpliedIrreversibleBlockHeight <= 0`, only considering miners who have positive height values. [2](#0-1) 

**Consensus Threshold Requirement**: The system requires at least `MinersCountOfConsent = (total_miners * 2) / 3 + 1` miners with non-zero heights for successful LIB calculation. If fewer heights are available, LIB returns 0. [3](#0-2) [4](#0-3) 

**Height Update Mechanism**: Miners only update their `ImpliedIrreversibleBlockHeight` when they successfully mine a block via `ProcessUpdateValue`. Miners who miss their time slots retain height=0 in that round. [5](#0-4) 

**Execution Scenario** (with 17 miners, requiring 12 for consensus):
- **Round N**: Only 11 out of 17 miners successfully mine blocks. These 11 miners set their `ImpliedIrreversibleBlockHeight` in Round N. The 6 miners who missed retain height=0 in Round N. Round N is saved to state.
- **Round N+1**: All 17 miners successfully participate and mine blocks
- **LIB Calculation in Round N+1**: When the 12th miner processes their block, the LIB calculator retrieves all 12 miners who have mined so far in Round N+1, then looks up their heights from Round N (retrieved from state via `TryToGetPreviousRoundInformation`). [6](#0-5) 
- However, if one of these 12 miners was among the 6 who didn't mine in Round N, their height from Round N is 0 and gets filtered out
- Only 11 heights pass the filter, which is less than the required 12
- LIB calculation returns 0, and no `IrreversibleBlockFound` event is fired [7](#0-6) 

The protobuf definition confirms that `implied_irreversible_block_height` defaults to 0 for new `MinerInRound` objects. [8](#0-7) 

## Impact Explanation

This vulnerability causes **consensus liveness degradation** with the following concrete impacts:

1. **Finality Stall**: When LIB calculation returns 0, the blockchain's Last Irreversible Block height does not advance, preventing blocks from achieving finality status

2. **Cross-Chain Operations Disruption**: Cross-chain transfers and indexing operations rely on LIB for finality guarantees. A stalled LIB prevents cross-chain transactions from progressing, as they require irreversible block confirmations

3. **Validator Impact**: Block validators cannot reliably confirm irreversible block heights during the stall period, affecting their synchronization and validation operations

4. **Temporary DoS**: The system experiences availability degradation affecting dependent services

**Severity Justification**: Medium - This is an availability/liveness issue rather than a fund-at-risk vulnerability. The impact is temporary and self-healing once miners achieve consistent participation across multiple consecutive rounds. However, during network instability, high latency periods, or coordinated downtime, this can cause extended finality stalls affecting critical operations.

**Quantified Impact**: With 17 miners (typical production configuration), if more than 5 miners (>29% of the network) miss their time slots in one round, the next round's LIB calculation will fail even if all miners participate in that next round.

## Likelihood Explanation

**Natural Occurrence Probability**: HIGH

This vulnerability occurs naturally without any malicious actor:
- Network instability, high latency, or temporary connectivity issues commonly cause miners to miss time slots
- Miner node maintenance, restarts, or brief outages naturally result in missed slots
- The Byzantine fault tolerance threshold (1/3 or ~33%) is very close to the failure threshold (6 out of 17 miners or ~35%), making this scenario realistic in production environments
- Production blockchain networks regularly experience periods where multiple nodes have degraded performance

**Attack Feasibility**: MEDIUM

While no direct attack by malicious miners is required, external attackers could exploit this:
- DDoS attacks targeting specific miner nodes could force them to miss time slots
- Network partition attacks could isolate miners temporarily
- The attack is economically irrational for Byzantine miners (missing slots forfeits mining rewards), but feasible for external attackers seeking to disrupt finality

**Preconditions**:
- Standard consensus operation with no special configuration required
- More than (n/3) miners miss time slots in one round (realistic during poor network conditions)
- Sufficient miners participate in the subsequent round to attempt LIB calculation

**Detection**: The issue manifests as LIB height not advancing, which may be difficult to distinguish from normal consensus variations, making it a low-detectability issue that could persist unnoticed.

## Recommendation

**Solution**: Modify the LIB calculation to handle miners who didn't participate in the previous round more gracefully. Consider one of these approaches:

1. **Use Most Recent Known Height**: Instead of filtering out miners with zero heights from the previous round, use the most recent non-zero `ImpliedIrreversibleBlockHeight` from any earlier round where that miner participated

2. **Adjust Threshold Dynamically**: Calculate `MinersCountOfConsent` based on the number of miners who actually participated in the previous round, rather than the total miner count

3. **Carry Forward Heights During Round Generation**: In `GenerateNextRoundInformation()`, copy `ImpliedIrreversibleBlockHeight` from the previous round for miners who missed their slots, preserving their last known height:

```csharp
// In Round_Generation.cs, around line 46-55
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minersNotMinedCurrentRound[i].Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1),
    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight  // ADD THIS
};
```

However, this approach requires careful consideration of consensus semantics to ensure miners who didn't observe recent blocks don't inadvertently contribute to LIB advancement with stale information.

## Proof of Concept

The vulnerability can be demonstrated with the following scenario in a test environment with 17 miners:

```csharp
// Test setup: 17 miners configured, MinersCountOfConsent = 12

// Round N: Simulate only 11 miners successfully mining
// - Miners M1-M11 mine blocks and set ImpliedIrreversibleBlockHeight
// - Miners M12-M17 miss their time slots (height remains 0 in Round N)
// - Round N is saved to state

// Round N+1: All 17 miners successfully mine
// - Each miner calls ProcessUpdateValue sequentially
// - When M12 (the 12th miner) processes their block:
//   - LIB calculator gets miners [M1...M12] who mined in Round N+1
//   - Retrieves their heights from Round N (from state)
//   - M1-M11: non-zero heights from Round N
//   - M12: height=0 from Round N (filtered out)
//   - Only 11 heights available < 12 required
//   - LIB calculation returns 0
//   - No IrreversibleBlockFound event fired

// Expected: LIB should advance since all miners participate in Round N+1
// Actual: LIB remains 0 due to insufficient miners with non-zero heights from Round N
```

This can be verified by examining the consensus contract state during round transitions and monitoring for missing `IrreversibleBlockFound` events when the described participation pattern occurs.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-25)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L56-64)
```csharp
    private bool TryToGetPreviousRoundInformation(out Round previousRound)
    {
        previousRound = new Round();
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        if (roundNumber < 2) return false;
        var targetRoundNumber = roundNumber.Sub(1);
        previousRound = State.Rounds[targetRoundNumber];
        return !previousRound.IsEmpty;
    }
```

**File:** protobuf/aedpos_contract.proto (L299-300)
```text
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
```
