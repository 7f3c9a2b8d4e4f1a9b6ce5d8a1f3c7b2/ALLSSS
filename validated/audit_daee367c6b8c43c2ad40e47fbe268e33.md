# Audit Report

## Title
LIB Calculation Fails When Insufficient Miners Participated in Previous Round

## Summary
The Last Irreversible Block (LIB) calculation can fail in the current round even when sufficient miners participate, if too few miners mined in the previous round. This occurs because the LIB algorithm retrieves miners who mined in the current round but evaluates their `ImpliedIrreversibleBlockHeight` values from the previous round, filtering out miners with zero heights who didn't participate previously.

## Finding Description

The AEDPoS consensus mechanism calculates LIB by examining miners who successfully mined in the current round and retrieving their implied irreversible block heights from the previous round. The vulnerability exists due to the interaction between several components:

**LIB Calculation Logic**: The `LastIrreversibleBlockHeightCalculator.Deconstruct()` method gets the list of miners who mined in the current round, then looks up their `ImpliedIrreversibleBlockHeight` values from the previous round stored in state. [1](#0-0) 

**Zero Height Filtering**: The `GetSortedImpliedIrreversibleBlockHeights` method explicitly filters out all miners with `ImpliedIrreversibleBlockHeight <= 0`, only considering miners who have positive height values. [2](#0-1) 

**Consensus Threshold Requirement**: The system requires at least `MinersCountOfConsent = (total_miners * 2) / 3 + 1` miners with non-zero heights for successful LIB calculation. [3](#0-2)  If fewer heights are available, LIB returns 0. [4](#0-3) 

**Height Update Mechanism**: Miners only update their `ImpliedIrreversibleBlockHeight` when they successfully mine a block via `ProcessUpdateValue`. [5](#0-4) 

**Execution Scenario** (with 17 miners, requiring 12 for consensus):
- **Round N**: Only 11 out of 17 miners successfully mine blocks. These 11 miners set their `ImpliedIrreversibleBlockHeight` in Round N. The 6 miners who missed retain height=0 in Round N. Round N is saved to state.
- **Round N+1**: All 17 miners successfully participate and mine blocks
- **LIB Calculation in Round N+1**: When miners process their blocks, the LIB calculator retrieves miners who have mined so far in Round N+1, then looks up their heights from Round N (retrieved from state via `TryToGetPreviousRoundInformation`). [6](#0-5) 
- However, if one of these miners was among the 6 who didn't mine in Round N, their height from Round N is 0 and gets filtered out
- Only 11 heights pass the filter, which is less than the required 12
- LIB calculation returns 0, and no `IrreversibleBlockFound` event is fired [7](#0-6) 

The protobuf definition confirms that `implied_irreversible_block_height` defaults to 0 for new `MinerInRound` objects. [8](#0-7) 

When generating the next round, new `MinerInRound` objects are created without copying the `ImpliedIrreversibleBlockHeight` field, causing all miners to start with height=0 in the new round. [9](#0-8) 

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

The issue can be fixed by modifying the LIB calculation to handle miners who participated in the current round but missed the previous round. Two potential solutions:

**Solution 1: Use Current Round Heights When Available**
Modify `GetSortedImpliedIrreversibleBlockHeights` to use heights from the current round if a miner has already set their height in this round, falling back to the previous round only for miners who haven't mined yet in the current round.

**Solution 2: Copy Heights During Round Generation**
When generating the next round, copy the `ImpliedIrreversibleBlockHeight` from the previous round for all miners, ensuring continuity of finality information even for miners who missed their slots.

**Solution 3: Calculate LIB Based on Previous Round Participants**
Instead of using miners who mined in the current round, use miners who mined in the previous round to ensure all referenced heights are non-zero.

## Proof of Concept

Due to the complexity of the AEDPoS consensus system, a full integration test would require:

1. Set up a test network with 17 miners
2. Simulate Round N where only 11 miners successfully mine blocks
3. Ensure Round N is saved with 11 non-zero and 6 zero `ImpliedIrreversibleBlockHeight` values
4. Transition to Round N+1 where all 17 miners participate
5. Observe that when the 12th miner processes their block, if any of the first 12 miners were among the 6 who didn't mine in Round N, the LIB calculation returns 0
6. Verify that no `IrreversibleBlockFound` event is fired

The vulnerability is confirmed through code analysis showing the mismatch between retrieving miners from the current round while using their heights from the previous round, combined with zero-height filtering that removes miners who didn't participate previously.

**Notes**

This is a design-level vulnerability in the AEDPoS consensus LIB calculation algorithm. The issue arises from a temporal mismatch: the algorithm identifies which miners participated in round N+1 but then evaluates their consensus state from round N. When network conditions cause inconsistent participation across rounds, this temporal dependency creates a scenario where current good participation cannot compensate for previous poor participation, resulting in finality stalls even when the network has recovered.

The self-healing nature of this vulnerability (it resolves once miners participate consistently for multiple consecutive rounds) reduces its severity from High to Medium, but it remains a legitimate consensus liveness issue that can impact production blockchain operations during periods of network instability.

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

**File:** protobuf/aedpos_contract.proto (L300-300)
```text
    int64 implied_irreversible_block_height = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```
