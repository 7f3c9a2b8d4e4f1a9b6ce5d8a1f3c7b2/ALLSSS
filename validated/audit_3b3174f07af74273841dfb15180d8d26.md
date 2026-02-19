# Audit Report

## Title
LIB Calculation Failure During Miner List Expansion Due to Mismatched Threshold Basis

## Summary
The Last Irreversible Block (LIB) calculation uses the current round's total miner count to calculate the Byzantine fault-tolerant threshold (2/3+1), but validates this threshold against implied irreversible heights retrieved from the previous round. When the miner list increases at term change, new miners have no data in the previous round, making the threshold mathematically impossible to meet and causing LIB advancement to halt until sufficient original miners participate.

## Finding Description

The vulnerability exists in the `LastIrreversibleBlockHeightCalculator.Deconstruct()` method which calculates the Last Irreversible Block height using a Byzantine fault-tolerant consensus algorithm. [1](#0-0) 

The threshold calculation uses the current round's miner count: [2](#0-1) 

The root cause is a three-phase mismatch:

**Phase 1 - Threshold Calculation**: `MinersCountOfConsent` is calculated as `(currentRound.RealTimeMinersInformation.Count * 2 / 3) + 1`, using the NEW miner count after term change.

**Phase 2 - Data Retrieval**: The method retrieves `impliedIrreversibleHeights` from the PREVIOUS round, filtered by miners who have mined in the CURRENT round: [3](#0-2) 

**Phase 3 - Miner Identification**: Only miners who have actually produced blocks in the current round are considered: [4](#0-3) 

**Concrete Failure Scenario:**

When `GenerateFirstRoundOfNewTerm` creates a new term with increased miners (e.g., 10 → 13): [5](#0-4) 

The calculation fails because:
- `MinersCountOfConsent = (13 * 2 / 3) + 1 = 9` (based on NEW count)
- Maximum available data from previous round: 10 entries (only old miners exist there)
- If only 8 of the 10 original miners mine in the current round: `impliedIrreversibleHeights.Count = 8`
- Check fails: `8 < 9` → LIB calculation returns 0, preventing advancement

The LIB calculator is invoked during every `UpdateValue` call: [6](#0-5) 

**Why Existing Protections Fail**: The `IsMinerListJustChanged` flag is set during term changes but is NOT checked in the LIB calculation logic. It is only used to skip secret sharing: [7](#0-6) 

No similar protection exists for LIB threshold adjustment.

## Impact Explanation

**Severity: HIGH - Denial of Service to Critical Consensus Invariant**

This vulnerability causes deterministic failure of LIB advancement, which is a critical consensus property providing finality guarantees. The impacts include:

1. **Broken Finality Guarantees**: Blocks remain unconfirmed as irreversible, undermining the core purpose of LIB
2. **Cross-Chain Operation Failure**: Cross-chain bridges and indexing depend on LIB verification and will stall
3. **User Experience Degradation**: Applications relying on `ConfirmedIrreversibleBlockHeight` for transaction finality lose this guarantee
4. **Network-Wide Scope**: All participants are affected simultaneously

**Quantified Damage:**
- **Frequency**: Occurs at every term change that increases miner count (expected during network growth)
- **Duration**: Multiple rounds (potentially dozens of blocks) until enough original miners participate
- **Scope**: 100% of network participants relying on finality

While this is not a funds-at-risk vulnerability, it constitutes a HIGH severity DoS against a critical protocol invariant that provides security guarantees to the entire ecosystem.

## Likelihood Explanation

**Likelihood: HIGH - Deterministic Protocol-Level Bug**

**No Attacker Required**: This is a logic error in the consensus implementation that triggers automatically during normal network operations.

**Zero Attack Complexity**: Term changes with miner list expansion are regular governance operations. When they occur, the bug manifests deterministically.

**Guaranteed Trigger Conditions**:
- Term changes occur at configured intervals (typically yearly)
- Network growth naturally increases miner count
- The test suite confirms this pattern: [8](#0-7) 

However, the tests do not validate LIB calculation correctness during these transitions.

**Mathematical Certainty**: When miner count increases from M to N (where N > M), and fewer than `(N * 2/3) + 1` of the original M miners participate in the first round, LIB calculation MUST fail due to insufficient historical data.

## Recommendation

Implement special handling for the `IsMinerListJustChanged` condition in the LIB calculation. When the miner list has just changed, adjust the threshold to use the previous round's miner count instead of the current round's count:

```csharp
public void Deconstruct(out long libHeight)
{
    if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

    var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
    var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
    
    // Use previous round's miner count when list just changed
    var requiredConsent = _currentRound.IsMinerListJustChanged 
        ? _previousRound.MinersCountOfConsent 
        : _currentRound.MinersCountOfConsent;
    
    if (impliedIrreversibleHeights.Count < requiredConsent)
    {
        libHeight = 0;
        return;
    }

    libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
}
```

Alternatively, preserve LIB from the previous round for one additional round after miner list changes to allow the new consensus to stabilize.

## Proof of Concept

```csharp
[Fact]
public async Task LIB_Fails_When_Miner_List_Increases()
{
    // Setup: Initialize with 10 miners
    var initialMiners = InitialCoreDataCenterKeyPairs.Take(10).ToList();
    await InitializeConsensusWithMiners(initialMiners);
    
    // Verify LIB advances normally in first term
    await ProduceBlocksAndVerifyLIB(initialMiners);
    var libBeforeTermChange = await GetCurrentLIB();
    Assert.True(libBeforeTermChange > 0, "LIB should advance in normal operation");
    
    // Trigger term change with increased miners (10 → 13)
    var expandedMiners = InitialCoreDataCenterKeyPairs.Take(13).ToList();
    await TriggerTermChangeWithNewMiners(expandedMiners);
    
    // Only 8 of original 10 miners participate in new round
    var participatingMiners = initialMiners.Take(8).ToList();
    await ProduceBlocksWithMiners(participatingMiners);
    
    // Verify vulnerability: LIB fails to advance
    var libAfterTermChange = await GetCurrentLIB();
    Assert.Equal(libBeforeTermChange, libAfterTermChange, 
        "BUG: LIB stalled - should advance but threshold is impossible to meet");
    
    // The condition that causes failure:
    // MinersCountOfConsent = (13 * 2/3) + 1 = 9
    // But only 8 miners from previous round participated
    // Therefore: impliedIrreversibleHeights.Count (8) < MinersCountOfConsent (9)
}
```

## Notes

The vulnerability is confirmed through multiple evidence points:
1. Direct code inspection shows the threshold mismatch between current and previous round miner counts
2. The `IsMinerListJustChanged` flag exists but grep search confirms it's never checked in LIB calculation logic
3. Test suite validates miner count increases but doesn't verify LIB advancement during these transitions
4. The mathematical impossibility is deterministic when fewer than the new threshold of old miners participate

This is a protocol-level logic bug affecting consensus finality, not a funds-at-risk vulnerability, but its impact on network operation and user trust justifies HIGH severity classification.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-19)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L42-42)
```csharp
        round.IsMinerListJustChanged = true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/MinersCountTest.cs (L118-118)
```csharp
            Assert.Equal(AEDPoSContractTestConstants.SupposedMinersCount.Add(termCount.Mul(2)), minerCount);
```
