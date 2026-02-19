### Title
Incomplete Dataset in LIB Calculation Due to Current Round Miner Filtering

### Summary
The `Deconstruct()` method in `LastIrreversibleBlockHeightCalculator` filters the previous round's `ImpliedIrreversibleBlockHeights` by only including miners who mined in the current round. When exactly `MinersCountOfConsent` miners mine in the current round, but all miners mined in the previous round, the calculation proceeds with an incomplete dataset that excludes valid heights from miners who didn't mine in the current round. This can result in a non-representative (inflated) LIB height being selected, violating the 2/3+1 consensus requirement and potentially compromising cross-chain security.

### Finding Description

The vulnerability exists in the LIB calculation flow: [1](#0-0) 

The root cause is at lines 24-25 where `GetMinedMiners()` retrieves only miners who successfully mined in the **current** round (those with `SupposedOrderOfNextRound != 0`): [2](#0-1) 

These pubkeys are then used to filter the **previous** round's `ImpliedIrreversibleBlockHeights`: [3](#0-2) 

The check at line 26 only verifies that the count meets `MinersCountOfConsent`, which is calculated as `(minerCount * 2 / 3) + 1` based on the current round's total miner count: [4](#0-3) 

**Why protections fail:**

When the current round has 10 total miners, `MinersCountOfConsent = 7`. If exactly 7 miners mine in the current round:
- The check `impliedIrreversibleHeights.Count < 7` passes (7 >= 7)
- However, if all 10 miners mined in the previous round, only 7 heights are considered
- The 3 miners who mined in the previous round but not the current round are excluded

The LIB selection at line 32 uses index `(count-1)/3` to pick a conservative height from the sorted list. With 7 heights instead of 10, the selection becomes biased if the excluded miners had different (particularly lower) heights.

**Execution path:**

This occurs during normal consensus operation when a miner produces a block: [5](#0-4) 

Each miner's `ImpliedIrreversibleBlockHeight` is set when they produce a block: [6](#0-5) 

### Impact Explanation

**Concrete harm:**

1. **Premature Block Finalization**: The LIB can be artificially inflated, marking blocks as irreversible before achieving true 2/3+1 consensus from all miners' views.

2. **Cross-Chain Security Compromise**: The incorrect LIB is used by cross-chain modules: [7](#0-6) 
   
   This triggers system-wide updates that affect cross-chain indexing and verification, potentially allowing unfinalized blocks to be used in cross-chain operations.

3. **Finality Violations**: If blocks marked irreversible are later reorganized (which shouldn't happen but becomes possible with incorrect LIB), it breaks the finality guarantee.

**Quantified example:**
- Previous round: 10 miners mine with heights [100, 101, 102, 150, 151, 152, 153, 154, 155, 156]
- Current round: Only 7 miners (with high heights) mine
- Excluded miners have heights [100, 101, 102]
- **Incorrect LIB**: Index (7-1)/3 = 2 → Height 152
- **Correct LIB**: Index (10-1)/3 = 3 → Height 150
- **Result**: Blocks 151-152 prematurely finalized

**Who is affected:**
- All chain participants relying on LIB guarantees
- Cross-chain operations between parent/side chains
- Applications assuming finality semantics

**Severity justification:** HIGH - Violates core consensus invariant (2/3+1 agreement), impacts cross-chain security, and enables premature finalization with potential for double-spend or reorganization attacks on supposedly final blocks.

### Likelihood Explanation

**Attacker capabilities:**
- No special permissions required
- Miners can naturally miss time slots due to:
  - Network issues
  - Being offline
  - Intentional non-mining (passive attack)
  - Rate limiting or censorship [8](#0-7) 

The code explicitly handles miners who don't mine (incrementing `MissedTimeSlots`), confirming this is an expected scenario.

**Attack complexity:**
- **LOW** - Requires only that certain miners don't produce blocks
- No sophisticated timing or transaction ordering needed
- Can occur naturally without malicious intent
- Coordinated attack: Miners with lower implied heights collectively skip their slots

**Feasibility conditions:**
- System has ≥10 miners (realistic for production)
- Exactly `MinersCountOfConsent` miners mine in current round
- Previous round had more miners mine than current round
- The excluded miners have different height distributions than included miners

**Detection/operational constraints:**
- Difficult to distinguish malicious non-mining from legitimate issues
- LIB appears valid since it passes the count check
- No alerts or validation failures occur

**Probability:** MEDIUM-HIGH - The edge case (exactly `MinersCountOfConsent` miners mining) can occur regularly, especially with network instability or when 30% of miners are experiencing issues.

### Recommendation

**Code-level mitigation:**

Modify `Deconstruct()` to consider ALL miners from the previous round who have valid `ImpliedIrreversibleBlockHeight` values, not just those who mined in the current round:

```csharp
public void Deconstruct(out long libHeight)
{
    if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

    // Get ALL miners from previous round who have implied heights
    var impliedIrreversibleHeights = _previousRound.RealTimeMinersInformation.Values
        .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
        .Select(i => i.ImpliedIrreversibleBlockHeight)
        .ToList();
    
    impliedIrreversibleHeights.Sort();
    
    // Require at least MinersCountOfConsent from PREVIOUS round's miners
    var previousRoundMinersCountOfConsent = _previousRound.MinersCountOfConsent;
    if (impliedIrreversibleHeights.Count < previousRoundMinersCountOfConsent)
    {
        libHeight = 0;
        return;
    }

    libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
}
```

**Invariant checks to add:**
1. Verify LIB calculation considers sufficient historical data
2. Add assertion that LIB doesn't increase beyond safe bounds in a single round
3. Validate that the dataset used for LIB contains at least `MinersCountOfConsent` entries from validators who actually participated in consensus during the measurement period

**Test cases:**
1. Previous round: 10 miners all mine; Current round: exactly 7 mine → Verify all 10 heights considered
2. Varied height distributions with selective non-mining → Verify LIB remains conservative
3. Edge case: Previous round has exactly `MinersCountOfConsent` miners → Verify sufficient data
4. Cross-round miner list changes → Verify LIB calculation handles miner set transitions correctly

### Proof of Concept

**Required initial state:**
- Chain with 10 active miners in consensus
- All miners successfully mine in Round N with varying implied heights

**Transaction steps:**

1. **Round N (Height 1000-1009):**
   - Miner A mines block 1000, sets `ImpliedIrreversibleBlockHeight = 1000`
   - Miner B mines block 1001, sets `ImpliedIrreversibleBlockHeight = 1001`
   - Miner C mines block 1002, sets `ImpliedIrreversibleBlockHeight = 1002`
   - Miners D-J mine blocks 1003-1009 with heights 1003-1009
   - All 10 miners have recorded their heights in Round N

2. **Round N+1 (Height 1010+):**
   - Miners A, B, C intentionally miss their time slots (don't mine)
   - Miners D, E, F, G, H, I, J successfully mine (7 miners)
   - When 7th miner completes their block:
     - `GetMinedMiners()` returns 7 miners (D-J)
     - `GetSortedImpliedIrreversibleBlockHeights` filters Round N by these 7 miners
     - Gets heights: [1003, 1004, 1005, 1006, 1007, 1008, 1009]
     - Count = 7 = `MinersCountOfConsent`, check passes
     - LIB = heights[(7-1)/3] = heights[2] = 1005

**Expected vs actual result:**
- **Expected (correct):** LIB should consider all 10 heights from Round N: [1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009], selecting heights[(10-1)/3] = heights[3] = 1003
- **Actual (vulnerable):** LIB only considers 7 heights: [1003, 1004, 1005, 1006, 1007, 1008, 1009], selecting heights[2] = 1005
- **Delta:** Blocks 1004-1005 are prematurely marked irreversible without true consensus

**Success condition:**
The exploit succeeds when `IrreversibleBlockFound` event is fired with `IrreversibleBlockHeight = 1005` despite blocks 1004-1005 not having achieved 2/3+1 consensus from all validators' perspectives (missing agreement from miners A, B, C who have lower heights).

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L39-56)
```csharp
        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```
