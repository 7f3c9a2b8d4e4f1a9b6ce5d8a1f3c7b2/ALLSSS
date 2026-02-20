# Audit Report

## Title
Byzantine Fault Tolerance Violation in Last Irreversible Block Height Calculation Due to Insufficient Confirmation Threshold

## Summary
The Last Irreversible Block (LIB) height calculation uses an index selection formula that results in blocks being marked as irreversible with fewer confirmations than required for Byzantine fault tolerance. When exactly `MinersCountOfConsent` miners participate, the selected LIB is confirmed by only `(count - floor((count-1)/3))` miners, which is less than the BFT-required `(n - floor((n-1)/3))` miners for networks with n ≥ 5 miners.

## Finding Description

The vulnerability exists in the `LastIrreversibleBlockHeightCalculator` where the index selection formula incorrectly uses the participating miner count instead of ensuring BFT-safe confirmation thresholds. [1](#0-0) 

The threshold `MinersCountOfConsent` is calculated as `floor(n * 2 / 3) + 1`: [2](#0-1) 

**Root Cause:** When exactly `MinersCountOfConsent` miners participate, the code selects the LIB at index `floor((count-1)/3)`. This means only `count - floor((count-1)/3)` miners have confirmed that height or higher, which is insufficient for BFT safety.

**Mathematical Proof:**

For **n=5 total miners**:
- Byzantine tolerance: f = floor(4/3) = 1
- BFT requires: 5 - 1 = **4 confirmations**
- MinersCountOfConsent = floor(10/3) + 1 = **4 miners**
- When exactly 4 miners report: index = floor(3/3) = 1
- Confirmations = 4 - 1 = **3 miners**
- **3 < 4 → Violates BFT**

For **n=7 total miners**:
- Byzantine tolerance: f = floor(6/3) = 2
- BFT requires: 7 - 2 = **5 confirmations**
- MinersCountOfConsent = floor(14/3) + 1 = **5 miners**
- When exactly 5 miners report: index = floor(4/3) = 1
- Confirmations = 5 - 1 = **4 miners**
- **4 < 5 → Violates BFT**

Each miner sets their `ImpliedIrreversibleBlockHeight` during block production: [3](#0-2) 

The LIB is calculated and stored during consensus processing: [4](#0-3) 

The existing validation only checks that LIB doesn't decrease: [5](#0-4) 

## Impact Explanation

**Consensus Safety Violation:** The LIB mechanism provides finality guarantees by marking blocks as irreversible. By allowing blocks to be marked irreversible with insufficient confirmations, the system violates its Byzantine fault tolerance guarantees.

**Cross-Chain Impact:** Cross-chain systems rely on LIB for finality. The cross-chain indexing infrastructure uses the LIB to determine when blocks are safe to index, as evidenced by the `IrreversibleBlockStateProvider` and cross-chain event handling. If the LIB is set prematurely with insufficient confirmations, cross-chain operations could be based on blocks that are not truly irreversible.

**Attack Scenario (n=7 miners):**
1. Two Byzantine miners (within the f=2 tolerance) strategically abstain from mining
2. Five honest miners (meeting `MinersCountOfConsent` threshold) participate
3. LIB is calculated with only 4 confirmations instead of the BFT-required 5
4. This weakens the finality guarantee below the Byzantine fault tolerance threshold
5. Affects cross-chain finality and potentially enables fork-related attacks

This is **HIGH severity** because it undermines a fundamental consensus safety guarantee that cross-chain systems depend upon for finality.

## Likelihood Explanation

**Attacker Requirements:**
- Control f = floor((n-1)/3) Byzantine miners (standard Byzantine assumption)
- Coordinate abstention behavior (trivial - simply don't mine blocks)
- No privileged access required beyond normal miner capabilities

**Attack Feasibility:** HIGH
- Byzantine miners can force exactly `MinersCountOfConsent` participation by abstaining
- Abstention is indistinguishable from legitimate network issues or downtime  
- The vulnerability triggers automatically once the participation condition is met
- No complex timing or state manipulation required

**Detection Difficulty:** HIGH
- No validation checks the actual confirmation count against total miner count
- Byzantine behavior (not mining) appears identical to honest nodes with connectivity issues
- The system operates normally from a state machine perspective

**Probability:** Medium-to-High for networks with n ≥ 5 miners where this gap exists.

## Recommendation

The index selection formula should be modified to ensure the selected LIB has confirmations from at least `n - floor((n-1)/3)` miners, regardless of how many miners actually participated.

**Suggested Fix:**

Change the index calculation to account for the total number of miners rather than just the participating count:

```csharp
// Instead of using (count - 1) / 3, calculate the index based on total miners
var totalMiners = _currentRound.RealTimeMinersInformation.Count;
var requiredConfirmations = totalMiners - (totalMiners - 1) / 3;
var index = impliedIrreversibleHeights.Count - requiredConfirmations;

// Ensure we don't go out of bounds
if (index < 0)
{
    libHeight = 0;
    return;
}

libHeight = impliedIrreversibleHeights[index];
```

Alternatively, increase the `MinersCountOfConsent` threshold to ensure sufficient confirmations when the minimum is met, or add an additional validation check that ensures the selected LIB has the BFT-required number of confirmations.

## Proof of Concept

A test case demonstrating this issue would:

1. Set up a network with n=7 miners
2. Have exactly 5 miners (MinersCountOfConsent) participate and provide implied irreversible heights
3. Calculate the LIB using the current formula
4. Verify that only 4 miners confirmed the selected height (below the BFT requirement of 5)
5. Demonstrate that this violates the expected Byzantine fault tolerance guarantee

The mathematical proof provided in the Finding Description demonstrates that this issue occurs deterministically when exactly `MinersCountOfConsent` miners participate in networks with n ≥ 5 miners.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-32)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```
