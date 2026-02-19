# Audit Report

## Title
LIB Index Calculation Violates Byzantine Fault Tolerance Threshold

## Summary
The Last Irreversible Block (LIB) height calculation in the AEDPoS consensus contract uses an incorrect index formula that fails to maintain the required 2/3+1 Byzantine Fault Tolerance threshold. When exactly the minimum required number of miners participate, the algorithm selects a block height where only 2/3 (instead of 2/3+1) of miners have confirmed, breaking the consensus safety guarantee.

## Finding Description

The `LastIrreversibleBlockHeightCalculator.Deconstruct()` method calculates the LIB height by retrieving miners who mined in the current round, obtaining their `ImpliedIrreversibleBlockHeight` values from the previous round, sorting them in ascending order, and selecting the height at index `(Count-1)/3`. [1](#0-0) 

The algorithm verifies that the count of participating miners meets the minimum threshold defined as `MinersCountOfConsent = (TotalMiners * 2/3) + 1`. [2](#0-1) 

**Root Cause:** In a sorted ascending array, selecting index `i` means `(Count - i)` miners have reported heights at or above the selected value. For proper BFT consensus requiring at least `MinersCountOfConsent` confirmations, the correct formula should be `i = Count - MinersCountOfConsent` to ensure `Count - i >= MinersCountOfConsent`.

**Mathematical Proof of Failure:**
- For 7 total miners: `MinersCountOfConsent = floor(7 * 2 / 3) + 1 = 5`
- When exactly 5 miners participate (minimum threshold):
  - Current formula: `Index = (5-1)/3 = floor(4/3) = 1`
  - In array [h₀, h₁, h₂, h₃, h₄], selecting index 1 gives h₁
  - Miners with height ≥ h₁: indices {1,2,3,4} = **4 miners**
  - **Required: 5 miners, Actual: 4 miners (VIOLATION)**

The check on line 26 only validates that enough miners participated, but does not ensure the selected index maintains the consensus threshold. [3](#0-2) 

The calculated LIB height is then used to fire an `IrreversibleBlockFound` event that updates the blockchain's finality state. [4](#0-3) 

## Impact Explanation

**Consensus Integrity Violation:** This vulnerability breaks the fundamental Byzantine Fault Tolerance guarantee by allowing the LIB to be set with fewer than 2/3+1 confirmations. The LIB represents the point beyond which blocks are considered irreversible, and this property is critical for:
- Preventing chain reorganizations beyond the LIB
- Ensuring transaction finality
- Cross-chain message reliability (as LIB is used for cross-chain indexing)

**Concrete Security Impact:**
1. **Extended Reorganization Windows:** Blocks that should be finalized remain vulnerable to reorganization attacks
2. **Double-Spend Vulnerability:** Transactions thought to be final may still be reversed if malicious miners exploit the weakened threshold
3. **Cross-Chain Security:** Incorrect LIB affects cross-chain message finality, potentially enabling cross-chain double-spends

**Severity:** High - This directly undermines a fundamental consensus security property (BFT threshold) that the entire blockchain's security model depends upon.

## Likelihood Explanation

**Trigger Conditions:** The vulnerability manifests whenever exactly `MinersCountOfConsent` miners participate in a round, which can occur through:

1. **Natural Occurrence:** Network issues, hardware failures, or maintenance causing exactly the minimum number of miners to successfully mine
2. **Malicious Triggering:** An attacker with network resources can selectively DoS specific miners to reduce participation to exactly the threshold

**Feasibility Assessment:**
- The bug exists in the production consensus logic and executes during normal block processing [5](#0-4) 
- No additional privileges or compromised keys are required
- The condition (exactly MinersCountOfConsent participants) is realistic in distributed networks with occasional connectivity issues
- Public miner lists make targeted attacks feasible [6](#0-5) 

**Likelihood:** Medium-High - While requiring specific conditions (exactly minimum participation), this can occur naturally and is also exploitable by determined attackers.

## Recommendation

Replace the incorrect index calculation formula with the mathematically correct one:

**Current (Incorrect):**
```csharp
libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**Corrected:**
```csharp
libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(_currentRound.MinersCountOfConsent)];
```

This ensures that when the index is selected, at least `MinersCountOfConsent` miners have confirmed heights at or above the selected LIB value, maintaining the 2/3+1 Byzantine Fault Tolerance requirement.

**Additional Validation:** Add an assertion to verify the invariant:
```csharp
var confirmingMiners = impliedIrreversibleHeights.Count - index;
Assert(confirmingMiners >= _currentRound.MinersCountOfConsent, 
    "LIB must have at least MinersCountOfConsent confirmations");
```

## Proof of Concept

```csharp
[Fact]
public void LIB_Calculation_Violates_BFT_Threshold_With_Minimum_Participation()
{
    // Setup: 7 total miners, MinersCountOfConsent = 5
    var totalMiners = 7;
    var minersCountOfConsent = totalMiners * 2 / 3 + 1; // = 5
    
    // Scenario: Exactly 5 miners participate (minimum threshold)
    var impliedHeights = new List<long> { 100, 110, 120, 130, 140 };
    impliedHeights.Sort();
    
    // Current (buggy) formula
    var currentIndex = (impliedHeights.Count - 1) / 3; // = 1
    var selectedLibHeight = impliedHeights[currentIndex]; // = 110
    
    // Count miners that confirmed this height or higher
    var confirmingMiners = impliedHeights.Count - currentIndex; // = 4
    
    // ASSERTION FAILURE: Only 4 miners confirmed, but we need 5
    Assert.True(confirmingMiners >= minersCountOfConsent, 
        $"BFT Violation: Only {confirmingMiners} miners confirmed, " +
        $"but {minersCountOfConsent} required for 2/3+1 consensus");
    
    // Expected behavior with correct formula
    var correctIndex = impliedHeights.Count - minersCountOfConsent; // = 0
    var correctLibHeight = impliedHeights[correctIndex]; // = 100
    var correctConfirmingMiners = impliedHeights.Count - correctIndex; // = 5
    Assert.True(correctConfirmingMiners >= minersCountOfConsent); // PASSES
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```
