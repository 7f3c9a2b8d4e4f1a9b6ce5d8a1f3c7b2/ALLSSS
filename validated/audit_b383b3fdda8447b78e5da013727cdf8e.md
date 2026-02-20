# Audit Report

## Title
LIB Index Calculation Violates Byzantine Fault Tolerance Threshold

## Summary
The Last Irreversible Block (LIB) height calculation in the AEDPoS consensus contract uses an incorrect index formula that fails to maintain the required 2/3+1 Byzantine Fault Tolerance threshold. When exactly the minimum required number of miners participate, the algorithm selects a block height where only 2/3 (instead of 2/3+1) of miners have confirmed, breaking the consensus safety guarantee.

## Finding Description

The `LastIrreversibleBlockHeightCalculator.Deconstruct()` method calculates the LIB by selecting a height at index `(Count-1)/3` from a sorted ascending array of implied irreversible block heights reported by miners who participated in the current round. [1](#0-0) 

The system defines the minimum consensus threshold as `MinersCountOfConsent = (TotalMiners * 2/3) + 1`, representing the 2/3+1 supermajority required for Byzantine Fault Tolerance. [2](#0-1) 

**Root Cause**: In a sorted ascending array, selecting index `i` means that `(Count - i)` miners have reported heights at or above the selected value. To ensure at least `MinersCountOfConsent` confirmations, the formula must satisfy: `Count - i >= MinersCountOfConsent`, which means `i <= Count - MinersCountOfConsent`. The correct index should be `i = Count - MinersCountOfConsent`.

**Mathematical Proof of Violation**:
- For 7 total miners: `MinersCountOfConsent = floor(7 * 2 / 3) + 1 = 5`
- When exactly 5 miners participate (minimum threshold):
  - Current formula: `Index = (5-1)/3 = 1`
  - Array: [h₀, h₁, h₂, h₃, h₄]
  - Selecting index 1 gives h₁
  - Miners confirming height ≥ h₁: {1,2,3,4} = **4 miners** (indices 1-4)
  - **Required: 5 miners, Actual: 4 miners → VIOLATION**

The validation check only ensures sufficient miners participated but does not verify the selected index maintains the consensus threshold. [3](#0-2) 

The calculated LIB is then propagated via an `IrreversibleBlockFound` event that updates the blockchain's finality state throughout the system. [4](#0-3) 

## Impact Explanation

**Consensus Integrity Violation**: This vulnerability breaks the fundamental Byzantine Fault Tolerance guarantee by allowing the LIB to be set with fewer than 2/3+1 confirmations. The LIB represents the point beyond which blocks are considered irreversible—a critical property for:
- Preventing chain reorganizations beyond the LIB
- Ensuring transaction finality guarantees
- Cross-chain message reliability (LIB is used for cross-chain indexing)

**Concrete Security Impacts**:
1. **Extended Reorganization Windows**: Blocks prematurely marked as final remain vulnerable to reorganization if Byzantine miners exploit the weakened threshold
2. **Double-Spend Risk**: Transactions considered final may be reversed if malicious actors coordinate to reorganize the chain
3. **Cross-Chain Security Degradation**: Incorrect LIB affects cross-chain message finality verification, potentially enabling cross-chain double-spend attacks

**Severity**: High - This directly undermines a fundamental consensus security property (BFT 2/3+1 threshold) that the blockchain's entire security model depends upon. The system is designed to tolerate up to 1/3 Byzantine failures, but this bug reduces the actual safety margin below the required threshold.

## Likelihood Explanation

**Trigger Conditions**: The vulnerability manifests whenever exactly `MinersCountOfConsent` miners participate in a round. This occurs when:

1. **Natural Occurrence**: Network congestion, hardware failures, or scheduled maintenance causing exactly the minimum number of miners to successfully produce blocks
2. **Malicious Triggering**: An attacker with sufficient network resources can selectively DoS specific miners to reduce participation to exactly the threshold

**Feasibility Assessment**:
- The vulnerable code executes during normal consensus block processing [5](#0-4) 
- No special privileges or compromised keys required—any miner can trigger via normal `UpdateValue` transactions
- The condition (exactly `MinersCountOfConsent` participants) is realistic in distributed networks with occasional connectivity issues
- Miner lists are publicly accessible, making targeted network attacks feasible [6](#0-5) 

**Likelihood**: Medium-High - While requiring a specific condition (exactly minimum participation), this can occur naturally during network instability and is exploitable by determined attackers with network-level capabilities.

## Recommendation

Replace the index calculation formula to ensure the BFT threshold is maintained:

**Current (Incorrect)**:
```
libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**Corrected**:
```
libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(_currentRound.MinersCountOfConsent)];
```

This ensures that when selecting a height, at least `MinersCountOfConsent` miners have confirmed heights at or above the selected value, maintaining the 2/3+1 BFT guarantee.

**Additional Validation**: Add an assertion to verify the invariant:
```csharp
var selectedIndex = impliedIrreversibleHeights.Count.Sub(_currentRound.MinersCountOfConsent);
Assert(selectedIndex >= 0, "Invalid LIB calculation: insufficient confirmations");
libHeight = impliedIrreversibleHeights[selectedIndex];
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

```csharp
// Setup: 7 total miners, MinersCountOfConsent = 5
// Scenario: Exactly 5 miners participate (minimum threshold)

var impliedHeights = new List<long> { 100, 150, 200, 250, 300 }; // 5 miners

// Current (buggy) calculation:
var buggyIndex = (5 - 1) / 3; // = 1
var buggyLIB = impliedHeights[buggyIndex]; // = 150

// Miners confirming height >= 150: indices {1,2,3,4} = 4 miners
// VIOLATION: Only 4 confirmations instead of required 5

// Correct calculation:
var correctIndex = 5 - 5; // = 0
var correctLIB = impliedHeights[correctIndex]; // = 100

// Miners confirming height >= 100: indices {0,1,2,3,4} = 5 miners
// VALID: Exactly 5 confirmations as required
```

**Expected Result**: With exactly 5 participating miners (the minimum threshold for 7 total miners), the current implementation selects a LIB height confirmed by only 4 miners, violating the 2/3+1 BFT requirement. The correct implementation would select a height confirmed by all 5 participating miners.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

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

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
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
