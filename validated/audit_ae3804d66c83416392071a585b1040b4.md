# Audit Report

## Title
Incorrect LIB Index Calculation Violates 2/3 Consensus Threshold in AEDPoS

## Summary
The Last Irreversible Block (LIB) height calculation uses an incorrect index formula `(Count - 1) / 3` that fails to ensure 2/3+ consensus when the count of implied irreversible heights equals `MinersCountOfConsent`. This allows blocks to be finalized with as low as 57% miner agreement instead of the required 67%, fundamentally violating the Byzantine Fault Tolerance guarantee of the consensus protocol.

## Finding Description

The vulnerability exists in the `LastIrreversibleBlockHeightCalculator.Deconstruct()` method that calculates which block height should be marked as irreversible. [1](#0-0) 

The `MinersCountOfConsent` threshold is defined as `(TotalMiners * 2) / 3 + 1`, representing the minimum number of miners needed for consensus. [2](#0-1) 

**Root Cause:**

The algorithm verifies that at least `MinersCountOfConsent` miners have provided implied irreversible heights, then selects the height at index `(Count - 1) / 3` from the sorted list. This index calculation is mathematically incorrect for ensuring 2/3 consensus.

In a sorted ascending list of n heights `[H₀, H₁, H₂, ..., Hₙ₋₁]`, selecting index i means (n - i) miners reported heights ≥ Hᵢ. With the current formula:
- Index = (n - 1) / 3
- Agreeing miners = n - (n - 1) / 3 = (2n + 1) / 3

When n = MinersCountOfConsent = (TotalMiners × 2/3) + 1:
- **7 total miners**: MinersCountOfConsent = 5, index = 1, agreeing = 4 miners (4/7 = 57%)
- **10 total miners**: MinersCountOfConsent = 7, index = 2, agreeing = 5 miners (5/10 = 50%)

Both scenarios fall below the required 67% threshold (2/3 + 1) for Byzantine Fault Tolerance.

**Why Existing Protections Fail:**

The guard at line 26 only ensures sufficient miners have mined, but does not validate that the selected index provides 2/3 consensus on the resulting height. [3](#0-2) 

The validation provider only checks that LIB doesn't decrease, not that it's correctly calculated. [4](#0-3) 

## Impact Explanation

**Severity: HIGH - Consensus Integrity Violation**

When the LIB is advanced without proper 2/3 consensus, the system's fundamental security guarantees are broken:

1. **Byzantine Fault Tolerance Breakdown**: BFT consensus assumes up to 1/3 of nodes can be malicious or faulty. With only 57% agreement, a coordinated attack by 43% of miners could compromise finality guarantees.

2. **Irreversible Block Compromise**: The incorrectly calculated LIB is used to fire the `IrreversibleBlockFound` event, which updates the chain's canonical last irreversible block height. [5](#0-4) 

3. **System-Wide Cascading Impact**: The LIB height affects multiple critical subsystems including state finalization, transaction pool pruning, cross-chain verification, and governance proposal cleanup. Premature finalization could lead to state inconsistencies across the network.

4. **Cross-Chain Security**: Side chains and cross-chain bridges rely on the main chain's LIB for security. Incorrectly finalized blocks could be used as merkle proof anchors, propagating the consensus weakness to connected chains.

## Likelihood Explanation

**Likelihood: HIGH - Natural Occurrence During Normal Operation**

1. **Reachable Entry Point**: The vulnerable code path is triggered when any miner calls the public `UpdateValue` method during normal block production. [6](#0-5) 

2. **Frequent Condition**: The vulnerable scenario occurs when exactly `MinersCountOfConsent` miners have successfully mined blocks in the current round. With 7 miners, this means exactly 5 must have mined - a common situation during normal consensus rounds, especially when some miners experience temporary network issues or delays.

3. **No Attack Required**: This is a deterministic logic bug that manifests during legitimate protocol execution. No malicious actor is needed to trigger it - it happens naturally based on mining participation rates.

4. **Silent Failure**: The miscalculation produces a valid block height that passes all existing validation checks, making it undetectable without deep mathematical analysis of the consensus guarantees.

5. **Persistent Risk**: This occurs repeatedly across every consensus round where exactly `MinersCountOfConsent` miners participate, making it a continuous rather than one-time vulnerability.

## Recommendation

The index selection formula must be corrected to ensure at least 2/3 of **total** miners agree on the selected height, not just 2/3 of the miners who have provided heights.

**Correct Formula:**
For ensuring (TotalMiners × 2/3 + 1) miners agree on height Hᵢ in a sorted list of n heights:
- Required: n - i ≥ MinersCountOfConsent
- Therefore: i ≤ n - MinersCountOfConsent
- When n = MinersCountOfConsent: i = 0 (select the minimum height)

**Recommended Fix:**
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

    // Correct: Select index where at least MinersCountOfConsent miners agree
    var index = impliedIrreversibleHeights.Count.Sub(_currentRound.MinersCountOfConsent);
    libHeight = impliedIrreversibleHeights[index];
}
```

This ensures that when exactly `MinersCountOfConsent` miners have mined (the minimum required), we select index 0 (the lowest height), meaning all participating miners agree on heights ≥ the selected height, providing the full 2/3+ consensus.

## Proof of Concept

**Test Scenario: 7 Total Miners, Exactly 5 Have Mined**

Setup:
- Total miners in consensus: 7
- MinersCountOfConsent = (7 × 2) / 3 + 1 = 5
- Miners who have mined: exactly 5
- Their implied irreversible heights (sorted): [100, 150, 200, 250, 300]

Current Vulnerable Behavior:
- Check passes: 5 ≥ 5 ✓
- Index = (5 - 1) / 3 = 1
- Selected height: 150 (H₁)
- Miners agreeing (height ≥ 150): 4 miners at indices [1,2,3,4]
- Consensus: 4/7 = 57.14% < 67% ✗ **BFT VIOLATED**

Expected Correct Behavior:
- Index = 5 - 5 = 0
- Selected height: 100 (H₀)
- Miners agreeing (height ≥ 100): 5 miners at indices [0,1,2,3,4]
- Consensus: 5/7 = 71.43% ≥ 67% ✓ **BFT SATISFIED**

The proof demonstrates that the current implementation can finalize blocks with only 57% consensus, breaking the fundamental 2/3 Byzantine Fault Tolerance guarantee that is critical for blockchain security.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
