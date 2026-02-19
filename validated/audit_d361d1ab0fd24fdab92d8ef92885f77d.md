# Audit Report

## Title
Incomplete Block Finalization During Term Transition Due to Mismatch Between Term Change Criteria and LIB Calculation

## Summary
The AEDPoS consensus mechanism contains a critical design flaw where term transitions can occur before sufficient miners produce `UpdateValue` blocks to finalize the Last Irreversible Block (LIB). This happens because `NeedToChangeTerm` counts all miners with `ActualMiningTimes` (including TinyBlock-only producers), while LIB calculation only considers miners who produced `UpdateValue` blocks, creating a mismatch that leaves blocks from the terminated round unfinalized.

## Finding Description

The vulnerability stems from inconsistent criteria used for term transition decisions versus LIB finalization calculations across the consensus contract.

**Root Cause - Different Counting Mechanisms:**

The `NeedToChangeTerm` method counts miners based solely on `ActualMiningTimes` regardless of block type: [1](#0-0) 

However, `ActualMiningTimes` is updated by BOTH consensus behaviors:
- `ProcessUpdateValue` adds to it: [2](#0-1) 

- `ProcessTinyBlock` also adds to it: [3](#0-2) 

**Critical Difference in Field Updates:**

`ProcessTinyBlock` does NOT set `SupposedOrderOfNextRound` or `ImpliedIrreversibleBlockHeight`: [4](#0-3) 

But `ProcessUpdateValue` DOES set both fields: [5](#0-4) 

**LIB Calculation Exclusion:**

The `GetMinedMiners` method used in LIB calculation filters out TinyBlock-only producers: [6](#0-5) 

The LIB calculation uses `GetMinedMiners` and fails when insufficient miners are counted: [7](#0-6) 

**No LIB Recalculation During Term Transition:**

The `ProcessNextTerm` method does not trigger any LIB calculation. LIB calculation ONLY occurs in `ProcessUpdateValue`: [8](#0-7) 

When generating the next round, the old LIB value is simply copied forward: [9](#0-8) 

**Triggerable Scenario:**

In a network with 7 miners (MinersCountOfConsent = 5):
1. During Round N approaching term boundary, 3 miners produce `UpdateValue` blocks (setting `SupposedOrderOfNextRound != 0`)
2. 2 additional miners (extra block producers) produce only `TinyBlock` blocks (leaving `SupposedOrderOfNextRound = 0`)
3. All 5 miners have `ActualMiningTimes` past the term period boundary
4. `NeedToChangeTerm` returns true (5 >= 5) because it counts all miners with `ActualMiningTimes` [10](#0-9) 
5. A miner generates and executes `NextTerm` command
6. The last LIB calculation used only 3 miners' heights (from `GetMinedMiners`)
7. Since 3 < 5 (MinersCountOfConsent), `libHeight = 0` was returned, leaving blocks unfinalized
8. Term transition proceeds with stale LIB value

## Impact Explanation

**Consensus Integrity Violation (Critical):**
This vulnerability directly undermines the fundamental consensus guarantee that blocks should reach irreversible status after 2/3+1 miner confirmation. Blocks from the terminated round remain unfinalized indefinitely, violating the core safety property of the consensus mechanism.

**Cross-Chain Security Compromise:**
The cross-chain contract relies on LIB heights for verification. Stale or zero LIB values can:
- Block valid cross-chain transactions from being verified
- Create synchronization inconsistencies between parent and side chains
- Prevent cross-chain token transfers and message passing

**Block Finality Guarantee Failure:**
Applications and smart contracts that depend on block finality guarantees will experience:
- Transactions remaining in an unconfirmed state longer than protocol specifications
- Potential for reorganization of blocks that should be irreversible under normal consensus rules
- Inconsistent chain state interpretation across nodes

This is a **Critical** severity issue because it affects the entire blockchain's security model at the consensus layer, potentially impacting all dependent systems and breaking core protocol guarantees.

## Likelihood Explanation

**High Likelihood - Can Occur During Normal Operation:**

This is not an attack scenario but a design flaw that can manifest during routine consensus operation:

1. **Extra Block Producers Naturally Produce TinyBlocks:** The consensus mechanism allows designated extra block producers to produce TinyBlocks in their extended time slots. This is a normal and expected behavior: [11](#0-10) 

2. **No Special Privileges Required:** Any miner operating according to protocol rules can trigger this condition. No malicious behavior or compromised keys are needed.

3. **Term Boundary Alignment:** The issue becomes more likely when:
   - Multiple miners are designated as extra block producers
   - Network conditions or timing cause some miners to produce only TinyBlocks near term boundaries
   - The term period naturally expires while some miners have only produced TinyBlocks

4. **Detection Difficulty:** The vulnerability may go unnoticed because:
   - Term transitions complete successfully
   - Consensus data is properly sent to the Election contract
   - Only the LIB height remains stale, which may not trigger immediate monitoring alerts
   - Block production continues normally in the new term

**Feasibility: HIGH** - This can happen during any term transition period when miner participation timing varies, which is common in distributed consensus systems.

## Recommendation

The fix requires ensuring that LIB is properly calculated before term transitions, or alternatively, adjusting the term change criteria to match the LIB calculation requirements.

**Option 1: Trigger LIB Calculation in ProcessNextTerm**

Add LIB calculation logic at the beginning of `ProcessNextTerm` before creating the next round:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // Add LIB calculation before term transition
    if (TryToGetCurrentRoundInformation(out var currentRound) && 
        TryToGetPreviousRoundInformation(out var previousRound))
    {
        new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
            out var libHeight);
        if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
        {
            Context.Fire(new IrreversibleBlockFound
            {
                IrreversibleBlockHeight = libHeight
            });
            currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
            currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            TryToUpdateRoundInformation(currentRound);
        }
    }
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of ProcessNextTerm
}
```

**Option 2: Align NeedToChangeTerm with LIB Requirements**

Modify `NeedToChangeTerm` to only count miners who produced `UpdateValue` blocks:

```csharp
public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
{
    return RealTimeMinersInformation.Values
               .Where(m => m.SupposedOrderOfNextRound != 0) // Only count UpdateValue producers
               .Where(m => m.ActualMiningTimes.Any())
               .Select(m => m.ActualMiningTimes.Last())
               .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                   t, currentTermNumber, periodSeconds))
           >= MinersCountOfConsent;
}
```

**Option 3: Ensure Minimum UpdateValue Blocks Before Term Change**

Add an additional check that sufficient miners have produced `UpdateValue` blocks:

```csharp
protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
{
    if (CurrentRound.RoundNumber == 1) return AElfConsensusBehaviour.NextRound;
    
    var updateValueMinersCount = CurrentRound.RealTimeMinersInformation.Values
        .Count(m => m.SupposedOrderOfNextRound != 0);
    
    if (updateValueMinersCount < CurrentRound.MinersCountOfConsent)
        return AElfConsensusBehaviour.NextRound; // Not enough UpdateValue blocks yet
    
    return !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
               CurrentRound.TermNumber, _periodSeconds) ||
           CurrentRound.RealTimeMinersInformation.Keys.Count == 1
        ? AElfConsensusBehaviour.NextRound
        : AElfConsensusBehaviour.NextTerm;
}
```

## Proof of Concept

The vulnerability can be demonstrated with a test that:
1. Sets up a network with 7 miners (MinersCountOfConsent = 5)
2. Has 3 miners produce UpdateValue blocks
3. Has 2 miners produce only TinyBlock blocks
4. Advances time past the term boundary
5. Triggers NextTerm
6. Verifies that LIB was not properly updated due to insufficient UpdateValue producers

The core issue is architecturally embedded in the mismatch between `NeedToChangeTerm` (counting `ActualMiningTimes` from any block type) and `GetMinedMiners` (filtering by `SupposedOrderOfNextRound` which is only set by UpdateValue blocks), combined with the absence of LIB recalculation in `ProcessNextTerm`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-248)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```
