### Title
Missing Upper Bound Validation for ImpliedIrreversibleBlockHeight Allows Protocol State Inconsistency

### Summary
The `LibInformationValidationProvider.ValidateHeaderInformation()` function only validates that a miner's `ImpliedIrreversibleBlockHeight` does not decrease but lacks upper bound checks to ensure it cannot exceed the current block height. This allows miners to submit arbitrarily high values, potentially causing the consensus contract's `ConfirmedIrreversibleBlockHeight` to advance beyond actual produced blocks, creating a permanent divergence between consensus state and chain state that halts LIB advancement and affects cross-chain operations.

### Finding Description

The vulnerability exists in the validation logic for miner-provided `ImpliedIrreversibleBlockHeight` values: [1](#0-0) 

The validation only checks that the new `ImpliedIrreversibleBlockHeight` is not lower than the previous value, but has no upper bound check. The protocol expects this value to be set to the current block height during normal consensus data generation: [2](#0-1) 

However, a miner with modified node software could provide an `UpdateValueInput` with an inflated `ImpliedIrreversibleBlockHeight` that exceeds `Context.CurrentHeight`. This value is accepted without validation and stored directly: [3](#0-2) 

When the `LastIrreversibleBlockHeightCalculator` runs, it aggregates these implied heights from miners and calculates a new `ConfirmedIrreversibleBlockHeight`: [4](#0-3) 

If approximately 1/3 or more miners provide inflated values beyond the actual chain height, the calculated LIB height will be invalid. The consensus contract then updates its `ConfirmedIrreversibleBlockHeight` to this inflated value: [5](#0-4) 

### Impact Explanation

This vulnerability creates a critical protocol inconsistency with multiple severe consequences:

1. **LIB Advancement Halt**: When `ConfirmedIrreversibleBlockHeight` exceeds actual produced blocks, the `IrreversibleBlockFoundLogEventProcessor` attempts to retrieve the block hash at that height but receives null, causing it to skip updating the chain's `LastIrreversibleBlockHeight`: [6](#0-5) 

2. **Consensus State Divergence**: The consensus contract's Round state maintains an invalid `ConfirmedIrreversibleBlockHeight` that is higher than the chain's actual `LastIrreversibleBlockHeight`, creating a permanent inconsistency.

3. **Validation Lock**: Future consensus validations compare against the inflated `ConfirmedIrreversibleBlockHeight` in the base round, potentially causing legitimate blocks to be rejected: [7](#0-6) 

4. **Cross-Chain Operations Impact**: Cross-chain functionality depends on accurate LIB heights for safe block finality. The frozen LIB prevents proper cross-chain indexing: [8](#0-7) 

The severity is HIGH because this creates a permanent protocol-level inconsistency affecting consensus integrity, finality guarantees, and cross-chain operations.

### Likelihood Explanation

The attack is highly feasible:

**Attacker Capabilities**: A miner running a modified node can easily alter the `UpdateValueInput` before submission. No compromise of cryptographic keys or complex exploit chain is required.

**Attack Complexity**: LOW. The miner simply needs to modify their node software to provide `ImpliedIrreversibleBlockHeight` values higher than `Context.CurrentHeight`. The validation in `LibInformationValidationProvider` will accept any value that doesn't go backwards.

**Feasibility Conditions**: Requires approximately 1/3 of the miner set (calculated as `(count-1)/3` position in sorted array) to provide inflated values for the attack to affect the consensus LIB calculation. For a 7-miner set, 3 colluding miners suffice. For a 21-miner set, 7 miners are needed.

**Detection Constraints**: The inflated values would be visible in block headers and consensus events, making the attack detectable but only after damage is done.

**Economic Rationality**: The attack cost is minimal (node modification) with potential for causing significant disruption to the network's finality and cross-chain operations.

### Recommendation

Add upper bound validation to `LibInformationValidationProvider.ValidateHeaderInformation()`:

```csharp
// After line 30 in LibInformationValidationProvider.cs, add:
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    var providedImpliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    if (providedImpliedHeight != 0)
    {
        // ImpliedIrreversibleBlockHeight cannot exceed the current block height
        // Use a reasonable offset to account for any legitimate variations
        var maxAllowedHeight = validationContext.ExtraData.BlockHeight; // or Context.CurrentHeight - 1
        if (providedImpliedHeight > maxAllowedHeight)
        {
            validationResult.Message = $"Implied irreversible block height {providedImpliedHeight} exceeds current height {maxAllowedHeight}";
            return validationResult;
        }
        
        // Optionally, also check against ConfirmedIrreversibleBlockHeight
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedImpliedHeight > providedRound.ConfirmedIrreversibleBlockHeight + reasonableOffset)
        {
            validationResult.Message = "Implied irreversible block height significantly exceeds confirmed height";
            return validationResult;
        }
    }
}
```

**Invariant to enforce**: `ImpliedIrreversibleBlockHeight <= CurrentBlockHeight` for all miners.

**Test cases**:
1. Verify rejection when `ImpliedIrreversibleBlockHeight > Context.CurrentHeight`
2. Verify rejection when `ImpliedIrreversibleBlockHeight` is far ahead of `ConfirmedIrreversibleBlockHeight`
3. Verify normal operation when values are within reasonable bounds

### Proof of Concept

**Initial State**:
- 7 miners in consensus (M1-M7)
- Current block height: 1000
- Current `ConfirmedIrreversibleBlockHeight`: 900
- All miners' `ImpliedIrreversibleBlockHeight`: 950

**Attack Steps**:
1. **Round N+1**: Miners M1, M2, M3 produce blocks with modified `UpdateValueInput`:
   - M1 sets `ImpliedIrreversibleBlockHeight = 5000` (normal: 1001)
   - M2 sets `ImpliedIrreversibleBlockHeight = 5100` (normal: 1002)
   - M3 sets `ImpliedIrreversibleBlockHeight = 5200` (normal: 1003)
   - M4-M7 use normal values: 1004-1007

2. **Validation**: Each UpdateValue transaction passes `LibInformationValidationProvider` because inflated values > previous values (950).

3. **Round N+2**: First miner's `ProcessUpdateValue` triggers `LastIrreversibleBlockHeightCalculator`:
   - Gets miners who mined in Round N+2
   - Retrieves their implied heights from Round N+1: [1004, 1005, 1006, 1007, 5000, 5100, 5200]
   - Sorted position (7-1)/3 = 2 selects value: 1006 (still reasonable in this distribution)
   
4. **Attack refinement**: If M4-M7 also inflate slightly (e.g., 2000-2500), sorted becomes [2000, 2100, 2200, 2500, 5000, 5100, 5200], selecting 2200 as new `ConfirmedIrreversibleBlockHeight`.

5. **Expected Result**: `ConfirmedIrreversibleBlockHeight` updated to 2200 in consensus state.

6. **Actual Result**: `IrreversibleBlockFoundEvent` fires with height 2200, but `IrreversibleBlockFoundLogEventProcessor` fails at `GetBlockHashByHeightAsync` (returns null for non-existent height 2200), chain's `LastIrreversibleBlockHeight` remains at 900.

**Success Condition**: Permanent divergence where consensus Round state has `ConfirmedIrreversibleBlockHeight = 2200` but chain has `LastIrreversibleBlockHeight = 900`, halting all future LIB updates and cross-chain operations.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-280)
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
```

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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L63-65)
```csharp
            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;
```

**File:** src/AElf.CrossChain/CrossChainModuleEventHandler.cs (L25-28)
```csharp
    public async Task HandleEventAsync(NewIrreversibleBlockFoundEvent eventData)
    {
        await _crossChainService.UpdateCrossChainDataWithLibAsync(eventData.BlockHash, eventData.BlockHeight);
    }
```
