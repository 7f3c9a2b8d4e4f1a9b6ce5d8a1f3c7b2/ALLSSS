### Title
Missing Upper Bound Validation for ImpliedIrreversibleBlockHeight Allows Consensus State Pollution

### Summary
The `LibInformationValidationProvider` only validates that `ImpliedIrreversibleBlockHeight` does not decrease, but fails to check if miners claim unreasonably high values exceeding the current block height. [1](#0-0)  While a downstream safeguard prevents updating the chain's LIB to non-existent blocks, the false values are still stored in consensus contract state, potentially affecting cross-chain operations and future validations.

### Finding Description

The vulnerability exists in the consensus validation flow. When miners produce blocks with `UpdateValue` behavior, they include an `ImpliedIrreversibleBlockHeight` value representing their view of the last irreversible block.

The expected behavior sets this value to the current block height: [2](#0-1) 

However, miners can modify consensus extra data before block submission. The validation in `LibInformationValidationProvider` only rejects values that are LOWER than previously recorded: [1](#0-0) 

This allows miners to claim arbitrarily high values (e.g., `Context.CurrentHeight + 1000000`), which pass validation and are stored in state: [3](#0-2) 

These false values are then used in LIB calculation: [4](#0-3) 

The calculated LIB is stored in consensus state: [5](#0-4) 

### Impact Explanation

**Consensus State Pollution**: False `ConfirmedIrreversibleBlockHeight` values are permanently stored in consensus contract state, violating the invariant that LIB heights should reflect actual consensus finality.

**Future Validation Weakening**: Subsequent blocks' validation checks against the polluted base round values: [6](#0-5)  allowing further invalid states to propagate.

**Cross-Chain Security Risk**: Cross-chain operations rely on LIB information from the consensus contract. [7](#0-6)  False LIB values could impact cross-chain verification integrity.

**Public State Exposure**: The polluted values are exposed through view methods, misleading external consumers about chain finality status.

While `IrreversibleBlockFoundLogEventProcessor` prevents the blockchain service's LIB from advancing to non-existent blocks, [8](#0-7)  the consensus contract's internal state remains corrupted, affecting consensus integrity and cross-chain operations.

### Likelihood Explanation

**Attacker Capability**: Any active miner in the miner list can execute this attack during normal block production.

**Attack Complexity**: LOW - Miners simply modify the `ImpliedIrreversibleBlockHeight` field in consensus extra data before block submission. No special timing or coordination required.

**Feasibility**: The attack is immediately executable. Miners control the consensus extra data content and the validation does not enforce the expected invariant that `ImpliedIrreversibleBlockHeight` should equal the mining block height.

**Detection**: The attack is difficult to detect as the values appear valid (non-decreasing) to the validation logic and only manifest as incorrect consensus state.

**Economic Cost**: None beyond normal mining operations. No additional transaction fees or locked funds required.

### Recommendation

Add an upper bound check in `LibInformationValidationProvider.ValidateHeaderInformation()`:

```csharp
// After line 30, add:
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > validationContext.ExtraData.BlockHeight)
{
    validationResult.Message = "Implied lib height cannot exceed current block height.";
    return validationResult;
}
```

Note: `validationContext.ExtraData.BlockHeight` should be added to track the current block height during validation, or use an alternative mechanism to verify the provided value matches the expected mining height.

**Test Cases**:
1. Reject blocks where `ImpliedIrreversibleBlockHeight > Context.CurrentHeight`
2. Reject blocks where `ImpliedIrreversibleBlockHeight < baseRound` value (existing check)
3. Accept blocks where `ImpliedIrreversibleBlockHeight == Context.CurrentHeight` (normal case)

### Proof of Concept

**Initial State**:
- Blockchain at height 1000
- Miner M is in the active miner list
- M has previously mined with `ImpliedIrreversibleBlockHeight = 950`

**Attack Steps**:
1. M produces block at height 1001
2. M generates consensus extra data via normal flow (would set `ImpliedIrreversibleBlockHeight = 1001`)
3. M modifies the consensus data, setting `ImpliedIrreversibleBlockHeight = 2000000` (far beyond chain tip)
4. M includes modified consensus data in block header
5. Block undergoes validation via `ValidateConsensusBeforeExecution` [9](#0-8) 
6. `LibInformationValidationProvider` checks: `950 > 2000000` = false, validation passes
7. Block is accepted and `ProcessUpdateValue` stores: `minerInRound.ImpliedIrreversibleBlockHeight = 2000000`

**Expected Result**: Validation should reject the block with "Implied lib height cannot exceed current block height"

**Actual Result**: Block is accepted, consensus state is polluted with false value `2000000`, which will be used in future LIB calculations

**Success Condition**: Query `GetCurrentRoundInformation` and verify miner M's `ImpliedIrreversibleBlockHeight = 2000000` despite blockchain only being at height 1001

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-281)
```csharp
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

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataService.cs (L1-1)
```csharp
using System.Collections.Generic;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L63-65)
```csharp
            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```
