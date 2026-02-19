### Title
Insufficient Validation of ImpliedIrreversibleBlockHeight Allows LIB Manipulation by Malicious Miners

### Summary
The `ImpliedIrreversibleBlockHeight` field is copied without upper bound validation, allowing malicious miners to set arbitrarily high values in their block headers. When 1/3 or more miners collude, they can manipulate the Last Irreversible Block (LIB) height to point to non-existent future blocks, violating chain finality guarantees and enabling cross-chain security exploits.

### Finding Description

**Root Cause:** The vulnerability exists because `ImpliedIrreversibleBlockHeight` is copied without validation in multiple locations, and the only validation check does not enforce an upper bound. [1](#0-0) 

The `GetUpdateValueRound()` function copies the `ImpliedIrreversibleBlockHeight` value from the miner's round information without any validation checks.

**Validation Weakness:** The sole validation occurs in `LibInformationValidationProvider`, which only checks that the provided height is not LOWER than the previously stored value: [2](#0-1) 

This validation fails to enforce that `ImpliedIrreversibleBlockHeight` must be less than or equal to `Context.CurrentHeight` or any other reasonable upper bound.

**Intended Behavior:** The contract correctly sets this value during honest block production: [3](#0-2) 

However, miners have full control over their block headers and can provide manipulated consensus extra data instead of using the contract-generated value.

**State Persistence:** The manipulated value is directly assigned to state without additional checks: [4](#0-3) 

**LIB Calculation Impact:** The LIB height is calculated using these miner-provided values: [5](#0-4) 

The calculation takes the (count-1)/3 percentile value from sorted implied heights. With 1/3+ malicious miners providing inflated values, the calculated LIB will be artificially high.

**Validation Context Limitation:** The validation providers lack access to current block height: [6](#0-5) 

The `ConsensusValidationContext` does not include `Context.CurrentHeight`, preventing validation providers from enforcing upper bound checks.

### Impact Explanation

**Chain Finality Violation:** The LIB height represents the last irreversible block height - blocks below this threshold are considered finalized and immutable. Manipulating this to point beyond the actual chain tip breaks the fundamental finality guarantee of the consensus protocol.

**Cross-Chain Security Breach:** Cross-chain contracts rely on LIB for security decisions. When indexing parent/side chain states, they trust that blocks below the reported LIB are irreversible. A manipulated LIB pointing to future blocks could:
- Allow premature finalization of unconfirmed transactions
- Enable double-spend attacks across chains
- Cause incorrect merkle proof verification

**IrreversibleBlockFound Event Exploitation:** The contract fires an `IrreversibleBlockFound` event with the calculated LIB: [7](#0-6) 

External systems (including cross-chain indexers, light clients, and DApp interfaces) consume this event. Broadcasting a LIB height that exceeds the actual chain height corrupts these systems' understanding of chain state.

**Affected Parties:**
- Cross-chain protocols relying on LIB-based finality
- Light clients and SPV systems
- DApps and services that wait for irreversibility
- Chain reorganization protection mechanisms

**Severity Justification:** This is a CRITICAL consensus-layer vulnerability that breaks Byzantine Fault Tolerance assumptions and enables cross-chain exploits with potential for significant value extraction.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an elected miner in the consensus round (realistic for adversarial validators)
- Requires 1/3+ miners for full LIB manipulation (matches Byzantine assumption threshold)
- Single malicious miner can still store inflated values that affect edge cases

**Attack Complexity:** LOW
1. Modify consensus extra data before block production
2. Set `ImpliedIrreversibleBlockHeight` to `CurrentHeight + N` where N is arbitrarily large
3. Create `UpdateValueInput` with same inflated value
4. Submit block with manipulated header and transaction
5. Validation passes (only checks value >= previous value)
6. Repeat for 1/3+ of mining nodes in round

**Execution Practicality:** The attack requires no complex cryptography, timing exploits, or state manipulation. The validation logic simply lacks proper bounds checking.

**Detection/Operational Constraints:** 
- Attack may be detectable by comparing reported LIB with actual chain height
- However, by the time detection occurs, `IrreversibleBlockFound` events have already been broadcast
- Cross-chain state may have already been committed based on false finality signals

**Economic Rationality:** For adversarial validators looking to exploit cross-chain bridges or manipulate finality-dependent protocols, the attack cost is zero (no additional economic stake required beyond being a validator). The potential gain from cross-chain exploits or DApp manipulation could be substantial.

### Recommendation

**1. Add Upper Bound Validation in LibInformationValidationProvider:**

Modify the validation to enforce that `ImpliedIrreversibleBlockHeight` cannot exceed the current block height. Since validation providers don't have direct access to `Context.CurrentHeight`, the validation context must be extended:

```csharp
// In ConsensusValidationContext.cs
public long CurrentBlockHeight { get; set; }

// In AEDPoSContract_Validation.cs - when creating validationContext
CurrentBlockHeight = Context.CurrentHeight,

// In LibInformationValidationProvider.cs - add upper bound check
if (providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > 
    validationContext.CurrentBlockHeight)
{
    validationResult.Message = "ImpliedIrreversibleBlockHeight exceeds current block height.";
    return validationResult;
}
```

**2. Add Sanity Check in ProcessUpdateValue:** [8](#0-7) 

Before line 248, add:
```csharp
Assert(updateValueInput.ImpliedIrreversibleBlockHeight <= Context.CurrentHeight, 
    "ImpliedIrreversibleBlockHeight cannot exceed current height.");
```

**3. Add Bounds Check in LIB Calculation:**

Before firing the `IrreversibleBlockFound` event, verify that `libHeight <= Context.CurrentHeight`:
```csharp
if (libHeight > Context.CurrentHeight)
{
    Context.LogDebug(() => $"Calculated LIB {libHeight} exceeds current height {Context.CurrentHeight}, rejecting.");
    libHeight = currentRound.ConfirmedIrreversibleBlockHeight; // Keep previous value
}
```

**4. Regression Test Cases:**
- Test that miners cannot set `ImpliedIrreversibleBlockHeight > CurrentHeight`
- Test that LIB calculation rejects inflated values
- Test that validation fails when UpdateValue contains future block heights
- Test cross-chain scenarios with manipulated LIB values

### Proof of Concept

**Initial State:**
- Network with 7 miners in current consensus round
- Current block height: 1000
- Current LIB: 990
- 3 miners (43% > 1/3) are malicious colluders

**Attack Sequence:**

1. **Malicious Miner 1 (at height 1001):**
   - Receives mining turn at block 1001
   - Calls `GetConsensusExtraData` to get template (which sets `ImpliedIrreversibleBlockHeight = 1001`)
   - **Manipulates** consensus extra data: sets `ImpliedIrreversibleBlockHeight = 9000`
   - Creates `UpdateValueInput` with `ImpliedIrreversibleBlockHeight = 9000`
   - Submits block with manipulated header and transaction

2. **Validation at Height 1001:**
   - `LibInformationValidationProvider` checks: `baseRound[miner1].ImpliedIrreversibleBlockHeight (0 or 990) > providedRound[miner1].ImpliedIrreversibleBlockHeight (9000)`?
   - Check evaluates to FALSE (990 is not > 9000)
   - **Validation PASSES** ✓
   - Value 9000 is stored in round state

3. **Repeat for Malicious Miners 2 & 3 at subsequent heights:**
   - Each sets `ImpliedIrreversibleBlockHeight` to high values (9000, 9001, 9002)
   - All validations pass

4. **LIB Calculation (triggered by any UpdateValue after 3+ miners produced blocks):**
   - Collects `ImpliedIrreversibleBlockHeight` values from miners in previous round
   - Honest miners: [1001, 1002, 1003, 1004]
   - Malicious miners: [9000, 9001, 9002]
   - Sorted list: [1001, 1002, 1003, 1004, 9000, 9001, 9002]
   - Calculates LIB as `heights[(7-1)/3]` = `heights[2]` = **1003**

**With 1/3+ Threshold Met:**
- If 3+ malicious miners with values in top positions: [1001, 1002, 9000, 9001, 9002, 9003, 9004]
- LIB calculation: `heights[(7-1)/3]` = `heights[2]` = **9000**

**Expected vs Actual Result:**
- **Expected:** `ImpliedIrreversibleBlockHeight` rejected as > CurrentHeight during validation
- **Actual:** Value accepted, stored, and used in LIB calculation
- **Result:** `IrreversibleBlockFound` event fires with `IrreversibleBlockHeight = 9000` when actual chain height is ~1005

**Success Condition:** 
Cross-chain indexers and contracts receive `IrreversibleBlockFound(9000)` event, causing them to treat blocks up to height 9000 as finalized, even though these blocks don't exist yet. This breaks finality assumptions and enables cross-chain exploits.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L29-29)
```csharp
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L8-41)
```csharp
public class ConsensusValidationContext
{
    public long CurrentTermNumber { get; set; }
    public long CurrentRoundNumber { get; set; }

    /// <summary>
    ///     We can trust this because we already validated the pubkey
    ///     during `AEDPoSExtraDataExtractor.ExtractConsensusExtraData`
    /// </summary>
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();

    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;

    /// <summary>
    ///     Previous round information fetch from StateDb.
    /// </summary>
    public Round PreviousRound { get; set; }

    /// <summary>
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
    public LatestPubkeyToTinyBlocksCount LatestPubkeyToTinyBlocksCount { get; set; }

    public AElfConsensusHeaderInformation ExtraData { get; set; }
}
```
