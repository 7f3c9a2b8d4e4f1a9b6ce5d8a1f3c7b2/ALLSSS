# Audit Report

## Title
Missing Upper Bound Validation on ImpliedIrreversibleBlockHeight Allows LIB Calculation Manipulation

## Summary
The AEDPoS consensus contract fails to validate that `ImpliedIrreversibleBlockHeight` does not exceed `Context.CurrentHeight` when miners submit consensus updates. This allows malicious miners to inject inflated values that can cause the Last Irreversible Block (LIB) mechanism to fire events with invalid future block heights, leading to silent failures in LIB advancement and stalling the finality mechanism.

## Finding Description

The vulnerability exists in the consensus update flow where miners submit their view of the irreversible block height without proper bounds checking.

During normal block generation, the system correctly sets `ImpliedIrreversibleBlockHeight` to the current block height: [1](#0-0) 

However, when processing the UpdateValue transaction, the value is accepted directly from the input without validating it against the current height: [2](#0-1) 

The only validation that exists checks that the value did not decrease, but **does not validate an upper bound**: [3](#0-2) 

In subsequent rounds, these potentially inflated values from the previous round are used to calculate the global LIB: [4](#0-3) 

If the calculated LIB exceeds the current blockchain height, the system fires an `IrreversibleBlockFound` event with an invalid future height: [5](#0-4) 

When the event processor attempts to retrieve the block hash at this non-existent future height, it receives null and silently returns without updating the LIB: [6](#0-5) 

This breaks the security guarantee that the LIB mechanism should reliably advance and accurately reflect the finalized state of the blockchain.

## Impact Explanation

**Consensus Safety Violation:**
The LIB (Last Irreversible Block) is a critical consensus safety mechanism that determines which blocks are finalized and cannot be reverted. When malicious miners inject inflated `ImpliedIrreversibleBlockHeight` values:

1. With > 1/3 miner collusion (exceeding the 33% Byzantine fault tolerance threshold), the LIB calculation can produce heights that exceed the actual blockchain height
2. Invalid `IrreversibleBlockFound` events are fired with future block heights
3. The event processor silently fails when attempting to retrieve non-existent blocks
4. Legitimate LIB advancement stalls, preventing finality from progressing

**Systemic Impact:**
- **Cross-Chain Operations:** Cross-chain indexing and verification depend on LIB heights for determining finalized state. Stalled LIB values delay cross-chain transaction processing and can cause synchronization inconsistencies
- **Transaction Pool Management:** Systems that prune transaction pools based on LIB will malfunction
- **State Finalization:** Services depending on finalized state become unreliable
- **Network Synchronization:** Nodes may disagree on finalized state

**Severity Justification:**
This is a **HIGH severity** vulnerability because it:
- Directly undermines a core consensus safety mechanism
- Affects the reliability of blockchain finality
- Has cascading effects on cross-chain and downstream systems
- Violates fundamental invariants about irreversible block heights

While full exploitation requires > 1/3 miner collusion (beyond standard BFT assumptions), even a single compromised miner can inject inflated values that contribute to potential future LIB calculation errors or cause invalid event emissions.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an active miner in the consensus set (requires stake and election)
- For full LIB manipulation: requires > 1/3 of miners to collude
- For causing invalid LIB events and potential stalls: single malicious miner can inject inflated values

**Technical Feasibility:**
- **Low complexity:** Simply requires modifying the `UpdateValueInput.ImpliedIrreversibleBlockHeight` field when producing blocks
- **No cryptographic bypass needed:** The validation logic demonstrably lacks the upper bound check
- **Direct attack vector:** The entry point is the standard `UpdateValue` consensus transaction used during block production
- **Validation bypass:** The `LibInformationValidationProvider` only checks for non-decreasing values, not upper bounds

**Detection Difficulty:**
- Inflated values are stored directly in consensus state without flagging
- LIB advancement stalls would be noticeable but root cause unclear without deep investigation  
- Invalid event emissions fail silently in the processor

**Economic Considerations:**
- Requires miner status (stake requirements and election)
- For full LIB manipulation: requires controlling > 1/3 of miner stakes (significant economic cost)
- For griefing attacks causing LIB stalls: lower barrier (single compromised miner)
- No immediate economic gain for attacker, but can disrupt consensus and cross-chain operations

**Overall Likelihood:** **MEDIUM-LOW** due to the requirement for miner privileges, but the technical attack path is straightforward once that privilege is obtained.

## Recommendation

Add validation in `LibInformationValidationProvider` to ensure `ImpliedIrreversibleBlockHeight` does not exceed the current block height during validation:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0)
{
    var impliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Existing check: ensure it didn't decrease
    if (baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > impliedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
    
    // NEW: ensure it doesn't exceed current height
    if (impliedHeight > validationContext.CurrentHeight)
    {
        validationResult.Message = "Implied lib height exceeds current block height.";
        return validationResult;
    }
}
```

Additionally, add a defensive check in `ProcessUpdateValue` before firing the `IrreversibleBlockFound` event:

```csharp
// In AEDPoSContract_ProcessConsensusInformation.ProcessUpdateValue
if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
{
    // NEW: ensure calculated LIB doesn't exceed current height
    if (libHeight <= Context.CurrentHeight)
    {
        Context.LogDebug(() => $"New lib height: {libHeight}");
        Context.Fire(new IrreversibleBlockFound
        {
            IrreversibleBlockHeight = libHeight
        });
        currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
        currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
    }
    else
    {
        Context.LogWarning(() => $"Calculated LIB {libHeight} exceeds current height {Context.CurrentHeight}");
    }
}
```

## Proof of Concept

A malicious miner can exploit this vulnerability by:

1. Modifying their consensus node to generate blocks with `UpdateValueInput.ImpliedIrreversibleBlockHeight` set to an inflated value (e.g., `Context.CurrentHeight + 1000`)
2. The block passes validation since `LibInformationValidationProvider` only checks the value didn't decrease
3. The inflated value is stored in the consensus state
4. In subsequent rounds, when `LastIrreversibleBlockHeightCalculator` runs with this inflated value from the previous round, it can calculate a LIB height exceeding the current blockchain height (especially with > 1/3 miner collusion)
5. The `IrreversibleBlockFound` event is fired with an invalid future height
6. The `IrreversibleBlockFoundLogEventProcessor` attempts to get the block hash at the non-existent height, receives null, and silently returns without updating LIB
7. The LIB mechanism stalls, preventing finality advancement

The vulnerability is confirmed by the absence of validation at the identified code locations and the demonstrated execution path from malicious input to system impact.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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
