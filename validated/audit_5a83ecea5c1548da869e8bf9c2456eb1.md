# Audit Report

## Title
LIB Height Deflation Attack via Malicious ImpliedIrreversibleBlockHeight Reporting

## Summary
The AEDPoS consensus contract fails to validate that miners report reasonable `ImpliedIrreversibleBlockHeight` values close to the current block height. Malicious miners can report artificially low values (e.g., 1) which pass validation, and with approximately one-third of miners colluding, they can prevent the Last Irreversible Block (LIB) from advancing, eliminating finality guarantees and disrupting cross-chain operations.

## Finding Description

The vulnerability exists in the LIB calculation and validation mechanism of the AEDPoS consensus system.

**Attack Flow:**

1. When honest miners produce blocks, they set `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` during block production [1](#0-0) 

2. This value is packaged into `UpdateValueInput` [2](#0-1) 

3. During validation, `LibInformationValidationProvider` only checks that the new value does not decrease from the miner's previous report [3](#0-2) 

4. The value is directly assigned without any bounds checking [4](#0-3) 

5. The LIB is calculated by sorting all `ImpliedIrreversibleBlockHeight` values and selecting the value at index `(count - 1) / 3` [5](#0-4) 

**Exploitation:**

A malicious miner can modify their consensus node to report `ImpliedIrreversibleBlockHeight = 1` (or any low positive value) instead of `Context.CurrentHeight`. This passes validation because:
- It's not zero (filtered out by `GetSortedImpliedIrreversibleBlockHeights`) [6](#0-5) 
- It doesn't decrease from previous reports (satisfies the only validation check)
- There is no upper or lower bound validation

With approximately N/3 malicious miners (where N is the total miner count) reporting artificially low heights, the LIB calculation's selection at index `(N-1)/3` will pick one of these low values instead of a legitimate height.

**No Detection Mechanism:**

The evil miner detection logic only identifies miners who miss time slots, not those reporting incorrect LIB heights [7](#0-6) 

## Impact Explanation

This vulnerability has **HIGH** impact because it breaks fundamental consensus integrity guarantees:

1. **Finality Loss**: The LIB (Last Irreversible Block) is the foundation of transaction finality in AElf. An artificially low LIB means blocks above that height remain reversible indefinitely, eliminating finality guarantees that users and applications depend on.

2. **Cross-Chain Disruption**: Cross-chain operations rely on LIB heights for verification and indexing. An artificially low LIB renders cross-chain bridges and parent-child chain communications inoperable.

3. **Reorganization Risk**: A low LIB allows potential reorganization of recent blocks that should be irreversible, creating uncertainty about transaction permanence and potentially enabling double-spend attacks if reorganizations can be coordinated.

4. **Economic Impact**: The loss of finality guarantees undermines the blockchain's utility for any application requiring transaction certainty (financial settlements, asset transfers, governance decisions).

**Concrete Example**: With 7 miners, if 3 malicious miners report height 1, the LIB becomes 1 (selection index: (7-1)/3 = 2, the 3rd lowest value). All blocks at height 2+ cannot be finalized.

## Likelihood Explanation

The likelihood is **MEDIUM-HIGH** because:

**Attacker Requirements:**
- Must control approximately 1/3 of the elected miner set (standard Byzantine fault tolerance assumption)
- Must be actively participating miners (not requiring privilege escalation)

**Attack Complexity:**
- **Low**: Attackers simply modify their consensus node software to report a constant low value instead of `Context.CurrentHeight`
- No timing coordination needed beyond normal mining participation
- No need to exploit complex race conditions or edge cases

**No Countermeasures:**
- Zero detection mechanisms for incorrect LIB reporting
- No slashing or economic penalties for malicious values
- No reputation system tracking LIB reporting accuracy
- Validation only enforces monotonicity, not reasonableness

**Realistic Preconditions:**
- The 1/3 Byzantine actor threshold is the standard threat model for BFT consensus systems
- Miners have full control over their node software and can modify reported values
- The attack can be sustained indefinitely once initiated

## Recommendation

Implement bounds validation on `ImpliedIrreversibleBlockHeight` in the `LibInformationValidationProvider`:

```csharp
// Add to LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0)
{
    var providedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    var currentHeight = validationContext.CurrentHeight; // Need to add to context
    
    // Validate the reported height is within reasonable bounds
    // Allow some lag, but not arbitrary low values
    var maxAllowedLag = 1000; // Configurable parameter
    
    if (providedHeight < currentHeight - maxAllowedLag)
    {
        validationResult.Message = "ImpliedIrreversibleBlockHeight too far behind current height.";
        return validationResult;
    }
    
    // Also ensure it doesn't exceed current height
    if (providedHeight > currentHeight)
    {
        validationResult.Message = "ImpliedIrreversibleBlockHeight cannot exceed current height.";
        return validationResult;
    }
    
    // Existing non-decrease check
    if (baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > providedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
}
```

Additionally:
1. Extend evil miner detection to track LIB reporting accuracy
2. Implement slashing for miners consistently reporting suspiciously low values
3. Add monitoring and alerting for LIB advancement stalls

## Proof of Concept

The vulnerability can be proven by creating a test that:

1. Deploys the consensus contract with 7 miners
2. Has 3 malicious miners report `ImpliedIrreversibleBlockHeight = 1` in their UpdateValue transactions
3. Has 4 honest miners report `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` (e.g., 1000)
4. Verifies that the malicious values pass validation (non-decrease check only)
5. Calls the LIB calculation and verifies it returns 1 instead of a value near 1000
6. Demonstrates that blocks at height 2+ cannot be finalized

The test would verify that:
- Malicious UpdateValue inputs with `ImpliedIrreversibleBlockHeight = 1` pass `LibInformationValidationProvider` validation
- The LIB calculation selects the value at index `(7-1)/3 = 2`, which is 1 (from the 3 malicious miners)
- The `ConfirmedIrreversibleBlockHeight` remains at 1 despite the blockchain progressing to height 1000+

This proves the vulnerability is exploitable and has the claimed impact on finality.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L48-48)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```
