# Audit Report

## Title
Coordinated LIB Denial-of-Service via Zero ImpliedIrreversibleBlockHeight Bypass

## Summary
The `LibInformationValidationProvider` contains a critical validation bypass that allows miners to submit zero `ImpliedIrreversibleBlockHeight` values, circumventing regression checks. When more than one-third of miners exploit this flaw, the Last Irreversible Block (LIB) calculation permanently fails, halting consensus finality and blocking all cross-chain operations.

## Finding Description

The vulnerability exists in the validation logic that verifies whether a miner's reported irreversible block height has regressed. The conditional check was designed to allow new miners (who legitimately have zero initial values) to pass validation without regression checks. However, this creates an exploitable bypass where existing miners can intentionally submit zero values to avoid validation entirely. [1](#0-0) 

The check only validates regression if `ImpliedIrreversibleBlockHeight != 0`. When a miner submits zero, the entire regression check is skipped, allowing the validation to pass.

During normal block production, the system sets a miner's `ImpliedIrreversibleBlockHeight` to the current block height: [2](#0-1) 

After producing their first block, this value should never be zero during honest operation. However, miners control their consensus transaction submissions. When a miner submits an `UpdateValue` transaction, the validation context recovers the attacker-provided value: [3](#0-2) 

This recovered zero value is then stored directly in the round state without additional validation: [4](#0-3) 

The attack propagates to LIB calculation through filtering logic. When computing the LIB for subsequent rounds, the system explicitly excludes zero values: [5](#0-4) 

The LIB calculation requires a minimum threshold of valid (non-zero) heights defined as `MinersCountOfConsent` (two-thirds plus one of all miners): [6](#0-5) 

If insufficient valid heights remain after filtering zeros, the calculation returns zero, indicating LIB progression has failed: [7](#0-6) 

The `UpdateValue` method is publicly accessible, allowing any miner to submit their consensus data: [8](#0-7) 

Pre-execution validation applies `LibInformationValidationProvider` for `UpdateValue` behavior but fails to prevent the zero-value bypass: [9](#0-8) 

## Impact Explanation

**Consensus Finality Breakdown:**
The LIB mechanism is fundamental to AElf's consensus safety. When LIB stops advancing (returns zero), no blocks become irreversible, eliminating finality guarantees. This breaks the core invariant that LIB should monotonically increase (or remain constant), never regressing to zero after having advanced.

**Cross-Chain Operations Blocked:**
Cross-chain indexing critically depends on irreversible block heights for security. The `IrreversibleBlockStateProvider` validates LIB existence before allowing cross-chain operations: [10](#0-9) 

When LIB fails to advance beyond genesis height, this validation returns false, blocking parent-chain data retrieval: [11](#0-10) 

And chain height pair retrieval: [12](#0-11) 

These operations effectively halt all inter-chain asset transfers and communication.

**Quantified Attack Threshold:**
For a network with 21 miners:
- `MinersCountOfConsent = 21 × 2 ÷ 3 + 1 = 15`
- Attack requires 8 colluding miners (>1/3 Byzantine threshold)
- This leaves 13 valid heights, below the required 15
- LIB calculation returns 0, permanently halting finality

**Severity:** Critical - violates fundamental consensus safety properties with protocol-wide operational impact affecting all network participants.

## Likelihood Explanation

**Attacker Capabilities:**
The attack requires coordination among slightly more than one-third of active miners (8 out of 21). This aligns precisely with the Byzantine fault tolerance threshold that distributed consensus systems are designed to tolerate. Miners have complete control over the content of their `UpdateValueInput` messages submitted via the public `UpdateValue` method.

**Attack Complexity:**
Execution is trivial. A malicious miner simply constructs an `UpdateValueInput` with `implied_irreversible_block_height = 0` and submits it during their assigned time slot. No cryptographic manipulation, complex timing attacks, or sophisticated exploits are required. The attack can be sustained indefinitely by repeatedly submitting zero values.

**Feasibility Conditions:**
The standard Byzantine adversary model assumes up to one-third of participants may act maliciously. This vulnerability is exploitable at exactly that threshold, making it feasible under the security assumptions the protocol claims to satisfy. No economic penalties (slashing) exist for this behavior, eliminating deterrence.

**Detection and Attribution:**
While the effect (LIB not advancing) is immediately observable in blockchain state, attributing responsibility to specific miners is difficult when multiple participants simultaneously exhibit the behavior. The protocol lacks mechanisms to penalize or automatically exclude miners engaging in this attack pattern.

## Recommendation

Add explicit validation to reject zero `ImpliedIrreversibleBlockHeight` values from miners who have previously produced blocks:

```csharp
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
{
    var providedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    var baseHeight = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Reject zero values from existing miners who have previously mined
    if (baseHeight > 0 && providedHeight == 0)
    {
        validationResult.Message = "Existing miner cannot submit zero implied lib height.";
        return validationResult;
    }
    
    // Check regression for non-zero values
    if (providedHeight != 0 && baseHeight > providedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
}
```

This ensures that only genuinely new miners (with `baseHeight == 0`) can pass with zero values, while existing miners must maintain non-zero, non-regressing heights.

## Proof of Concept

**Test Setup:** Create a network with 21 miners where 8 colluding miners submit `UpdateValueInput` with `ImpliedIrreversibleBlockHeight = 0`.

**Expected Behavior:** `LibInformationValidationProvider` should reject these submissions to prevent LIB calculation failure.

**Actual Behavior:** 
1. Validation passes because line 24 check (`!= 0`) evaluates to false
2. Zero values are stored in round state
3. `GetSortedImpliedIrreversibleBlockHeights` filters out 8 zeros, leaving 13 valid heights
4. Since 13 < 15 (MinersCountOfConsent), `LastIrreversibleBlockHeightCalculator` returns 0
5. `ValidateIrreversibleBlockExistingAsync` returns false, blocking cross-chain operations

**Result:** LIB advancement halts, consensus finality is broken, cross-chain operations are blocked.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** src/AElf.CrossChain.Core/Indexing/Infrastructure/IrreversibleBlockStateProvider.cs (L30-38)
```csharp
    public async Task<bool> ValidateIrreversibleBlockExistingAsync()
    {
        if (_irreversibleBlockExists)
            return true;
        var libIdHeight = await GetLastIrreversibleBlockHashAndHeightAsync();
        var lastIrreversibleBlockHeight = libIdHeight.BlockHeight;
        _irreversibleBlockExists = lastIrreversibleBlockHeight > AElfConstants.GenesisBlockHeight;
        return _irreversibleBlockExists;
    }
```

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataService.cs (L159-162)
```csharp
        var isReadyToCreateChainCache =
            await _irreversibleBlockStateProvider.ValidateIrreversibleBlockExistingAsync();
        if (!isReadyToCreateChainCache)
            return new ChainIdAndHeightDict();
```

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataService.cs (L275-277)
```csharp
        var libExists = await _irreversibleBlockStateProvider.ValidateIrreversibleBlockExistingAsync();
        if (!libExists)
            return parentChainBlockDataList;
```
