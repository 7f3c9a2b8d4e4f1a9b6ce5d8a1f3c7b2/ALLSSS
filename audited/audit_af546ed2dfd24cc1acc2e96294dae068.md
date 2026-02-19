# Audit Report

## Title
Unreasonably High ImpliedIrreversibleBlockHeight Causes Consensus DoS via Arithmetic Overflow

## Summary
A malicious miner can inject an arbitrarily high `ImpliedIrreversibleBlockHeight` value that bypasses validation, corrupts the consensus contract state, and causes all subsequent consensus operations to fail with an `OverflowException`, permanently halting block production.

## Finding Description

The AEDPoS consensus contract allows miners to report their view of the implied irreversible block height during block production. However, the validation and processing logic contains a critical flaw that enables a permanent denial-of-service attack.

**Attack Execution Path:**

1. **Normal Flow**: When generating consensus data, the contract sets `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` [1](#0-0) 

2. **Malicious Injection**: A malicious miner can modify their consensus header information to include an arbitrarily high value (e.g., 999999999999) before submitting their block. This value flows through `ExtractInformationToUpdateConsensus` [2](#0-1)  into the `UpdateValueInput`.

3. **Validation Bypass**: The `LibInformationValidationProvider` only validates that the implied height is non-decreasing [3](#0-2)  but does NOT check if the value exceeds `Context.CurrentHeight`. The validation only ensures: `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` returns false.

4. **State Corruption**: `ProcessUpdateValue` directly stores the malicious value without bounds checking [4](#0-3) 

5. **LIB Calculation**: The `LastIrreversibleBlockHeightCalculator.Deconstruct` method selects the bogus value at the 1/3 consensus threshold position without validation [5](#0-4) 

6. **State Persistence**: The corrupted value is stored in `currentRound.ConfirmedIrreversibleBlockHeight` and persisted [6](#0-5) 

7. **Event Processor Limitation**: While `IrreversibleBlockFoundLogEventProcessor` validates that blocks exist before updating the chain's LIB [7](#0-6) , this validation occurs AFTER the contract state has already been corrupted and persisted.

**DoS Trigger Mechanism:**

Every consensus transaction calls `GetMaximumBlocksCount` [8](#0-7) , which reads the corrupted `ConfirmedIrreversibleBlockHeight` [9](#0-8)  and attempts to calculate `currentHeight.Sub(libBlockHeight)` [10](#0-9) 

Since `SafeMath.Sub` uses checked arithmetic [11](#0-10) , when `libBlockHeight > currentHeight`, an `OverflowException` is thrown, causing all subsequent consensus operations to fail.

**Permanent Damage**: The check `if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)` [12](#0-11)  prevents any future legitimate LIB updates from overwriting the bogus value, since all legitimate `libHeight` calculations will be less than the malicious value.

## Impact Explanation

**CRITICAL - Complete Blockchain Availability Failure**

This vulnerability enables a single malicious miner to permanently halt the entire blockchain:

- **Block Production Stopped**: Every consensus transaction throws an `OverflowException` in `GetMaximumBlocksCount`, preventing any new blocks from being produced
- **All Operations Cease**: Token transfers, governance actions, cross-chain operations, and all other contract executions become impossible
- **Irreversible Corruption**: The corrupted state persists permanently because the protection check prevents legitimate updates from fixing it
- **Network-Wide Impact**: All users, validators, applications, and dependent chains are affected
- **No Automatic Recovery**: Requires emergency intervention via hard fork or contract upgrade to restore functionality

The miner privilege check [13](#0-12)  only validates that the sender is in the miner list, not the validity of the consensus data they provide.

## Likelihood Explanation

**HIGH - Single Malicious Miner Can Execute At Will**

- **Low Barrier**: Requires only miner privileges (elected/staked participants in the consensus)
- **Simple Execution**: Single transaction with one modified field value
- **No Coordination**: Attacker acts alone without needing other miners' cooperation
- **Deterministic**: Attack succeeds reliably once executed
- **Silent Corruption**: State corrupts on first block, damage manifests on second block
- **No Countermeasures**: No monitoring or runtime checks can prevent the attack since validation happens after state update

Any active miner can execute this attack by modifying their consensus client to inject arbitrary `ImpliedIrreversibleBlockHeight` values, bypassing the normal flow that sets it to `Context.CurrentHeight`.

## Recommendation

Add upper bound validation in `LibInformationValidationProvider` to ensure `ImpliedIrreversibleBlockHeight` does not exceed a reasonable threshold based on `Context.CurrentHeight`:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0)
{
    var impliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
    
    // Validate non-decreasing
    if (baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight > impliedHeight)
    {
        validationResult.Message = "Incorrect implied lib height.";
        return validationResult;
    }
    
    // NEW: Validate upper bound - must not exceed current height
    if (impliedHeight > validationContext.ExtraData.Height)
    {
        validationResult.Message = "Implied lib height exceeds current block height.";
        return validationResult;
    }
}
```

Additionally, add defensive bounds checking in `ProcessUpdateValue` before storing:

```csharp
// Validate ImpliedIrreversibleBlockHeight before storage
Assert(updateValueInput.ImpliedIrreversibleBlockHeight <= Context.CurrentHeight, 
       "ImpliedIrreversibleBlockHeight cannot exceed current height.");

minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

## Proof of Concept

This vulnerability can be demonstrated by:

1. Deploy a test network with multiple miners
2. Modify one miner's consensus client to inject `ImpliedIrreversibleBlockHeight = Context.CurrentHeight + 1000000000000`
3. Submit an `UpdateValue` transaction with the malicious data
4. Observe that the transaction succeeds and state is updated
5. Attempt to produce the next block
6. Observe that `GetMaximumBlocksCount` throws `OverflowException`
7. Verify that no further blocks can be produced
8. Confirm that legitimate LIB updates cannot fix the corrupted state due to the comparison check

The attack succeeds because validation only checks non-decreasing property, not upper bounds against current blockchain height.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L68-68)
```csharp
        var minersCountInTheory = GetMaximumBlocksCount();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-272)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L279-284)
```csharp
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L63-65)
```csharp
            var libBlockHash = await _blockchainService.GetBlockHashByHeightAsync(chain,
                irreversibleBlockFound.IrreversibleBlockHeight, block.GetHash());
            if (libBlockHash == null) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L26-26)
```csharp
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L63-63)
```csharp
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-97)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
```
