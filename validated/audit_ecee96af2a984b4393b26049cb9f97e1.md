# Audit Report

## Title
Broken Validation Allows Miners to Manipulate ImpliedIrreversibleBlockHeight and Suppress LIB Finality

## Summary
The AEDPoS consensus validation flow contains a critical ordering bug where `RecoverFromUpdateValue` is called before validation, causing the `LibInformationValidationProvider` to compare the provided value against itself rather than the original state value. This allows miners to arbitrarily manipulate their `ImpliedIrreversibleBlockHeight`, and with 1/3+ colluding miners, they can suppress the Last Irreversible Block (LIB) advancement indefinitely, breaking finality guarantees.

## Finding Description

The vulnerability exists in the validation flow for consensus block production. When a miner produces a block, the intended behavior is to set `ImpliedIrreversibleBlockHeight` to the current block height. [1](#0-0) 

However, the validation process has a critical flaw. Before validation occurs, `ValidateBeforeExecution` calls `RecoverFromUpdateValue` which mutates the `baseRound` object by copying values from the provided round: [2](#0-1) 

This recovery operation overwrites the original `ImpliedIrreversibleBlockHeight` value from state: [3](#0-2) 

Subsequently, the `LibInformationValidationProvider` performs validation by comparing `baseRound` (already modified) against `providedRound`: [4](#0-3) 

Since `baseRound[pubkey].ImpliedIrreversibleBlockHeight` was just set to equal `providedRound[pubkey].ImpliedIrreversibleBlockHeight` by the recovery operation, this check compares the value against itself and always passes. The validation is completely ineffective.

A malicious miner can exploit this by:
1. Modifying both the block header's `Round.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight`
2. Modifying the transaction's `UpdateValueInput.ImpliedIrreversibleBlockHeight` to the same arbitrary value
3. Producing and signing the block with these manipulated values

The manipulated value is then stored directly without any upper bound validation: [5](#0-4) 

This stored value influences the LIB calculation, which sorts all miners' implied heights and selects the value at index `(count-1)/3`: [6](#0-5) 

Critically, there is **no validation** that:
- `ImpliedIrreversibleBlockHeight <= Context.CurrentHeight` (preventing future heights)
- `ImpliedIrreversibleBlockHeight == Context.CurrentHeight` (enforcing correct value)

## Impact Explanation

**LIB Suppression (1/3+ Miners):**
With the LIB calculation taking the value at index `(count-1)/3` from a sorted list, if 1/3 or more miners set artificially low `ImpliedIrreversibleBlockHeight` values (e.g., 0 or slowly increasing values), the selected LIB value will be suppressed. For a network with 21 miners, 7+ miners setting low values will place a low value at the 7th position (index 6), effectively preventing LIB advancement.

This has severe consequences:
- **Breaks finality guarantees:** Legitimate blocks remain reversible indefinitely
- **Enables double-spend attacks:** Without finality, long-range reorganizations become possible
- **Stalls cross-chain operations:** Cross-chain bridges rely on LIB for confirmation
- **Undermines economic security:** Applications requiring finality (DeFi, payments, etc.) become unreliable

**Severity: Critical** - This breaks a fundamental blockchain security guarantee that protects against reorganization attacks and ensures transaction irreversibility.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be an elected miner through the DPoS voting system
- Need to control approximately 1/3+ of elected miners for significant impact (7 out of 21 miners in typical configuration)

**Attack Complexity:**
- **Very Low:** The attack is trivial to execute - simply modify the `ImpliedIrreversibleBlockHeight` values in both block header and transaction before signing
- **No Detection:** No mechanism exists to detect or flag manipulated values
- **Consistently Exploitable:** The validation gap exists on every block production

**Feasibility:**
- Entry point is the normal block production flow accessible to all elected miners
- The validation flaw makes the attack 100% reliable when executed
- Grep search confirms no other validation checks this value against `Context.CurrentHeight`

**Economic Rationality:**
For high-value targets (major DeFi protocols, cross-chain bridges with significant TVL), the cost of controlling 1/3 mining power could be justified by the potential gains from double-spend attacks or ransom scenarios.

**Likelihood: Medium** - While it requires significant resources to control 1/3+ miners, the trivial execution and lack of detection make this a realistic threat for motivated attackers.

## Recommendation

**Fix the validation ordering issue:**

The validation should preserve the original `baseRound` state BEFORE calling `RecoverFromUpdateValue`, or validate against the original state directly. Additionally, add explicit upper bound validation:

```csharp
// In LibInformationValidationProvider.ValidateHeaderInformation:

// Get the ORIGINAL value from baseRound BEFORE any recovery
var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(pubkey) 
    ? baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight 
    : 0;

var providedImpliedHeight = providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;

// Check 1: Value should not decrease from previous
if (providedImpliedHeight != 0 && originalImpliedHeight > providedImpliedHeight)
{
    validationResult.Message = "Incorrect implied lib height - decreased.";
    return validationResult;
}

// Check 2: Value should not exceed current block height
// Note: This check should be added in a context where Context.CurrentHeight is accessible
// or passed through the validation context
if (providedImpliedHeight > validationContext.CurrentHeight)
{
    validationResult.Message = "Implied lib height exceeds current block height.";
    return validationResult;
}
```

Alternatively, restructure the validation flow to NOT call `RecoverFromUpdateValue` before validation, but rather after validation passes.

## Proof of Concept

A malicious miner node can modify its block production code to set arbitrary `ImpliedIrreversibleBlockHeight` values:

```csharp
// Malicious modification in block production flow:
// Instead of using the proper value from GetConsensusExtraDataToPublishOutValue,
// the miner constructs a modified Round object:

var maliciousRound = GetCurrentRound(); // Get current round
maliciousRound.RealTimeMinersInformation[myPubkey].ImpliedIrreversibleBlockHeight = 0; // Suppress LIB

// Include this in both:
// 1. Block header extra data
// 2. UpdateValueInput transaction parameter

// The validation will:
// - Call RecoverFromUpdateValue, overwriting baseRound[myPubkey].ImpliedIrreversibleBlockHeight = 0
// - Compare baseRound (now 0) vs providedRound (0)
// - Check passes: 0 > 0 is false, so validation succeeds
// - Value 0 is stored and used in LIB calculation

// With 7+ out of 21 miners doing this, the LIB will be suppressed to 0
```

To fully demonstrate this would require:
1. A test environment with multiple miner nodes
2. Modifying the miner node software to inject malicious values
3. Observing that validation passes despite incorrect values
4. Confirming LIB calculation uses the manipulated values

The core vulnerability is evident from the code structure where validation compares the value against itself after recovery.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-33)
```csharp
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
