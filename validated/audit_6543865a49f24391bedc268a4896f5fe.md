# Audit Report

## Title
Broken ImpliedIrreversibleBlockHeight Validation Allows Consensus Finality Manipulation

## Summary
The `LibInformationValidationProvider` contains a critical logic flaw where validation occurs after the base round state has already been modified to match the provided round, making the regression check permanently ineffective. Additionally, a zero-value bypass in the validation logic allows miners to submit `ImpliedIrreversibleBlockHeight = 0`, which can disrupt Last Irreversible Block (LIB) calculations and stall chain finality.

## Finding Description

The consensus validation flow in AEDPoS has a fundamental ordering bug. When validating consensus information, the `ValidateBeforeExecution` method calls `RecoverFromUpdateValue` before performing validation checks. [1](#0-0) 

This recovery operation copies the `ImpliedIrreversibleBlockHeight` from the provided round directly into the base round that will be used for validation: [2](#0-1) 

After this state mutation, the `LibInformationValidationProvider` is added to the validation chain: [3](#0-2) 

The validator attempts to detect regressions by comparing the base round's value against the provided round's value: [4](#0-3) 

**Critical Bug**: Since `RecoverFromUpdateValue` already copied `providedRound[pubkey].ImpliedIrreversibleBlockHeight` to `baseRound[pubkey].ImpliedIrreversibleBlockHeight`, the comparison on lines 25-26 checks if a value is greater than itself. This condition can never be true, rendering the regression validation completely non-functional.

**Zero-Value Bypass**: Line 24 contains an additional flaw - it skips validation entirely when `ImpliedIrreversibleBlockHeight = 0`. This allows a miner to regress from any valid height (e.g., 1000) back to 0, bypassing all validation.

The unvalidated value is then written directly to state during block processing: [5](#0-4) 

This corrupted value affects LIB calculation, as the algorithm filters out miners with zero values: [6](#0-5) 

If enough miners submit zero values, the count of valid implied heights falls below the consensus threshold, causing the LIB calculation to return 0: [7](#0-6) 

## Impact Explanation

**Consensus Finality Disruption**: The broken validation enables a malicious or compromised miner to submit `ImpliedIrreversibleBlockHeight = 0` in their consensus updates. When miners with zero values are filtered out during LIB calculation, the remaining count may fall below `MinersCountOfConsent` (defined as 2/3 + 1 of total miners): [8](#0-7) 

If multiple miners coordinate this attack or if a sufficient number of miner nodes are compromised, the LIB would be set to 0, effectively stalling chain finality. This impacts:

- **Cross-chain security**: Cross-chain operations rely on LIB heights for irreversibility guarantees
- **Transaction finality**: Users cannot trust that transactions are irreversible
- **Network integrity**: The consensus mechanism's core finality guarantees are compromised

The broader security issue is that **no regression validation is being performed** on this critical consensus parameter, even for honest miners.

## Likelihood Explanation

**Prerequisites**:
- Requires control of one or more miner nodes (trusted role in DPoS)
- Miner must modify node software or configuration to submit malicious `ImpliedIrreversibleBlockHeight` values
- Standard consensus logic sets this value correctly during normal operations

**Attack Complexity**: Low - once a miner node is compromised or malicious, submitting a zero value is trivial since validation is non-functional.

**Detection**: The attack would be immediately visible in block explorer data and LIB progression metrics, making it easy to detect but potentially difficult to prevent in real-time.

**Probability**: Medium-Low - Requires compromising trusted miner infrastructure, but the validation being completely broken means there are no technical barriers once a miner is compromised.

## Recommendation

Fix the validation ordering by performing validation checks **before** calling `RecoverFromUpdateValue`:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    // Get base round WITHOUT modification
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // Perform validation FIRST using unmodified baseRound
    var validationContext = new ConsensusValidationContext
    {
        BaseRound = baseRound.Clone(), // Use a copy for validation
        ProvidedRound = extraData.Round,
        SenderPubkey = extraData.SenderPubkey.ToHex(),
        // ... other fields
    };

    // Add validators and validate
    var validationProviders = new List<IHeaderInformationValidationProvider> { /* ... */ };
    var service = new HeaderInformationValidationService(validationProviders);
    var validationResult = service.ValidateInformation(validationContext);
    
    if (!validationResult.Success)
        return validationResult;

    // Only AFTER validation passes, apply recovery
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

    return new ValidationResult { Success = true };
}
```

Additionally, remove or fix the `!= 0` bypass in `LibInformationValidationProvider`:

```csharp
// Always validate regression, don't skip for zero values
if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
    baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
    providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
{
    validationResult.Message = "Incorrect implied lib height - regression detected.";
    return validationResult;
}
```

## Proof of Concept

Due to the nature of this vulnerability requiring consensus infrastructure and miner key access, a complete proof of concept would require:

1. Running a local AElf testnet with multiple validator nodes
2. Modifying one validator node's consensus logic to submit `ImpliedIrreversibleBlockHeight = 0`
3. Observing that the validation passes (demonstrating the broken comparison)
4. Monitoring LIB progression to show that it stalls when sufficient miners submit zero values

The code-level bug can be verified by tracing through the execution path shown in the citations above, demonstrating that the comparison at line 25-26 of `LibInformationValidationProvider.cs` always evaluates to false after line 19 of `Round_Recover.cs` makes the values equal.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L82-82)
```csharp
                validationProviders.Add(new LibInformationValidationProvider());
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
