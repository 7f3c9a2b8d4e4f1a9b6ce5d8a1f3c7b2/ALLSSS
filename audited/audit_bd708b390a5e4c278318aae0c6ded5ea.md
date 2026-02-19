# Audit Report

## Title
ImpliedIrreversibleBlockHeight Validation Bypass Due to Premature State Modification

## Summary
The `ValidateBeforeExecution` method in the AEDPoS consensus contract modifies the base round state before validation occurs, causing the `LibInformationValidationProvider` to compare a miner's `ImpliedIrreversibleBlockHeight` against itself rather than the original stored value. This allows malicious miners to submit arbitrary values that influence Last Irreversible Block (LIB) calculations, potentially delaying consensus finality if more than 1/3 of miners collude.

## Finding Description

The vulnerability stems from incorrect validation ordering in the consensus validation flow. When validating consensus information, the system fetches the current round state from storage, then immediately modifies it with provided values before performing validation checks.

The execution flow is:

1. `ValidateBeforeExecution` retrieves the base round from state [1](#0-0) 

2. For `UpdateValue` or `TinyBlock` behaviors, it calls recovery methods that modify the base round in-place [2](#0-1) 

3. The `RecoverFromUpdateValue` method overwrites the `ImpliedIrreversibleBlockHeight` in the base round with the provided value [3](#0-2) 

4. The validation context is then created with the already-modified base round [4](#0-3) 

5. The `LibInformationValidationProvider` attempts to validate by comparing the base round value against the provided round value [5](#0-4) 

Since both values now contain the attacker-provided value, the check `baseRound.ImpliedIrreversibleBlockHeight > providedRound.ImpliedIrreversibleBlockHeight` evaluates to `providedValue > providedValue`, which is always false, causing validation to always pass.

The malicious value is then persisted during consensus processing [6](#0-5) 

This affects LIB calculation because the `LastIrreversibleBlockHeightCalculator` uses these implied heights from miners to calculate the network's irreversible block height [7](#0-6) 

Legitimate miners set `ImpliedIrreversibleBlockHeight` to `Context.CurrentHeight` when generating consensus data [8](#0-7) , but there is no validation enforcing this expectation.

## Impact Explanation

**Severity: Medium**

The vulnerability breaks consensus finality guarantees:

- **Finality Delay**: Malicious miners can submit artificially low `ImpliedIrreversibleBlockHeight` values (e.g., 0 or values far in the past). Since LIB is calculated using the value at index `(count-1)/3` of the sorted list, if more than 1/3 of miners submit low values, the calculated LIB will be artificially low, delaying finality advancement.

- **Cross-Chain Impact**: Cross-chain operations rely on LIB heights for security guarantees. Delayed LIB advancement blocks or delays cross-chain transactions, affecting interoperability.

- **Consensus Integrity**: The network's shared view of transaction irreversibility is compromised, undermining one of the core consensus guarantees.

**Mitigating Factor**: The check at line 272 prevents the confirmed LIB from decreasing [9](#0-8) , preventing rollback of already-finalized blocks. However, this doesn't prevent the attack from stalling forward progress.

## Likelihood Explanation

**Probability: Medium-High**

The attack is highly feasible:

- **Low Barrier**: Any elected miner can execute this attack. Mining permission is validated [10](#0-9) , but there's no validation of the `ImpliedIrreversibleBlockHeight` value itself.

- **Low Complexity**: The attacker simply needs to provide a low value in their consensus data. No complex state manipulation or timing requirements exist.

- **Persistent Attack**: Malicious miners can execute this repeatedly in every round they participate in.

- **No Detection/Slashing**: The codebase contains no mechanism to detect or slash miners for this behavior.

- **Collusion Threshold**: While a single malicious miner has limited impact, collusion of >1/3 of miners (a realistic scenario in smaller validator sets) can significantly impair LIB advancement.

## Recommendation

The validation should occur **before** the base round is modified. Restructure `ValidateBeforeExecution` as follows:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // Create validation context with UNMODIFIED baseRound
    var validationContext = new ConsensusValidationContext
    {
        BaseRound = baseRound,
        CurrentTermNumber = State.CurrentTermNumber.Value,
        CurrentRoundNumber = State.CurrentRoundNumber.Value,
        PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
        LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
        ExtraData = extraData
    };

    // Add validation providers and validate FIRST
    var validationProviders = new List<IHeaderInformationValidationProvider> { /* ... */ };
    var service = new HeaderInformationValidationService(validationProviders);
    var validationResult = service.ValidateInformation(validationContext);
    
    if (!validationResult.Success)
        return validationResult;

    // ONLY AFTER validation passes, modify baseRound
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
    if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
        baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

    return new ValidationResult { Success = true };
}
```

Additionally, consider adding explicit bounds checking for `ImpliedIrreversibleBlockHeight` to ensure it's within a reasonable range of `Context.CurrentHeight`.

## Proof of Concept

This vulnerability can be demonstrated by creating a test that:
1. Sets up a consensus round with multiple miners
2. Has a malicious miner submit an `UpdateValueInput` with `ImpliedIrreversibleBlockHeight = 0`
3. Verifies the validation passes despite the obviously invalid value
4. Confirms the malicious value is persisted and affects subsequent LIB calculations
5. Shows that with >1/3 miners submitting low values, the calculated LIB is artificially low

The test would invoke the consensus contract's block validation path with crafted consensus data containing the malicious `ImpliedIrreversibleBlockHeight` value, demonstrating that it bypasses validation and influences LIB calculation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L68-68)
```csharp
            new MiningPermissionValidationProvider(),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-26)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-272)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L25-32)
```csharp
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```
