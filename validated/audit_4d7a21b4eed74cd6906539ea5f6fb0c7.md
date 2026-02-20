# Audit Report

## Title
ImpliedIrreversibleBlockHeight Validation Bypass Due to Premature State Modification

## Summary
The `ValidateBeforeExecution` method modifies the base round state before validation occurs, causing `LibInformationValidationProvider` to compare a miner's `ImpliedIrreversibleBlockHeight` against itself. This allows malicious miners to submit arbitrary values that influence Last Irreversible Block (LIB) calculations, potentially delaying consensus finality if more than 1/3 of miners collude.

## Finding Description

The vulnerability stems from incorrect validation ordering in the consensus validation flow. When a miner produces a block with `UpdateValue` or `TinyBlock` behavior, the validation process modifies state before checking it.

**Execution Flow:**

1. `ValidateBeforeExecution` retrieves the current round from state storage into `baseRound` [1](#0-0) 

2. For `UpdateValue` or `TinyBlock` behaviors, the method calls recovery methods that modify `baseRound` in-place BEFORE validation [2](#0-1) 

3. `RecoverFromUpdateValue` overwrites the `ImpliedIrreversibleBlockHeight` in the base round with the attacker-provided value [3](#0-2) 

4. The validation context is created with the already-modified `baseRound` [4](#0-3) 

5. `LibInformationValidationProvider` attempts to validate by comparing `baseRound.ImpliedIrreversibleBlockHeight` against `providedRound.ImpliedIrreversibleBlockHeight` [5](#0-4) 

Since both values now contain the attacker-provided value (the `ProvidedRound` is from the extraData [6](#0-5) ), the check becomes `providedValue > providedValue`, which is always false, causing validation to always pass.

6. The malicious value is persisted during `ProcessUpdateValue` [7](#0-6)  and [8](#0-7) 

7. The `LastIrreversibleBlockHeightCalculator` uses these implied heights from miners to calculate LIB, taking the value at index `(count-1)/3` from the sorted list [9](#0-8) 

Legitimate miners set `ImpliedIrreversibleBlockHeight` to `Context.CurrentHeight` when generating consensus data [10](#0-9) , but there is no validation enforcing this expectation.

## Impact Explanation

**Severity: Medium**

The vulnerability breaks consensus finality guarantees:

- **Finality Delay**: Malicious miners can submit artificially low `ImpliedIrreversibleBlockHeight` values. Since LIB is calculated using the value at index `(count-1)/3` of the sorted list, if more than 1/3 of miners submit low values, the calculated LIB will be artificially low, delaying finality advancement.

- **Cross-Chain Impact**: Cross-chain operations rely on LIB heights for security guarantees. Delayed LIB advancement blocks or delays cross-chain transactions, affecting interoperability.

- **Consensus Integrity**: The network's shared view of transaction irreversibility is compromised, undermining core consensus guarantees.

**Mitigating Factor**: The check at line 272 prevents the confirmed LIB from decreasing [11](#0-10) , preventing rollback of already-finalized blocks. However, this doesn't prevent the attack from stalling forward progress.

## Likelihood Explanation

**Probability: Medium-High**

The attack is highly feasible:

- **Low Barrier**: Any elected miner can execute this attack. Mining permission is validated [12](#0-11) , but there's no validation of the `ImpliedIrreversibleBlockHeight` value itself.

- **Low Complexity**: The attacker simply needs to provide a low value in their consensus data. No complex state manipulation or timing requirements exist.

- **Persistent Attack**: Malicious miners can execute this repeatedly in every round they participate in.

- **No Detection/Slashing**: The codebase contains no mechanism to detect or slash miners for this behavior.

- **Collusion Threshold**: While a single malicious miner has limited impact, collusion of >1/3 of miners can significantly impair LIB advancement.

## Recommendation

The fix is to preserve the original base round state for validation purposes. Modify `ValidateBeforeExecution` to create a copy of the base round before recovery operations:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // Create a copy for validation that won't be modified
    var baseRoundForValidation = baseRound.Clone();
    
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

    if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
        baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

    var validationContext = new ConsensusValidationContext
    {
        BaseRound = baseRoundForValidation, // Use unmodified copy
        // ... rest of context
    };
    // ... rest of validation
}
```

Additionally, add explicit range validation in `LibInformationValidationProvider` to ensure `ImpliedIrreversibleBlockHeight` values are reasonable (e.g., within a certain range of `Context.CurrentHeight`).

## Proof of Concept

```csharp
// This test demonstrates the validation bypass
[Fact]
public async Task MaliciousMiner_CanBypassImpliedIrreversibleBlockHeightValidation()
{
    // Setup: Initialize consensus with elected miners
    await InitializeConsensusAsync();
    
    // Attacker is an elected miner
    var maliciousMiner = InitialMiners[0];
    
    // Current block height is 1000
    var currentHeight = 1000L;
    
    // Attacker generates UpdateValue with artificially low ImpliedIrreversibleBlockHeight
    var maliciousUpdateValue = new UpdateValueInput
    {
        ImpliedIrreversibleBlockHeight = 1, // Should be ~1000 but attacker provides 1
        // ... other required fields
    };
    
    // Execute block with malicious data
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(maliciousUpdateValue);
    
    // Verify: Transaction succeeds (validation bypassed)
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Malicious value is persisted
    var round = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    round.RealTimeMinersInformation[maliciousMiner.PublicKey.ToHex()]
        .ImpliedIrreversibleBlockHeight.ShouldBe(1); // Malicious value stored
    
    // Impact: If >1/3 miners do this, LIB calculation will be artificially low
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-272)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```
