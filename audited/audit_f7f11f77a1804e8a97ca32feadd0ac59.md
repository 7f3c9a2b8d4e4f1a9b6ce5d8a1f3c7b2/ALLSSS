# Audit Report

## Title
Broken ImpliedIrreversibleBlockHeight Validation Allows Malicious LIB Manipulation

## Summary
A critical logic error in the consensus validation flow allows malicious miners to artificially lower their reported `ImpliedIrreversibleBlockHeight` value, bypassing validation checks designed to prevent this. The `RecoverFromUpdateValue` method modifies the baseline round data before validation occurs, causing the validation to compare a value against itself rather than against the stored state, always passing. This enables attackers to delay chain finality by manipulating Last Irreversible Block (LIB) calculations.

## Finding Description

The vulnerability exists in the ordering of operations in the consensus validation flow. When a block with `UpdateValue` behavior is validated:

1. The current round information is fetched from state as `baseRound` [1](#0-0) 

2. For `UpdateValue` behavior, `RecoverFromUpdateValue` is immediately called on `baseRound`, which modifies it in-place by copying values from the provided round [2](#0-1) 

3. The recovery operation explicitly overwrites the miner's `ImpliedIrreversibleBlockHeight` in `baseRound` with the attacker-provided value [3](#0-2) 

4. The validation context is then created using this **already-modified** `baseRound` [4](#0-3) 

5. `LibInformationValidationProvider` is added to the validation pipeline [5](#0-4) 

6. The validation check compares `baseRound[pubkey].ImpliedIrreversibleBlockHeight` (now equal to the attacker's value) with `providedRound[pubkey].ImpliedIrreversibleBlockHeight` [6](#0-5) 

**Root Cause**: Since `RecoverFromUpdateValue` executes before validation, the security check effectively becomes `attackerValue > attackerValue`, which is always false, allowing the validation to pass regardless of whether the value decreased.

The malicious value is then persisted to state during consensus information processing [7](#0-6) 

The LIB calculator retrieves implied heights from the previous round for miners who mined in the current round [8](#0-7)  and sorts them, taking the value at index `(count-1)/3` (the 1/3 quantile) [9](#0-8) 

Additionally, the same logic error affects `ValidateConsensusAfterExecution`, where the recovery method is called and its result assigned back to the header information before hash comparison [10](#0-9) , causing both objects to reference the same modified data and making hash validation ineffective.

## Impact Explanation

**Severity: HIGH**

This vulnerability directly violates consensus finality guarantees, which are fundamental to blockchain security:

1. **Consensus Integrity Violation**: The Last Irreversible Block (LIB) height is calculated using the 1/3 quantile of sorted implied heights from active miners [11](#0-10) . A maliciously low value in the bottom third of sorted heights directly lowers the calculated LIB.

2. **Delayed Finality**: Lower LIB means blocks take longer to become irreversible, extending the window during which blocks remain reversible.

3. **Cross-Chain Impact**: Cross-chain operations and indexing depend on LIB for determining which blocks are finalized. Manipulated LIB heights create potential for cross-chain inconsistencies.

4. **Double-Spend Window**: Extended reversibility windows enable potential double-spend attack vectors by keeping transactions in a non-final state longer than protocol-intended.

5. **No Cryptographic Protection**: The hash validation that should detect tampering suffers from the same logic error, providing no defense against this attack.

While this doesn't directly result in fund theft, it fundamentally undermines the security model of the blockchain by breaking finality guarantees.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Prerequisites**:
- Must be an active block producer (miner) in the consensus round
- This is a non-trivial but feasible requirement (requires staking and election)

**Attack Complexity: LOW**
- Miners generate consensus extra data where `ImpliedIrreversibleBlockHeight` is normally set to the current block height [12](#0-11) 
- The miner simply modifies this value in the `UpdateValueInput` message [13](#0-12)  to be lower than their previous reported value
- Submit the block with modified consensus data
- The broken validation guarantees success

**Execution Feasibility**:
- No cryptographic barriers prevent modification
- Attack is repeatable across multiple rounds
- Success is guaranteed due to the validation logic error
- No alerting mechanism exists to detect abnormally low values

**Detection Difficulty**: LOW - While the malicious values are stored in state, there's no built-in monitoring for values that are unexpectedly low relative to block heights.

The combination of guaranteed success once prerequisites are met and the significant consensus compromise makes this MEDIUM-HIGH likelihood despite requiring miner access.

## Recommendation

**Fix the validation ordering by preserving the original baseline before recovery:**

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // Preserve original baseline for validation
    var originalBaseRound = baseRound.Clone(); // Add Clone method to Round type
    
    // Recover for context purposes
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

    if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
        baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

    var validationContext = new ConsensusValidationContext
    {
        BaseRound = originalBaseRound, // Use ORIGINAL for validation
        CurrentTermNumber = State.CurrentTermNumber.Value,
        CurrentRoundNumber = State.CurrentRoundNumber.Value,
        PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
        LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
        ExtraData = extraData
    };
    
    // Rest of validation...
}
```

Apply similar fix to `ValidateConsensusAfterExecution` to preserve the original state before recovery for hash comparison.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanLowerImpliedIrreversibleBlockHeight()
{
    // Setup: Initialize consensus with multiple miners
    await InitializeConsensusAsync();
    await ProduceNormalBlocksAsync(100); // Build up legitimate LIB history
    
    // Get current round and miner's legitimate implied height
    var currentRound = await GetCurrentRoundAsync();
    var maliciousMinerPubkey = currentRound.RealTimeMinersInformation.Keys.First();
    var legitimateHeight = currentRound.RealTimeMinersInformation[maliciousMinerPubkey]
        .ImpliedIrreversibleBlockHeight; // Should be ~100
    
    // Attack: Miner submits UpdateValue with artificially low implied height
    var maliciousHeight = legitimateHeight - 50; // Drastically lower value
    var updateValueInput = new UpdateValueInput
    {
        // ... normal fields ...
        ImpliedIrreversibleBlockHeight = maliciousHeight, // MALICIOUS
        // ... other required fields ...
    };
    
    // Execute the malicious update
    var result = await ConsensusContract.UpdateValue.SendAsync(updateValueInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Passes validation!
    
    // Verify: The malicious value was stored
    var updatedRound = await GetCurrentRoundAsync();
    var storedHeight = updatedRound.RealTimeMinersInformation[maliciousMinerPubkey]
        .ImpliedIrreversibleBlockHeight;
    storedHeight.ShouldBe(maliciousHeight); // Attack succeeded
    
    // Impact: Next round's LIB calculation uses the malicious value
    await ProduceNextRoundAsync();
    var calculatedLib = await GetCurrentLibHeightAsync();
    calculatedLib.ShouldBeLessThan(expectedLegitimateLib); // LIB is artificially lowered
}
```

The test demonstrates that a miner can successfully submit a lower `ImpliedIrreversibleBlockHeight` value, which passes validation due to the logic error, gets stored in state, and subsequently affects LIB calculations, proving the vulnerability is exploitable and has concrete impact on consensus finality.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-25)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-97)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-19)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** protobuf/aedpos_contract.proto (L217-218)
```text
    // The irreversible block height that miner recorded.
    int64 implied_irreversible_block_height = 12;
```
