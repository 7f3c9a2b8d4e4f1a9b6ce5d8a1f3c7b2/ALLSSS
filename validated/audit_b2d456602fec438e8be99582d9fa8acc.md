# Audit Report

## Title
LibInformationValidationProvider Bypass Through Pre-Validation State Modification

## Summary
The `LibInformationValidationProvider` validation is completely bypassed because `RecoverFromUpdateValue` modifies the `baseRound` object in-place before validation occurs. This allows malicious miners to report artificially low `ImpliedIrreversibleBlockHeight` values that should fail monotonicity checks, potentially delaying Last Irreversible Block (LIB) advancement and affecting consensus finality guarantees.

## Finding Description

The AEDPoS consensus validation system contains a critical ordering flaw that completely disables the `LibInformationValidationProvider`'s monotonicity check.

**The Root Cause:**

In `ValidateBeforeExecution`, when processing `UpdateValue` consensus behavior, the code fetches `baseRound` from state and then immediately modifies it by calling `RecoverFromUpdateValue`: [1](#0-0) [2](#0-1) 

The `RecoverFromUpdateValue` method modifies `baseRound` in-place, overwriting critical fields including `ImpliedIrreversibleBlockHeight`: [3](#0-2) 

After this modification, the validation context is created using the already-modified `baseRound`: [4](#0-3) 

**Why the Protection Fails:**

The `LibInformationValidationProvider` is added to validate `UpdateValue` behavior: [5](#0-4) 

This validator attempts to check that the provided `ImpliedIrreversibleBlockHeight` is not lower than the value in `baseRound`: [6](#0-5) 

However, at this point `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` has already been set equal to `providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` by the earlier `RecoverFromUpdateValue` call. The comparison becomes `X > X`, which is always false, so the validation never rejects decreasing values.

**Execution Flow:**

1. Miner produces block with maliciously low `ImpliedIrreversibleBlockHeight` value
2. `ValidateBeforeExecution` fetches original `baseRound` from state
3. `RecoverFromUpdateValue` overwrites `baseRound.ImpliedIrreversibleBlockHeight` with the malicious value
4. Validation context is created with the pre-modified `baseRound`
5. `LibInformationValidationProvider` compares the modified value against itself - validation passes
6. `ProcessUpdateValue` persists the low value to state: [7](#0-6) 

## Impact Explanation

**Consensus Finality Degradation:**

The `ImpliedIrreversibleBlockHeight` values are directly used in the Last Irreversible Block (LIB) height calculation: [8](#0-7) 

The calculator retrieves implied heights from miners and selects the value at position `(count-1)/3`: [9](#0-8) 

**Specific Harms:**

1. **Delayed Finality**: If malicious miners report artificially low values, they drag down the median calculation, preventing proper LIB advancement
2. **Cross-Chain Impact**: LIB height is used for cross-chain transaction verification and finality guarantees  
3. **Time-Sensitive Operations**: Any operations depending on block finalization are delayed
4. **Consensus Integrity**: Violates the monotonicity invariant that `ImpliedIrreversibleBlockHeight` should only increase per miner

While no direct fund theft occurs, consensus finality is a critical security property. The bypass completely disables an important monotonicity check, allowing malicious miners to manipulate when blocks become irreversible.

## Likelihood Explanation

**Attacker Capabilities:**
- Must be a consensus miner (privileged but within scope for consensus security)
- No additional permissions required beyond normal mining operations

**Attack Complexity:**
- Trivial: Simply provide a lower `ImpliedIrreversibleBlockHeight` value when producing blocks
- Expected value should be `Context.CurrentHeight`: [10](#0-9) 

- Attacker provides value < their previous reported height
- Validation bypass is automatic and deterministic

**Feasibility:**
- Reachable through normal `UpdateValue` consensus transaction flow
- No race conditions or timing requirements
- Low economic cost (normal mining operations)

**Detection:**
- Requires monitoring historical `ImpliedIrreversibleBlockHeight` values per miner across rounds
- Not immediately detectable without cross-round comparison
- Could appear as "slow" or "buggy" miner rather than malicious

**Probability:** High likelihood of exploitation if a miner becomes malicious, as the attack is trivial to execute and provides strategic advantages in controlling finality.

## Recommendation

The fix is to preserve the original `baseRound` state before modification and use it for validation. Modify `ValidateBeforeExecution` as follows:

```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (!TryToGetCurrentRoundInformation(out var baseRound))
        return new ValidationResult { Success = false, Message = "Failed to get current round information." };

    // Preserve original baseRound for validation
    var originalBaseRound = baseRound.Clone(); // or create a deep copy
    
    if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
        baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

    if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
        baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

    var validationContext = new ConsensusValidationContext
    {
        BaseRound = originalBaseRound, // Use unmodified version for validation
        CurrentTermNumber = State.CurrentTermNumber.Value,
        CurrentRoundNumber = State.CurrentRoundNumber.Value,
        PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
        LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
        ExtraData = extraData
    };
    
    // ... rest of validation
}
```

Alternatively, move the `RecoverFromUpdateValue` call to after validation completes.

## Proof of Concept

```csharp
[Fact]
public async Task LibInformationValidationBypass_Test()
{
    // Setup: Initialize consensus with multiple miners
    var miners = await InitializeConsensusAsync();
    var maliciousMiner = miners[0];
    
    // Miner produces first block with normal ImpliedIrreversibleBlockHeight
    var round1 = await ProduceNormalBlockAsync(maliciousMiner, currentHeight: 100);
    
    // Verify the miner's ImpliedIrreversibleBlockHeight is 100
    var minerInfo1 = round1.RealTimeMinersInformation[maliciousMiner];
    minerInfo1.ImpliedIrreversibleBlockHeight.ShouldBe(100);
    
    // Malicious miner produces second block with LOWER ImpliedIrreversibleBlockHeight
    var maliciousInput = new UpdateValueInput
    {
        ImpliedIrreversibleBlockHeight = 50, // Lower than previous 100!
        // ... other required fields
    };
    
    // This should FAIL validation but will PASS due to the bug
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Should fail but passes!
    
    // Verify the lower value was persisted to state
    var round2 = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo2 = round2.RealTimeMinersInformation[maliciousMiner];
    minerInfo2.ImpliedIrreversibleBlockHeight.ShouldBe(50); // Monotonicity violated!
    
    // Verify LIB calculation is now affected by the low value
    // (subsequent blocks will use this low value in LIB median calculation)
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-20)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-249)
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
