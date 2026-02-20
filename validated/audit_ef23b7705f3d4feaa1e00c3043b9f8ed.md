# Audit Report

## Title
ImpliedIrreversibleBlockHeight Monotonicity Violation Due to Pre-Validation Mutation

## Summary
The `RecoverFromUpdateValue()` function mutates `ImpliedIrreversibleBlockHeight` before validation occurs, causing the `LibInformationValidationProvider` to compare the provided value against itself rather than the original state value. This completely bypasses the monotonicity check, allowing malicious miners to arbitrarily decrease their `ImpliedIrreversibleBlockHeight`, corrupting the data used for Last Irreversible Block (LIB) calculations and breaking consensus integrity guarantees.

## Finding Description

The vulnerability exists in the consensus validation flow where state mutation occurs before security validation, rendering the validation check ineffective.

**Root Cause - Pre-Validation Mutation:**

In `ValidateBeforeExecution`, the contract retrieves the current round from state, then immediately mutates it by calling `RecoverFromUpdateValue` before any validation checks occur: [1](#0-0) [2](#0-1) 

The `RecoverFromUpdateValue` method directly overwrites the `ImpliedIrreversibleBlockHeight` field in the base round without any validation: [3](#0-2) 

If the original state had `ImpliedIrreversibleBlockHeight = 1000` and the attacker provides `ImpliedIrreversibleBlockHeight = 500`, after line 19 executes, `baseRound[pubkey].ImpliedIrreversibleBlockHeight` becomes `500`.

**Broken Validation Logic:**

After the mutation, the validation context is created with the already-modified `baseRound`: [4](#0-3) 

The `LibInformationValidationProvider` is then added to validate LIB information: [5](#0-4) 

The validator compares the modified `baseRound` against `providedRound`, where `providedRound` is defined as `ExtraData.Round`: [6](#0-5) 

The validation check attempts to detect if the `ImpliedIrreversibleBlockHeight` decreased: [7](#0-6) 

Since `baseRound[pubkey].ImpliedIrreversibleBlockHeight` was already set to the provided value (500) during recovery, the check becomes: `500 > 500`, which is always `false`. The validation cannot detect any decrease.

**State Persistence:**

The malicious value is persisted to state during transaction execution: [8](#0-7) [9](#0-8) 

**LIB Calculation Impact:**

The corrupted `ImpliedIrreversibleBlockHeight` values are used to calculate the Last Irreversible Block: [10](#0-9) 

The LIB calculator retrieves sorted heights from all miners and selects the value at position `(count-1)/3` for Byzantine fault tolerance: [11](#0-10) [12](#0-11) 

By providing artificially low values, malicious miners corrupt the input data for LIB calculations, preventing proper LIB advancement and breaking the monotonicity invariant.

## Impact Explanation

**Critical Consensus Integrity Violation:**

The `ImpliedIrreversibleBlockHeight` field represents each miner's view of the irreversible block height and is fundamental to the BFT consensus finality mechanism. The complete bypass of monotonicity validation has severe consequences:

1. **Invariant Violation**: The security guarantee that `ImpliedIrreversibleBlockHeight` can only increase is completely broken
2. **LIB Calculation Corruption**: The Byzantine fault-tolerant LIB calculation relies on collecting these values from all miners and selecting the (2/3) percentile. Corrupted input data undermines this mechanism
3. **Finality Guarantee Weakening**: While `ConfirmedIrreversibleBlockHeight` has a separate protection preventing absolute decreases, the corrupted individual miner values can prevent proper LIB advancement, causing finality to stall
4. **BFT Assumptions Broken**: The validation mechanism itself is bypassed, violating the assumption that at most 1/3 of miners can be malicious

**Affected Parties:**
- All network participants relying on consensus finality
- Cross-chain protocols depending on parent chain LIB verification
- Applications using LIB for transaction finality decisions

**Severity:** CRITICAL - Breaks a core consensus invariant and undermines Byzantine fault tolerance guarantees.

## Likelihood Explanation

**Access Requirements:**

The only access control is verification that the sender is in the miner list: [13](#0-12) 

Any active miner can exploit this vulnerability through the public `UpdateValue` method: [14](#0-13) 

**Attack Complexity:** LOW
- Attacker must be an active miner in the consensus set (valid threat model for BFT)
- No complex state setup or timing requirements required
- Simply submit an `UpdateValue` transaction with a lower `ImpliedIrreversibleBlockHeight`
- The broken validation logic will not detect the decrease
- The malicious value will be persisted to state

**Feasibility:** HIGH
- Exploitable through normal consensus operations
- No special conditions required beyond being a miner
- Can be executed in any round during block production
- The validation mechanism is completely bypassed

## Recommendation

Move the `RecoverFromUpdateValue` call to AFTER validation, not before. The validation should compare the provided value against the original state value, not the already-mutated value.

**Fixed validation flow:**
```csharp
// Get original state
if (!TryToGetCurrentRoundInformation(out var baseRound))
    return new ValidationResult { Success = false, Message = "Failed to get current round information." };

// Create validation context with ORIGINAL baseRound (no mutation yet)
var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound,  // Original, unmutated state
    // ... other fields
};

// Perform validation with validators
var service = new HeaderInformationValidationService(validationProviders);
var validationResult = service.ValidateInformation(validationContext);

if (validationResult.Success == false)
    return validationResult;

// ONLY mutate after validation passes
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

This ensures the validator compares the provided value against the true original state value, allowing it to properly detect decreases.

## Proof of Concept

```csharp
[Fact]
public async Task UpdateValue_ShouldReject_WhenImpliedIrreversibleBlockHeightDecreases()
{
    // Setup: Initialize consensus with first round and mine initial blocks
    await InitializeConsensusAndMineSomeBlocks();
    
    // Get current round and set miner's ImpliedIrreversibleBlockHeight to 1000
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerPubkey = ValidationDataProvider.GetMiners().First();
    currentRound.RealTimeMinersInformation[minerPubkey.ToHex()].ImpliedIrreversibleBlockHeight = 1000;
    
    // Store the modified round
    await UpdateRoundInformation(currentRound);
    
    // Attacker: Create UpdateValueInput with DECREASED ImpliedIrreversibleBlockHeight (500 < 1000)
    var maliciousInput = new UpdateValueInput
    {
        ImpliedIrreversibleBlockHeight = 500,  // Attempting to decrease from 1000 to 500
        // ... other required fields
    };
    
    // Attempt to call UpdateValue with decreased value
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(maliciousInput);
    
    // Expected: Transaction should FAIL validation
    // Actual: Transaction SUCCEEDS due to broken validation (comparing 500 > 500 = false)
    
    // Verify the malicious value was persisted (proving the vulnerability)
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var storedValue = updatedRound.RealTimeMinersInformation[minerPubkey.ToHex()].ImpliedIrreversibleBlockHeight;
    
    // This assertion will PASS, proving the vulnerability allows decreases
    storedValue.ShouldBe(500);  // Successfully decreased from 1000 to 500
}
```

**Notes:**
- The vulnerability is in production consensus contract code
- The pre-validation mutation on line 47 of `AEDPoSContract_Validation.cs` occurs before the validation context is created on line 52
- The `LibInformationValidationProvider` compares `baseRound[pubkey].ImpliedIrreversibleBlockHeight` (already mutated to provided value) against `providedRound[pubkey].ImpliedIrreversibleBlockHeight` (same provided value)
- This makes the check `provided_value > provided_value`, which is always false, so decreases are never detected
- While `ConfirmedIrreversibleBlockHeight` has a separate protection on line 272 of `AEDPoSContract_ProcessConsensusInformation.cs`, the individual miner's `ImpliedIrreversibleBlockHeight` monotonicity is completely unprotected
- The BFT LIB calculation relies on these individual values being trustworthy, and the broken validation undermines this assumption

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-21)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
