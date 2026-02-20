# Audit Report

## Title
Validation Bypass via Data Contamination Enables Last Irreversible Block (LIB) Manipulation

## Summary
The AEDPoS consensus validation logic contaminates trusted state data with untrusted block header data before performing security checks. This causes the `LibInformationValidationProvider` to compare `ImpliedIrreversibleBlockHeight` against itself, creating a tautological validation that always passes. Malicious miners can exploit this to manipulate LIB calculations, causing finality regression or denial of service.

## Finding Description

The vulnerability exists in the `ValidateBeforeExecution` method's handling of `UpdateValue` consensus behavior. The critical flaw is that validation retrieves trusted round data from blockchain state, but then contaminates this data with untrusted values from the block header **before** performing validation checks.

**Attack Flow:**

1. **Data Contamination**: The validation process fetches `baseRound` from trusted blockchain state, but then immediately modifies it by calling `RecoverFromUpdateValue` with untrusted data from the block header. [1](#0-0) [2](#0-1) 

2. **State Contamination**: The `RecoverFromUpdateValue` method directly overwrites the trusted `baseRound` with values from the untrusted `providedRound`, specifically setting `ImpliedIrreversibleBlockHeight` to the attacker-controlled value. [3](#0-2) 

3. **Validation Context Creation**: The validation context is created using the now-contaminated `baseRound` where `BaseRound` contains the malicious value and `ProvidedRound` returns the same untrusted data from the block header. [4](#0-3) [5](#0-4) 

4. **Tautological Validation**: The `LibInformationValidationProvider` performs the security check, comparing `baseRound.ImpliedIrreversibleBlockHeight > providedRound.ImpliedIrreversibleBlockHeight`. Since both values are now identical due to contamination, this becomes `X > X`, which always evaluates to false and validation passes. [6](#0-5) 

5. **Malicious Value Persists**: After validation passes, `ProcessUpdateValue` persists the malicious `ImpliedIrreversibleBlockHeight` to blockchain state. [7](#0-6) 

6. **LIB Calculation Manipulation**: The contaminated values are used in LIB calculation, where the algorithm selects the value at position `(count-1)/3` from sorted heights. With control of approximately ⅓ of miners, attackers can manipulate which block height becomes the LIB. [8](#0-7) [9](#0-8) [10](#0-9) 

The vulnerability is confirmed by the fact that `UpdateValueValidationProvider` only validates OutValue and Signature fields, not `ImpliedIrreversibleBlockHeight`: [11](#0-10) 

## Impact Explanation

**Critical Severity - Breaks Fundamental Consensus Invariant**

1. **Finality Regression**: Malicious miners can set `ImpliedIrreversibleBlockHeight` to values below the current LIB (e.g., setting it to 1 when current LIB is 1000). With control of ⅓+ miners (the threshold needed for LIB consensus in the sorting algorithm), attackers can force the LIB to regress to arbitrary heights, violating the irreversibility guarantee that is fundamental to blockchain security.

2. **Finality Denial of Service**: By consistently reporting zero or artificially low values, attackers can prevent the LIB from advancing, indefinitely blocking transaction finality. When zero values are submitted, they pass validation (the check at line 24 of `LibInformationValidationProvider.cs` requires `!= 0` to enter the comparison block), and during LIB calculation, zero values are filtered out, reducing the count of valid heights needed for consensus.

3. **Cross-Chain Security Impact**: Cross-chain bridges and external systems that rely on LIB for confirmation would be affected, potentially allowing double-spend attacks or transaction reversals after supposed finality.

4. **Consensus Disruption**: The LIB calculation's selection of `(count-1)/3` position means malicious miners controlling this threshold can arbitrarily manipulate consensus finality, undermining the network's security model.

The vulnerability directly breaks the monotonicity invariant that LIB heights must always increase, which is a core security guarantee of the consensus protocol.

## Likelihood Explanation

**High Likelihood**

1. **Low Attacker Requirements**: Any authorized miner in the current miner list can exploit this vulnerability. No special privileges beyond standard miner status are required.

2. **Simple Attack Vector**: The exploit requires only:
   - Producing a block with `UpdateValue` behavior (standard operation)
   - Setting `ImpliedIrreversibleBlockHeight` to a malicious value in consensus extra data
   - No complex state setup or timing requirements

3. **Deterministic Success**: The validation bypass is deterministic - the contaminated comparison will always pass, making the exploit 100% reliable when attempted.

4. **Silent Failure**: The bypassed validation means no error or event is raised. Detection requires external monitoring of LIB progression anomalies, making the attack difficult to detect in real-time.

5. **Production Entry Point**: The vulnerability exists in the standard block production and validation flow, making it reachable through normal consensus operations.

## Recommendation

**Fix: Perform validation BEFORE state contamination**

The root cause is that `RecoverFromUpdateValue` is called before validation. The fix is to reorder the operations so that validation occurs on pristine trusted state before any modifications:

```csharp
// In ValidateBeforeExecution method
if (!TryToGetCurrentRoundInformation(out var baseRound))
    return new ValidationResult { Success = false, Message = "Failed to get current round information." };

// Create validation context with uncontaminated baseRound
var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound, // Pristine trusted state
    CurrentTermNumber = State.CurrentTermNumber.Value,
    CurrentRoundNumber = State.CurrentRoundNumber.Value,
    PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
    LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
    ExtraData = extraData
};

// Perform validation first
var validationResult = service.ValidateInformation(validationContext);
if (!validationResult.Success)
    return validationResult;

// Only AFTER validation passes, apply the updates
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**Alternative: Add explicit monotonicity check**

Add a direct comparison between the stored value and provided value before contamination occurs:

```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    var pubkey = extraData.SenderPubkey.ToHex();
    if (baseRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
        extraData.Round.RealTimeMinersInformation.ContainsKey(pubkey))
    {
        var storedHeight = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
        var providedHeight = extraData.Round.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;
        
        if (providedHeight != 0 && storedHeight > providedHeight)
            return new ValidationResult { Success = false, Message = "ImpliedIrreversibleBlockHeight cannot decrease." };
    }
    
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}
```

## Proof of Concept

This vulnerability can be demonstrated by:

1. An authorized miner producing a block with `UpdateValue` consensus behavior
2. Setting `ImpliedIrreversibleBlockHeight` in the block's consensus extra data to a value lower than their previously recorded value (or zero)
3. The block passes validation despite violating the monotonicity invariant
4. The malicious value is persisted to state and influences subsequent LIB calculations
5. With ⅓+ colluding miners, the LIB can be forced to regress or stall

The deterministic bypass occurs because the validation at `LibInformationValidationProvider.cs:25-26` compares the contaminated `baseRound` value (which was overwritten at `Round_Recover.cs:19`) against the same `providedRound` value, creating the tautology that always passes validation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-19)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L22-27)
```csharp
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```
