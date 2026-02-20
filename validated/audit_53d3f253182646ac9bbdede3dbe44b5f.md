# Audit Report

## Title 
Pre-Validation State Corruption in UpdateValue Consensus Validation Allows Bypassing Last Irreversible Block Height Checks

## Summary
The `ValidateBeforeExecution` method in the AEDPoS consensus contract modifies the trusted round state object with untrusted block header data before validation occurs. This causes the `LibInformationValidationProvider` to compare the attacker's value against itself, allowing miners to set backwards `ImpliedIrreversibleBlockHeight` values and violate the consensus invariant that LIB heights must monotonically increase.

## Finding Description

The vulnerability exists due to an incorrect order of operations in the consensus block validation flow where state modification occurs before security validation.

The validation method retrieves the current round from state [1](#0-0) , but then immediately modifies this object in-place with attacker-controlled data from the block header [2](#0-1) .

The `RecoverFromUpdateValue` method directly overwrites critical consensus fields including `ImpliedIrreversibleBlockHeight` with the attacker's provided values [3](#0-2) . Since `Round` is a reference type (class) [4](#0-3) , this modification affects the actual object that is then used in the validation context created afterwards [5](#0-4) .

For UpdateValue behavior, the `LibInformationValidationProvider` is added to validate LIB information [6](#0-5) . The validation check attempts to ensure `ImpliedIrreversibleBlockHeight` doesn't decrease [7](#0-6) , but because `baseRound` was already corrupted by the attacker's value, it compares `attackerValue > attackerValue` which evaluates to false, causing validation to pass even when LIB height moves backwards.

The validation context provides `ProvidedRound` as a property that returns the attacker-controlled data [8](#0-7) . After validation passes, the malicious round data is used in consensus processing [9](#0-8) , and `ProcessUpdateValue` directly assigns the malicious `ImpliedIrreversibleBlockHeight` value without additional checks [10](#0-9)  before persisting it to state [11](#0-10) .

## Impact Explanation

This vulnerability allows any miner to set their `ImpliedIrreversibleBlockHeight` to arbitrary backwards values, directly violating the consensus invariant that Last Irreversible Block heights must be monotonically increasing.

**Concrete harms:**

1. **Consensus State Corruption**: Invalid LIB height information is permanently persisted to consensus state, with per-miner values moving backwards (e.g., from block height 1000 to 500).

2. **LIB Calculation Manipulation**: The corrupted per-miner values are used in future LIB calculations [12](#0-11) , which aggregate implied irreversible heights from multiple miners to compute the network's LIB [13](#0-12) .

3. **Finality Guarantee Degradation**: While the round-level `ConfirmedIrreversibleBlockHeight` has protection preventing backwards movement, the corrupted per-miner values undermine the Byzantine fault tolerance assumptions of the BFT-based LIB calculation, potentially preventing proper LIB advancement.

The severity is **Critical** because it directly violates fundamental consensus invariants and enables persistent state corruption that affects the integrity of the entire consensus mechanism's finality guarantees.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round (scheduled mining permission)
- Can craft consensus header information in produced blocks
- No special privileges beyond normal miner capabilities

**Attack Execution:**
1. Miner produces block during their scheduled time slot
2. Crafts block header with `extraData.Round.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` set to a backwards value (lower than current legitimate value)
3. Includes valid `OutValue` and `Signature` to pass other validation checks [14](#0-13) 
4. The LIB validation passes because `baseRound` was pre-corrupted with the attacker's value
5. Block is accepted and malicious data persists to state

**Feasibility:** High - this is executable during normal mining operations with no unusual chain state required. The attack is difficult to detect as all validations appear to pass normally from an observer's perspective.

## Recommendation

The validation logic must use an unmodified copy of the base round state for comparison. The fix should:

1. **Create a defensive copy** before any modifications:
```csharp
if (!TryToGetCurrentRoundInformation(out var originalBaseRound))
    return new ValidationResult { Success = false, Message = "Failed to get current round information." };

// Create a copy for modification
var baseRound = originalBaseRound.Clone(); // Or create new Round instance

// Now modify the copy
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

2. **Use the original unmodified round in validation context**:
```csharp
var validationContext = new ConsensusValidationContext
{
    BaseRound = originalBaseRound,  // Use unmodified original
    // ... other fields
};
```

This ensures the `LibInformationValidationProvider` compares the attacker's provided value against the legitimate current state value, not against itself.

## Proof of Concept

A proof of concept would require:
1. Setting up an AElf test chain with multiple miners
2. Having one miner node modified to craft malicious consensus header data
3. Setting `ImpliedIrreversibleBlockHeight` to a value lower than the current legitimate value in state
4. Verifying the block is accepted and the backwards value is persisted
5. Observing the corrupted state affects subsequent LIB calculations

The vulnerability is confirmed by code analysis showing the order-of-operations flaw where `baseRound` is modified before being used in validation, causing the security check to become ineffective.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L14-32)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L13-13)
```csharp
public partial class Round
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L268-270)
```csharp
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```
