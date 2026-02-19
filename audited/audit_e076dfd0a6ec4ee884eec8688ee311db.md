# Audit Report

## Title 
Pre-Validation State Corruption in UpdateValue Consensus Validation Allows Bypassing Last Irreversible Block Height Checks

## Summary
The `ValidateBeforeExecution` method in the AEDPoS consensus contract modifies trusted round state with untrusted block header data before validation occurs, causing the `LibInformationValidationProvider` to compare corrupted values against themselves. This allows miners to set backwards `ImpliedIrreversibleBlockHeight` values, violating the consensus invariant that LIB heights must monotonically increase.

## Finding Description

The vulnerability exists in the consensus block validation flow where the order of operations allows state corruption before security checks are performed.

The trusted `baseRound` is retrieved from state [1](#0-0)  but is then immediately modified in-place with attacker-controlled data from the block header [2](#0-1) 

The `RecoverFromUpdateValue` method overwrites critical consensus fields including `ImpliedIrreversibleBlockHeight` [3](#0-2) 

Since `Round` is a reference type [4](#0-3)  and state access returns cached objects [5](#0-4) , the modification affects the actual validation context created afterwards [6](#0-5) 

For UpdateValue behavior, the `LibInformationValidationProvider` is added to validate LIB information [7](#0-6) 

The validation check attempts to ensure `ImpliedIrreversibleBlockHeight` doesn't decrease [8](#0-7)  but because `baseRound` was already corrupted at line 19 of `RecoverFromUpdateValue`, it compares the attacker's value against itself (attackerValue > attackerValue = false), causing validation to pass even when LIB height moves backwards.

The validation context provides `ProvidedRound` as a property that returns the attacker-controlled `ExtraData.Round` [9](#0-8) 

After validation passes, the malicious round data is used to generate consensus transactions [10](#0-9)  with `ExtractInformationToUpdateConsensus` extracting the malicious `ImpliedIrreversibleBlockHeight` [11](#0-10) 

Finally, `ProcessUpdateValue` directly assigns the malicious value without additional checks [12](#0-11)  and persists it to state [13](#0-12) 

## Impact Explanation

This vulnerability allows any miner to set their `ImpliedIrreversibleBlockHeight` to arbitrary backwards values, directly violating the consensus invariant that Last Irreversible Block heights must be monotonically increasing.

**Concrete harms:**
1. **Consensus State Corruption**: Invalid LIB height information is permanently persisted to consensus state, with per-miner values moving backwards (e.g., from 1000 to 500)
2. **LIB Calculation Manipulation**: The corrupted values are used in future LIB calculations [14](#0-13)  which aggregate implied irreversible heights from multiple miners [15](#0-14) 
3. **Finality Guarantee Degradation**: While the round-level `ConfirmedIrreversibleBlockHeight` has a protection preventing backwards movement, the corrupted per-miner values undermine the Byzantine fault tolerance assumptions of the BFT-based LIB calculation

The severity is **Critical** because it directly violates fundamental consensus invariants and enables persistent state corruption that affects the integrity of the entire consensus mechanism.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round (scheduled mining permission)
- Can craft consensus header information in produced blocks
- No special privileges beyond normal miner capabilities

**Attack Execution:**
1. Miner produces block during scheduled time slot
2. Crafts block header with `extraData.Round.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` set to a backwards value
3. Includes valid `OutValue` and `Signature` to pass other validation checks [16](#0-15) 
4. The LIB validation passes due to pre-corruption of `baseRound`
5. Block is accepted and malicious data persists

**Feasibility:** High - executable during normal mining operations with no unusual chain state required. Detection is difficult as validation appears to pass normally.

## Recommendation

Reorder the validation flow to prevent state corruption before validation:

1. **Perform validation BEFORE modifying baseRound**: Move the `RecoverFromUpdateValue` call to occur AFTER validation completes successfully
2. **Use immutable validation context**: Create the validation context with the original untrusted `providedRound` and compare against the pristine `baseRound` from state
3. **Explicit validation of monotonicity**: Add an explicit check that compares the provided `ImpliedIrreversibleBlockHeight` against the current value in state before any modification occurs

Example fix structure:
```
// 1. Get trusted state
TryToGetCurrentRoundInformation(out var baseRound);

// 2. Create validation context WITHOUT modifying baseRound
var validationContext = new ConsensusValidationContext { 
    BaseRound = baseRound,  // Pristine from state
    // ... other fields
};

// 3. Run validation (now compares pristine vs. provided)
var validationResult = service.ValidateInformation(validationContext);
if (!validationResult.Success) return validationResult;

// 4. ONLY AFTER validation passes, apply the recovery
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, pubkey);
```

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up a miner with an existing `ImpliedIrreversibleBlockHeight` of 1000
2. Craft a block header with the same miner's `ImpliedIrreversibleBlockHeight` set to 500 (backwards)
3. Call `ValidateConsensusBeforeExecution` with this header
4. Verify validation passes (when it should fail)
5. Execute the corresponding `UpdateValue` transaction
6. Verify the state now contains the backwards value of 500

The test would demonstrate that the validation check at `LibInformationValidationProvider` line 25 fails to catch the backwards movement because both sides of the comparison contain the same attacker-provided value (500 > 500 = false, so no error is raised).

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L137-147)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                Context.LogDebug(() =>
                    $"Previous in value in extra data:{round.RealTimeMinersInformation[pubkey.ToHex()].PreviousInValue}");
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L35-50)
```csharp
        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
            PreviousInValue = minerInRound.PreviousInValue ?? Hash.Empty,
            RoundId = RoundIdForValidation,
            ProducedBlocks = minerInRound.ProducedBlocks,
            ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
            TuneOrderInformation = { tuneOrderInformation },
            EncryptedPieces = { minerInRound.EncryptedPieces },
            DecryptedPieces = { decryptedPreviousInValues },
            MinersPreviousInValues = { minersPreviousInValues },
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
            RandomNumber = randomNumber
        };
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
