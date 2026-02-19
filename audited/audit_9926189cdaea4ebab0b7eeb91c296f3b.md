### Title
Pre-Validation State Corruption in UpdateValue Consensus Validation Allows Bypassing Last Irreversible Block Height Checks

### Summary
The `ValidateBeforeExecution` method modifies the trusted `baseRound` object in-place with untrusted data from `extraData.Round` before validation occurs. This causes `LibInformationValidationProvider` to compare the corrupted `baseRound.ImpliedIrreversibleBlockHeight` against the same attacker-controlled value, making the validation check ineffective and allowing Last Irreversible Block (LIB) heights to move backwards, violating a critical consensus invariant.

### Finding Description

In the consensus validation flow, `ValidateBeforeExecution` retrieves the current round information from state and then immediately corrupts it with untrusted data before any validation checks are performed. [1](#0-0) 

The trusted `baseRound` is then modified in-place using the attacker-controlled `extraData.Round`: [2](#0-1) 

The `RecoverFromUpdateValue` method overwrites critical fields in `baseRound`, including `ImpliedIrreversibleBlockHeight`: [3](#0-2) 

Since `MappedState` returns a reference to the cached object rather than a copy: [4](#0-3) 

The validation context is created with this corrupted `baseRound`: [5](#0-4) 

For UpdateValue behavior, `LibInformationValidationProvider` is added to validate LIB information: [6](#0-5) 

The `LibInformationValidationProvider` attempts to ensure `ImpliedIrreversibleBlockHeight` doesn't decrease, but because `baseRound` was already corrupted, it compares the same attacker-provided value against itself: [7](#0-6) 

At line 25, `baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` has already been overwritten with the attacker's value from line 19 of `RecoverFromUpdateValue`. The check becomes: `attackerValue > attackerValue`, which is always false, causing validation to pass even when LIB height moves backwards.

After validation passes, the consensus transaction is generated using the malicious round data: [8](#0-7) 

The `ExtractInformationToUpdateConsensus` method extracts the malicious `ImpliedIrreversibleBlockHeight`: [9](#0-8) 

Finally, `ProcessUpdateValue` persists the malicious value to state: [10](#0-9) 

### Impact Explanation

This vulnerability allows any miner to manipulate the `ImpliedIrreversibleBlockHeight` to any arbitrary value, including moving it backwards, which violates the fundamental consensus invariant that Last Irreversible Block (LIB) heights must monotonically increase.

**Concrete Harms:**
1. **Consensus State Corruption**: The permanently stored consensus state contains invalid LIB height information that has moved backwards (e.g., from height 1000 to 500)
2. **Finality Violation**: LIB heights are used to determine block finality. Moving them backwards undermines the irreversibility guarantee, potentially enabling:
   - Double-spend attacks on finalized transactions
   - Reorganization of supposedly irreversible blocks
   - Cross-chain message replay vulnerabilities
3. **Protocol-Wide Impact**: All nodes relying on LIB height for finality decisions are affected, compromising the entire consensus mechanism

The severity is **Critical** because it directly violates the "LIB height rules" invariant specified in the audit requirements and affects the core consensus integrity of the blockchain.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner in the current round (has mining permission)
- Can craft consensus header information in produced blocks
- No special privileges beyond being a scheduled miner

**Attack Complexity:**
The attack is straightforward:
1. Miner waits for their scheduled time slot
2. Crafts a block with `extraData.Round.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight` set to a backwards value
3. Includes valid `OutValue` and `Signature` to pass `UpdateValueValidationProvider` checks
4. The corrupted LIB validation passes due to the pre-validation state modification
5. Block is accepted and malicious data is persisted

**Feasibility Conditions:**
- Attack is executable in normal operation
- No unusual chain state required
- Detection is difficult as the validation appears to pass normally
- Cost is minimal (just producing a block during scheduled slot)

**Probability:** High - Any malicious miner can execute this during their normal mining slot without detection until the corrupted state causes downstream issues.

### Recommendation

**Immediate Fix:**
Modify `ValidateBeforeExecution` to clone `baseRound` before passing it to `RecoverFromUpdateValue`, ensuring validation providers check against the original trusted state:

```csharp
// In ValidateBeforeExecution, before line 46:
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    var recoveredRound = baseRound.Clone(); // Create a copy
    recoveredRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
    
    var validationContext = new ConsensusValidationContext
    {
        BaseRound = baseRound, // Use original untouched baseRound
        ProvidedRound = recoveredRound, // Use recovered round for other checks
        // ... other fields
    };
}
```

Alternatively, refactor to perform validation BEFORE any state recovery:

```csharp
// Validate first using original baseRound and providedRound (extraData.Round)
var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound, // Original state
    // ProvidedRound already comes from ExtraData
    // ... other fields
};

// Run validators with untouched baseRound
var validationResult = service.ValidateInformation(validationContext);

// ONLY after validation passes, perform recovery for other purposes
if (validationResult.Success && extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**Additional Safeguards:**
1. Add explicit check in `LibInformationValidationProvider` that reads fresh state instead of using potentially corrupted `baseRound`
2. Add unit tests that verify LIB height cannot decrease through UpdateValue operations
3. Add monitoring/assertions that detect when stored LIB heights decrease between rounds

### Proof of Concept

**Initial State:**
- Current round number: 100
- Miner "MinerA" is in the active miner list
- `State.Rounds[100].RealTimeMinersInformation["MinerA"].ImpliedIrreversibleBlockHeight = 1000`

**Attack Steps:**
1. MinerA is scheduled to produce block at height 10000
2. MinerA crafts consensus header with:
   - `extraData.Behaviour = AElfConsensusBehaviour.UpdateValue`
   - `extraData.Round.RealTimeMinersInformation["MinerA"].OutValue = <valid_value>`
   - `extraData.Round.RealTimeMinersInformation["MinerA"].Signature = <valid_signature>`
   - `extraData.Round.RealTimeMinersInformation["MinerA"].ImpliedIrreversibleBlockHeight = 500` (BACKWARDS!)
   - `extraData.Round.RealTimeMinersInformation["MinerA"].ActualMiningTimes = [current_time]`

3. Block undergoes validation in `ValidateConsensusBeforeExecution`:
   - `baseRound` loaded with `ImpliedIrreversibleBlockHeight = 1000`
   - `RecoverFromUpdateValue` overwrites it to `500`
   - `LibInformationValidationProvider` checks: `500 > 500`? No → Validation **PASSES**

4. Block is accepted and `UpdateValue` transaction executes:
   - `ProcessUpdateValue` persists `ImpliedIrreversibleBlockHeight = 500` to state
   - State is now corrupted with backwards LIB height

**Expected Result:** Validation should REJECT the block because `1000 > 500` (LIB went backwards)

**Actual Result:** Validation ACCEPTS the block because it compares `500 > 500` (corrupted value against itself), and the backwards LIB height is permanently stored in consensus state.

**Success Condition:** Query `State.Rounds[100].RealTimeMinersInformation["MinerA"].ImpliedIrreversibleBlockHeight` after the attack shows `500` instead of the expected value ≥ `1000`, demonstrating successful LIB manipulation.

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

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L26-36)
```csharp
    public TEntity this[TKey key]
    {
        get
        {
            if (!Cache.TryGetValue(key, out var valuePair))
            {
                valuePair = LoadKey(key);
                Cache[key] = valuePair;
            }

            return valuePair.IsDeleted ? SerializationHelper.Deserialize<TEntity>(null) : valuePair.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L48-48)
```csharp
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```
