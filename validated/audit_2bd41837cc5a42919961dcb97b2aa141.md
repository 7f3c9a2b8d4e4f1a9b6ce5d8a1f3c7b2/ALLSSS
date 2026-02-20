# Audit Report

## Title
Broken ImpliedIrreversibleBlockHeight Validation Allows LIB Manipulation

## Summary
The `LibInformationValidationProvider.ValidateHeaderInformation()` contains a broken validation check that always passes due to premature state modification by `RecoverFromUpdateValue()`. This allows miners to set arbitrary `ImpliedIrreversibleBlockHeight` values without proper validation, enabling Last Irreversible Block (LIB) manipulation when sufficient miners collude.

## Finding Description

**Root Cause:**

The validation logic in `LibInformationValidationProvider` attempts to prevent `ImpliedIrreversibleBlockHeight` from decreasing, but this check is completely ineffective due to an ordering flaw in the validation flow. [1](#0-0) 

**Why the Check Fails:**

Before validation occurs, `ValidateBeforeExecution` calls `RecoverFromUpdateValue()` which modifies `baseRound` by copying the `providedRound`'s `ImpliedIrreversibleBlockHeight` value: [2](#0-1) 

The `RecoverFromUpdateValue` method directly assigns the provided value to the base round: [3](#0-2) 

After this assignment executes, `baseRound[pubkey].ImpliedIrreversibleBlockHeight` equals `providedRound[pubkey].ImpliedIrreversibleBlockHeight`. The validation context is then created with this already-modified `baseRound`: [4](#0-3) 

The subsequent validation check compares this value to itself, making the condition `baseRound[pubkey].ImpliedIrreversibleBlockHeight > providedRound[pubkey].ImpliedIrreversibleBlockHeight` always evaluate to false (validation passes).

**Expected vs Actual Behavior:**

During normal UpdateValue behavior, miners should set `ImpliedIrreversibleBlockHeight` to the current block height: [5](#0-4) 

However, a malicious miner can modify this value to any arbitrary number in their block header, and the broken validation will accept it. This value is then directly stored in the round state: [6](#0-5) 

## Impact Explanation

**Consensus Integrity Violation:**

These manipulated `ImpliedIrreversibleBlockHeight` values are directly used in LIB calculation in subsequent rounds. The LIB calculator retrieves sorted implied heights from the previous round: [7](#0-6) 

It then selects the LIB value using a 2/3+1 consensus mechanism: [8](#0-7) 

The formula takes the value at position `(count-1)/3` from sorted heights, meaning approximately 1/3 of miners can influence which value is selected as LIB.

**Attack Scenarios:**

1. **LIB Stalling (DoS):** If >1/3 of miners collude and report artificially low `ImpliedIrreversibleBlockHeight` values (e.g., 0 or far behind actual height), the LIB calculation will select these low values, preventing LIB from advancing. This stalls cross-chain operations, block pruning, and transaction finality guarantees.

2. **Premature LIB Advancement (Critical):** If >1/3 of miners report artificially high `ImpliedIrreversibleBlockHeight` values (exceeding actual irreversible height), the LIB could advance beyond truly irreversible blocks, causing false finality signals, enabling potential chain reorganizations after "finality", and violating Byzantine fault tolerance guarantees.

**Affected Parties:**
- All chain participants relying on LIB for finality
- Cross-chain bridges and side-chain operations  
- Applications requiring transaction finality guarantees

## Likelihood Explanation

**Attacker Capabilities:**
- Any active miner can exploit this by modifying their block header's consensus extra data
- No special permissions required beyond being in the current miner list
- Single miner can influence LIB calculation (limited by 2/3+1 consensus)
- >1/3 colluding miners can fully control LIB progression

**Attack Complexity:**
- Low: Simply set `ImpliedIrreversibleBlockHeight` to arbitrary values in block headers during block production
- The validation is broken and will always pass
- No cryptographic or computational barriers
- No on-chain transaction required, just modify consensus extra data

**Feasibility Conditions:**
- Miner must be in active rotation (normal consensus operation)
- For significant impact, requires >1/3 miner collusion
- Detection: Malicious values would be visible on-chain but may not trigger alarms without specific monitoring

**Overall Likelihood:** Medium to High
- Single miner: Can set arbitrary values with limited but measurable impact
- Colluding miners (>1/3): High impact scenario, realistic in adversarial conditions or during miner set transitions

## Recommendation

**Fix the Validation Order:**

The validation should occur BEFORE modifying the base round. Move the validation logic to compare against the ORIGINAL state from storage, not the recovered state.

**Option 1 - Validate Before Recovery:**
```csharp
// In ValidateBeforeExecution, validate BEFORE calling RecoverFromUpdateValue
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    // Store original value
    var originalImpliedHeight = baseRound.RealTimeMinersInformation.ContainsKey(extraData.SenderPubkey.ToHex()) 
        ? baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight 
        : 0;
    
    // Validate against original
    var providedHeight = extraData.Round.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()].ImpliedIrreversibleBlockHeight;
    if (providedHeight != 0 && originalImpliedHeight > providedHeight)
    {
        return new ValidationResult { Success = false, Message = "Incorrect implied lib height." };
    }
    
    // Also validate it doesn't exceed current height
    if (providedHeight > Context.CurrentHeight)
    {
        return new ValidationResult { Success = false, Message = "Implied lib height exceeds current height." };
    }
    
    // Now recover
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}
```

**Option 2 - Store Original in Context:**
Pass the unmodified original round to the validation context as a separate field, and validate against that instead of the modified `BaseRound`.

**Additional Validations Needed:**
1. Validate `ImpliedIrreversibleBlockHeight <= Context.CurrentHeight` (upper bound check)
2. Validate monotonic increase per miner
3. Consider adding reasonableness checks (e.g., not more than N blocks behind current height)

## Proof of Concept

```csharp
[Fact]
public async Task ImpliedIrreversibleBlockHeight_Validation_Is_Broken_Test()
{
    // Setup: Initialize consensus and advance to a normal round
    var minerKeyPair = InitialCoreDataCenterKeyPairs[0];
    KeyPairProvider.SetKeyPair(minerKeyPair);
    
    // Get current round to see the current ImpliedIrreversibleBlockHeight
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerPubkey = minerKeyPair.PublicKey.ToHex();
    var originalImpliedHeight = currentRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight;
    
    // Generate consensus command for UpdateValue
    var triggerForCommand = TriggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue());
    var consensusCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(triggerForCommand);
    consensusCommand.Hint = new AElfConsensusHint { Behaviour = AElfConsensusBehaviour.UpdateValue }.ToByteString();
    
    // Get consensus extra data
    var triggerForExtraData = TriggerInformationProvider.GetTriggerInformationForBlockHeaderExtraData(consensusCommand.ToBytesValue());
    var extraDataBytes = await AEDPoSContractStub.GetConsensusExtraData.CallAsync(triggerForExtraData);
    var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(extraDataBytes.Value);
    
    // ATTACK: Modify ImpliedIrreversibleBlockHeight to an artificially LOW value (e.g., 0)
    // This should fail validation but will pass due to the bug
    extraData.Round.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight = 0;
    
    // Validate - this should FAIL but will PASS due to the broken validation
    var modifiedExtraDataBytes = extraData.ToBytesValue();
    var validationResult = await AEDPoSContractStub.ValidateConsensusBeforeExecution.CallAsync(modifiedExtraDataBytes);
    
    // BUG: Validation passes even though we decreased ImpliedIrreversibleBlockHeight from originalImpliedHeight to 0
    validationResult.Success.ShouldBeTrue(); // This proves the vulnerability - validation should have failed!
    
    // Alternative attack: Set to artificially HIGH value (e.g., far in the future)
    extraData.Round.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight = 999999;
    modifiedExtraDataBytes = extraData.ToBytesValue();
    validationResult = await AEDPoSContractStub.ValidateConsensusBeforeExecution.CallAsync(modifiedExtraDataBytes);
    
    // BUG: This also passes even though it's way beyond current height
    validationResult.Success.ShouldBeTrue(); // Validation broken - should have failed!
}
```

## Notes

The vulnerability exists in the consensus validation flow where `RecoverFromUpdateValue()` is called before the validation providers run. This causes the validation context's `BaseRound` to already contain the attacker-provided values, making the validation check compare a value to itself.

The LIB calculation mechanism uses these stored values from previous rounds with a 2/3+1 consensus rule. While this provides some protection against single malicious miners, it means approximately 1/3 of miners colluding can manipulate which value gets selected as the LIB, potentially stalling or prematurely advancing chain finality.

This is a critical consensus-layer vulnerability that violates the Byzantine fault tolerance guarantees of the system by allowing manipulation of the Last Irreversible Block height, which is fundamental to transaction finality and cross-chain security.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-26)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```
