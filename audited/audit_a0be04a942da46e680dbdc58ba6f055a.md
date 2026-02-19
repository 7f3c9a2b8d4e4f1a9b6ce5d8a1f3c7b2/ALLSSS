# Audit Report

## Title
ImpliedIrreversibleBlockHeight Validation Bypass Due to Premature State Recovery

## Summary
The `LibInformationValidationProvider` validation logic is fundamentally broken because `RecoverFromUpdateValue` modifies the `baseRound` state before validation providers execute. This causes the validation to compare identical values instead of StateDb values against provided values, allowing malicious miners to report artificially low `ImpliedIrreversibleBlockHeight` values that bypass detection, potentially preventing Last Irreversible Block (LIB) advancement and disrupting chain finality.

## Finding Description

The vulnerability exists in the consensus validation flow for `UpdateValue` behavior. The validation process executes in this sequence:

1. **Load State**: The validation method loads `baseRound` from StateDb containing the current miner information [1](#0-0) 

2. **Premature Recovery**: Before validation providers run, `RecoverFromUpdateValue` is called on `baseRound`, which overwrites the miner's `ImpliedIrreversibleBlockHeight` with the value from the provided round [2](#0-1) 

3. **State Overwrite**: The recovery method copies the provided `ImpliedIrreversibleBlockHeight` into `baseRound`, destroying the original StateDb value [3](#0-2) 

4. **Broken Validation**: The `LibInformationValidationProvider` attempts to validate that the height hasn't decreased by comparing `baseRound` against `providedRound` [4](#0-3) 

However, the `ProvidedRound` property returns `ExtraData.Round`, which is the original provided round [5](#0-4) 

**Root Cause**: After step 3, both `baseRound[pubkey].ImpliedIrreversibleBlockHeight` and `providedRound[pubkey].ImpliedIrreversibleBlockHeight` contain the same provided value. The validation check becomes `providedValue > providedValue`, which is always false, rendering the validation ineffective.

**Attack Vector**: Miners can tamper with consensus extra data because:
- The contract generates `ImpliedIrreversibleBlockHeight = Context.CurrentHeight` when creating consensus data [6](#0-5) 
- This data is returned to the miner who can modify it before signing the block
- No cryptographic binding protects individual fields within the consensus extra data

**LIB Calculation Impact**: The tampered values directly affect LIB calculation, where heights are sorted and the value at position `(count-1)/3` becomes the new LIB [7](#0-6) 

## Impact Explanation

**High Severity - Consensus Liveness Attack**:

1. **LIB Advancement Prevention**: If 1/3+ miners collude to report artificially low `ImpliedIrreversibleBlockHeight` values, the calculated LIB height will be suppressed to the lowest values in the consensus set. This prevents legitimate blocks from achieving irreversible status.

2. **Transaction Finality Disruption**: Users cannot achieve finality guarantees on their transactions, undermining confidence in the blockchain's reliability and affecting economic activity.

3. **Cross-Chain Synchronization Failure**: LIB height is critical for cross-chain merkle proof validation. Stalled LIB prevents parent/side-chain synchronization and cross-chain asset transfers.

4. **State Management Crisis**: LIB determines which blocks can be pruned from state storage. Preventing LIB advancement causes unbounded state growth, leading to resource exhaustion.

**Severity Justification**: While the check at line 272 prevents LIB from decreasing [8](#0-7) , preventing LIB from advancing constitutes a severe operational impact classified as HIGH severity due to its effect on chain liveness and finality guarantees.

## Likelihood Explanation

**Medium Likelihood**:

**Attacker Requirements**:
- Must be elected as a miner through the governance mechanism
- Requires control over block production process to tamper with consensus extra data
- Needs 1/3+ miners for significant LIB impact

**Attack Complexity**:
- **Low technical complexity**: Individual miner can simply modify the height value before signing
- **Medium coordination complexity**: Achieving 1/3+ collusion requires coordinating multiple malicious actors
- **No cryptographic barriers**: The field has no signature or hash protection beyond the block-level signature

**Feasibility**:
- Validation happens sequentially during block processing [9](#0-8) 
- Post-execution validation also cannot detect tampering since StateDb is already updated with fake values during execution [10](#0-9) 

**Detection Constraints**:
- Attack is detectable through off-chain monitoring of miner behavior
- Miners risk reputation and economic stake through the election mechanism
- Subtle deviations may go unnoticed without explicit monitoring

## Recommendation

**Fix: Preserve Original StateDb Value for Validation**

The validation should occur BEFORE `RecoverFromUpdateValue` modifies the state. Refactor the validation flow:

```csharp
// In AEDPoSContract_Validation.cs, modify ValidateBeforeExecution:

// Create validation context BEFORE recovery
var validationContext = new ConsensusValidationContext
{
    BaseRound = baseRound.Clone(), // Use a clone to preserve original
    CurrentTermNumber = State.CurrentTermNumber.Value,
    CurrentRoundNumber = State.CurrentRoundNumber.Value,
    PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
    LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
    ExtraData = extraData
};

// Run validation with original StateDb values
var validationResult = service.ValidateInformation(validationContext);
if (!validationResult.Success) return validationResult;

// ONLY AFTER validation passes, recover the state
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**Alternative Fix: Store Original Value**

Modify `LibInformationValidationProvider` to compare against a preserved original:

```csharp
// Store original value before recovery in validation context
var originalImpliedHeight = baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight;

// Then in LibInformationValidationProvider:
if (providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
    originalImpliedHeight > providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
{
    validationResult.Message = "Incorrect implied lib height.";
    return validationResult;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ImpliedIrreversibleBlockHeight_Validation_Bypass_Test()
{
    // Setup: Initialize consensus with first round
    await InitializeConsensusAndMineFirstBlock();
    
    // Get current round to see the legitimate ImpliedIrreversibleBlockHeight
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var miner = InitialCoreDataCenterKeyPairs[0];
    KeyPairProvider.SetKeyPair(miner);
    var minerPubkey = miner.PublicKey.ToHex();
    var legitimateHeight = currentRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight;
    
    // Advance blockchain to create higher legitimate height
    await ProduceNormalBlocks(10);
    
    // Get consensus command for UpdateValue
    var triggerForCommand = TriggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue());
    var consensusCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(triggerForCommand);
    
    // Generate consensus extra data
    var triggerForExtraData = TriggerInformationProvider
        .GetTriggerInformationForBlockHeaderExtraData(consensusCommand.ToBytesValue());
    var extraDataBytes = await AEDPoSContractStub.GetConsensusExtraData.CallAsync(triggerForExtraData);
    var extraData = extraDataBytes.ToConsensusHeaderInformation();
    
    // ATTACK: Tamper with ImpliedIrreversibleBlockHeight to artificially low value
    var maliciousHeight = legitimateHeight - 5; // Report lower height than previous
    extraData.Round.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight = maliciousHeight;
    
    // Attempt validation - should reject but due to bug, it passes
    var validationResult = await AEDPoSContractStub.ValidateConsensusBeforeExecution
        .CallAsync(extraData.ToBytesValue());
    
    // BUG: Validation incorrectly passes even though height decreased
    validationResult.Success.ShouldBeTrue(); // This demonstrates the vulnerability
    
    // Further verification: Execute the update
    var trigger = AElfConsensusTriggerInformation.Parser.ParseFrom(triggerForExtraData.Value);
    trigger.RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(miner));
    await AEDPoSContractStub.UpdateValue.SendAsync(ExtractUpdateValueInput(extraData, trigger));
    
    // Verify the malicious low value was accepted into state
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    updatedRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight
        .ShouldBe(maliciousHeight); // Proves fake value was persisted
}
```

## Notes

This vulnerability represents a critical flaw in the consensus validation architecture where state recovery occurs before validation, fundamentally breaking the validation's ability to detect malicious inputs. The fix requires careful refactoring of the validation sequence to ensure original StateDb values are preserved for comparison. The vulnerability is particularly serious because it affects the core finality mechanism of the blockchain, though it requires malicious behavior from elected miners rather than being exploitable by arbitrary users.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L32-32)
```csharp
            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-272)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
```
