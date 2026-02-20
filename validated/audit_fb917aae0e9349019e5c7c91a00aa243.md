# Audit Report

## Title
FinalOrderOfNextRound Manipulation Allows Mining Order Centralization

## Summary
The AEDPoS consensus mechanism fails to validate that `FinalOrderOfNextRound` and `SupposedOrderOfNextRound` values are correctly calculated from miners' signatures. A malicious miner can modify these values in block headers to guarantee favorable mining positions in subsequent rounds, centralizing block production without detection.

## Finding Description

The vulnerability exists in the consensus validation and state update flow. The `SupposedOrderOfNextRound` should be deterministically calculated from a miner's signature using the formula `GetAbsModulus(signature.ToInt64(), minersCount) + 1`, which provides unpredictable but fair ordering. [1](#0-0) 

However, the validation gap occurs in `UpdateValueValidationProvider`, which only verifies that `OutValue` and `Signature` fields are non-empty without recalculating or validating the order values: [2](#0-1) 

When processing consensus updates, `ProcessUpdateValue` blindly copies the order values from the input without recalculation: [3](#0-2) 

The `TuneOrderInformation` dictionary is also applied without validation: [4](#0-3) 

These manipulated values directly determine mining positions when the next round is generated, as miners are ordered by their `FinalOrderOfNextRound`: [5](#0-4) 

The after-execution validation also fails because `RecoverFromUpdateValue` copies all miners' order values from the header without recalculation: [6](#0-5) 

This allows `ValidateConsensusAfterExecution` to pass since both the header and state contain the same manipulated values after `RecoverFromUpdateValue` copies them: [7](#0-6) 

## Impact Explanation

This vulnerability breaks the core consensus invariant of fair miner rotation in AEDPoS. A malicious miner can:

1. **Centralize Block Production**: Consistently secure position 1 in each round, mining first and gaining disproportionate block rewards
2. **Unfair Advantage**: Control significantly more blocks than their fair share over time
3. **Consensus Subversion**: Bypass the VRF-based randomization designed to ensure unpredictable, fair miner ordering
4. **Network Decentralization Violation**: A single miner can dominate consensus without requiring majority collusion

The manipulated `FinalOrderOfNextRound` directly controls the `Order` and `ExpectedMiningTime` in subsequent rounds, giving the attacker priority time slots repeatedly. Honest miners lose their fair share of block production opportunities and rewards.

## Likelihood Explanation

**Attacker Requirements:**
- Active miner in consensus set (realistic - anyone can become a miner through election)
- Ability to modify node software (feasible for any sophisticated miner)

**Attack Complexity:** LOW
- Requires only modifying integer values in the Round object before block header serialization
- No cryptographic capabilities needed beyond normal mining operations
- No coordination with other miners required
- Can be executed every time the attacker produces a block

**Detection:** Very difficult
- No on-chain evidence of manipulation (values appear valid)
- All validators accept the manipulated blocks as legitimate
- Would require off-chain statistical monitoring to detect patterns
- The deterministic calculation that should occur is never verified

The attack is highly feasible because miners control their own node software, and the multi-layer validation gap (before-execution, during-execution, and after-execution) allows manipulated blocks to pass all checks.

## Recommendation

Add validation to recalculate and verify `SupposedOrderOfNextRound` from the signature in `UpdateValueValidationProvider`:

```csharp
private bool ValidateOrderCalculation(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Additionally, validate `TuneOrderInformation` to ensure miners cannot arbitrarily tune other miners' orders without proper conflict resolution logic.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanManipulate_FinalOrderOfNextRound()
{
    // Setup: Initialize first round with boot miner
    await AEDPoSContract_FirstRound_BootMiner_Test();
    
    // Attacker (second miner) wants to secure position 1 in next round
    var attackerKeyPair = InitialCoreDataCenterKeyPairs[1];
    KeyPairProvider.SetKeyPair(attackerKeyPair);
    
    // Get consensus command and extra data
    var consensusCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(
        TriggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue()));
    
    var triggerForExtraData = TriggerInformationProvider
        .GetTriggerInformationForBlockHeaderExtraData(consensusCommand.ToBytesValue());
    var extraDataBytes = await AEDPoSContractStub.GetConsensusExtraData.CallAsync(triggerForExtraData);
    var extraData = extraDataBytes.ToConsensusHeaderInformation();
    
    // Create UpdateValueInput from extra data
    var updateValueInput = extraData.Round.ExtractInformationToUpdateConsensus(
        attackerKeyPair.PublicKey.ToHex(), 
        ByteString.CopyFrom(await GenerateRandomProofAsync(attackerKeyPair)));
    
    // MALICIOUS: Manipulate order to always be 1
    updateValueInput.SupposedOrderOfNextRound = 1;
    
    // Execute UpdateValue with manipulated order
    await AEDPoSContractStub.UpdateValue.SendAsync(updateValueInput);
    
    // Verify: The manipulated order was accepted and written to state
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerMinerInfo = currentRound.RealTimeMinersInformation[attackerKeyPair.PublicKey.ToHex()];
    
    // Attacker successfully secured position 1 for next round
    attackerMinerInfo.FinalOrderOfNextRound.ShouldBe(1);
    
    // Complete the round and generate next round
    // ... (complete other miners' blocks)
    
    // In the next round, attacker will have Order = 1 (first mining position)
    // This can be repeated indefinitely, centralizing block production
}
```

## Notes

This vulnerability represents a fundamental flaw in the AEDPoS consensus validation architecture. The lack of order value recalculation across all validation checkpoints (before-execution via `UpdateValueValidationProvider`, during execution via `ProcessUpdateValue`, and after-execution via `ValidateConsensusAfterExecution`) creates a complete bypass of the intended VRF-based fair ordering mechanism.

The issue is particularly severe because:
1. It affects consensus-level operations, not just individual contracts
2. The manipulated values persist across rounds, compounding the attack's effect
3. Detection requires off-chain statistical analysis rather than on-chain validation
4. The attack can be executed unilaterally by any single miner without coordination

The recommended fix should be implemented at multiple layers to ensure defense-in-depth: validation in `UpdateValueValidationProvider`, recalculation in `ProcessUpdateValue`, and verification in after-execution validation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```
