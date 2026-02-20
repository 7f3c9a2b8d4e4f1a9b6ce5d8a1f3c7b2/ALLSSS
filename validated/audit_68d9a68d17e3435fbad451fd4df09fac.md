# Audit Report

## Title
Miners Can Manipulate Mining Order by Providing Arbitrary SupposedOrderOfNextRound Values

## Summary
The AEDPoS consensus contract accepts `SupposedOrderOfNextRound` values from miners without validating that they match the cryptographically-calculated value derived from their signature. This allows malicious miners to arbitrarily control their mining position in subsequent rounds, breaking the consensus mechanism's fairness guarantees.

## Finding Description

The AEDPoS consensus mechanism is designed to determine each miner's position in the next round based on their cryptographic signature using the formula `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [1](#0-0) 

This proper calculation occurs in `ApplyNormalConsensusData`, which is called by the view function `GetConsensusExtraDataToPublishOutValue` when generating consensus data. [2](#0-1) 

However, when miners submit `UpdateValue` transactions, the contract directly assigns the `SupposedOrderOfNextRound` value from the input without any recalculation or validation. [3](#0-2) 

The validation phase only uses `UpdateValueValidationProvider`, which checks that `OutValue` and `Signature` are non-null/non-empty and validates the `PreviousInValue` relationship, but does NOT verify the `SupposedOrderOfNextRound` calculation. [4](#0-3) [5](#0-4) 

The `NextRoundMiningOrderValidationProvider` that could validate mining order is only applied for `NextRound` behavior, not for `UpdateValue` behavior. [6](#0-5) 

Furthermore, even this validator only checks counts, not individual value correctness. [7](#0-6) 

The manipulated `SupposedOrderOfNextRound` becomes `FinalOrderOfNextRound`, which directly determines mining order when `GenerateNextRoundInformation` creates the next round. [8](#0-7) 

## Impact Explanation

This vulnerability fundamentally breaks the consensus mechanism's cryptographic fairness guarantees. A malicious miner can:

1. **Control Mining Position**: Consistently choose to be first in mining order by setting `SupposedOrderOfNextRound = 1`, gaining priority in block production and rewards
2. **Produce Extra Blocks**: First miners can produce additional blocks when subsequent miners are late or offline, earning extra rewards
3. **Manipulate Consensus Flow**: By controlling their position, miners can influence round transitions and potentially the sequence of random number generation
4. **Enable Collusion**: Multiple malicious miners can coordinate to systematically manipulate the mining schedule across rounds

The severity is critical because mining order should be unpredictable and determined by cryptographic signatures, not miner choice. This affects all honest miners who lose their fair chance at preferential positions, and compromises the integrity of the consensus mechanism itself.

## Likelihood Explanation

The attack is highly practical with minimal complexity:

**Attacker Requirements**: Any active miner in the consensus set can execute this attack.

**Attack Steps**:
1. Miner calls `GetConsensusExtraData` to obtain a valid `OutValue` and `Signature` for their current `InValue`
2. Miner constructs a custom `UpdateValueInput` with the valid cryptographic values but replaces `SupposedOrderOfNextRound` with their desired position (e.g., 1 for first)
3. Miner directly calls the public `UpdateValue` method with the modified input [9](#0-8) 
4. The contract accepts this transaction as the validation only checks signature/outvalue existence, not correctness of the order value

**Feasibility**: The attack requires no special conditions beyond normal miner participation. The `UpdateValue` method is public and can be called directly by any miner with valid credentials. The cost is minimal (standard transaction fees) while the benefit is continuous preferential positioning.

**Detection**: While manipulation could theoretically be detected by comparing submitted values against recalculated ones, there is no on-chain enforcement, and miners are economically incentivized to exploit this advantage.

## Recommendation

Add validation to verify that the provided `SupposedOrderOfNextRound` matches the cryptographically-calculated value:

1. **Option 1**: Recalculate and validate in `ProcessUpdateValue`:
   - Extract the signature from the input
   - Recalculate: `expectedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1`
   - Assert that `updateValueInput.SupposedOrderOfNextRound == expectedOrder`

2. **Option 2**: Apply `NextRoundMiningOrderValidationProvider` to `UpdateValue` behavior (though this only checks counts, not individual correctness, so additional validation would still be needed)

3. **Option 3 (Recommended)**: Remove `SupposedOrderOfNextRound` from `UpdateValueInput` entirely and always calculate it server-side from the signature during `ProcessUpdateValue`, similar to how `ApplyNormalConsensusData` works

The recommended approach ensures the order cannot be manipulated regardless of user input and maintains consistency with the cryptographic fairness guarantee.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateMiningOrder_Test()
{
    // Setup: Initialize with multiple miners
    await InitializeCandidates(5);
    var firstRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Attacker is one of the miners
    var attackerKeyPair = InitialCoreDataCenterKeyPairs[0];
    var attackerPubkey = attackerKeyPair.PublicKey.ToHex();
    var attackerStub = GetAEDPoSContractStub(attackerKeyPair);
    
    // Step 1: Get legitimate consensus data
    var minerInRound = firstRound.RealTimeMinersInformation[attackerPubkey];
    BlockTimeProvider.SetBlockTime(minerInRound.ExpectedMiningTime);
    
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(attackerKeyPair.PublicKey),
        InValue = HashHelper.ComputeFrom("test_invalue"),
        Behaviour = AElfConsensusBehaviour.UpdateValue
    };
    
    var headerInfo = (await AEDPoSContractStub.GetConsensusExtraData.CallAsync(
        triggerInfo.ToBytesValue())).ToConsensusHeaderInformation();
    
    // Step 2: Extract the update input but MANIPULATE the order
    var legitimateInput = headerInfo.Round.ExtractInformationToUpdateConsensus(
        attackerPubkey, 
        ByteString.CopyFrom(await GenerateRandomProofAsync(attackerKeyPair)));
    
    // Record the original calculated order
    var calculatedOrder = legitimateInput.SupposedOrderOfNextRound;
    
    // Step 3: Manipulate to always be first
    legitimateInput.SupposedOrderOfNextRound = 1;
    
    // Step 4: Submit the manipulated value - should succeed (vulnerability)
    var result = await attackerStub.UpdateValue.SendAsync(legitimateInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Check that manipulated order was accepted
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerInfo = updatedRound.RealTimeMinersInformation[attackerPubkey];
    
    // The vulnerability allows this assertion to pass
    attackerInfo.SupposedOrderOfNextRound.ShouldBe(1);
    attackerInfo.FinalOrderOfNextRound.ShouldBe(1);
    
    // This should have been the calculated value, not 1
    calculatedOrder.ShouldNotBe(1); // Proves manipulation occurred
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
