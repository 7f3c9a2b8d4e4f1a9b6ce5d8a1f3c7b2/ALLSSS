# Audit Report

## Title
Miners Can Manipulate Mining Order by Providing Arbitrary SupposedOrderOfNextRound Values

## Summary
The AEDPoS consensus contract accepts `SupposedOrderOfNextRound` values from miners without validating that they match the cryptographically-calculated value derived from their signature. This allows malicious miners to arbitrarily control their mining position in subsequent rounds, breaking the consensus mechanism's fairness guarantees.

## Finding Description

The AEDPoS consensus mechanism is designed to determine each miner's position in the next round based on their cryptographic signature. The correct calculation uses the formula `GetAbsModulus(signature.ToInt64(), minersCount) + 1`: [1](#0-0) 

This proper calculation occurs in `ApplyNormalConsensusData`, which is called by the view function `GetConsensusExtraDataToPublishOutValue` when generating consensus data: [2](#0-1) 

However, when miners submit `UpdateValue` transactions, the contract directly assigns the `SupposedOrderOfNextRound` value from the input without any recalculation or validation: [3](#0-2) 

The validation phase only uses `UpdateValueValidationProvider`, which checks that `OutValue` and `Signature` are non-null/non-empty and validates the `PreviousInValue` relationship, but does NOT verify the `SupposedOrderOfNextRound` calculation: [4](#0-3) 

The `NextRoundMiningOrderValidationProvider` that could validate mining order is only applied for `NextRound` behavior, not for `UpdateValue` behavior: [5](#0-4) 

Furthermore, even this validator only checks counts, not individual value correctness: [6](#0-5) 

The manipulated `SupposedOrderOfNextRound` becomes `FinalOrderOfNextRound`, which directly determines mining order when `GenerateNextRoundInformation` creates the next round: [7](#0-6) 

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
3. Miner directly calls the public `UpdateValue` method with the modified input
4. The contract accepts this transaction as the validation only checks signature/outvalue existence, not correctness of the order value

**Feasibility**: The attack requires no special conditions beyond normal miner participation. The `UpdateValue` method is public: [8](#0-7) 

The cost is minimal (standard transaction fees) while the benefit is continuous preferential positioning.

**Detection**: While manipulation could theoretically be detected by comparing submitted values against recalculated ones, there is no on-chain enforcement, and miners are economically incentivized to exploit this advantage.

## Recommendation

Add validation in `ProcessUpdateValue` to recalculate and verify the `SupposedOrderOfNextRound` matches the cryptographic calculation:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    
    // Recalculate the expected SupposedOrderOfNextRound
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    var sigNum = updateValueInput.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    // Validate the provided value matches the calculated value
    Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
        "SupposedOrderOfNextRound does not match cryptographic calculation");
    
    // Rest of the method...
    minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
    minerInRound.Signature = updateValueInput.Signature;
    minerInRound.OutValue = updateValueInput.OutValue;
    minerInRound.SupposedOrderOfNextRound = expectedOrder; // Use validated value
    minerInRound.FinalOrderOfNextRound = expectedOrder;
    // ...
}
```

Alternatively, add `SupposedOrderOfNextRound` validation to the `UpdateValueValidationProvider`.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateMiningOrder()
{
    // Setup: Get current round with multiple miners
    var currentRound = await GetCurrentRoundInformation();
    var miner = currentRound.RealTimeMinersInformation.Values.First();
    
    // Attacker calls GetConsensusExtraData to get valid cryptographic values
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteStringHelper.FromHexString(miner.Pubkey),
        InValue = HashHelper.ComputeFrom("test"),
        Behaviour = AElfConsensusBehaviour.UpdateValue
    };
    var consensusExtraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
        triggerInfo.ToBytesValue());
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(
        consensusExtraData.Value);
    
    // Extract UpdateValueInput with correct signature/outvalue
    var updateInput = headerInfo.Round.ExtractInformationToUpdateConsensus(
        miner.Pubkey, HashHelper.ComputeFrom("random").ToByteString());
    
    // ATTACK: Replace SupposedOrderOfNextRound with attacker's desired value
    updateInput.SupposedOrderOfNextRound = 1; // Force first position
    
    // Submit manipulated UpdateValue transaction
    await ConsensusStub.UpdateValue.SendAsync(updateInput);
    
    // Verify: Check that the manipulated value was accepted
    var updatedRound = await GetCurrentRoundInformation();
    var updatedMiner = updatedRound.RealTimeMinersInformation[miner.Pubkey];
    
    // The manipulated value should be rejected, but it's accepted
    updatedMiner.FinalOrderOfNextRound.ShouldBe(1); // Attack succeeded
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-87)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
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
