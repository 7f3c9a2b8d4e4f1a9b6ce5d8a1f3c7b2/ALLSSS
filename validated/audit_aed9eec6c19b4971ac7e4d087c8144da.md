# Audit Report

## Title
Miners Can Manipulate Mining Order by Providing Arbitrary SupposedOrderOfNextRound Values

## Summary
The AEDPoS consensus contract accepts `SupposedOrderOfNextRound` values from miners without validating that they match the cryptographically-calculated value derived from their signature. This allows malicious miners to arbitrarily control their mining position in subsequent rounds, breaking the consensus mechanism's fairness guarantees.

## Finding Description

The AEDPoS consensus mechanism is designed to determine each miner's position in the next round based on their cryptographic signature using the formula `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. This proper calculation occurs in `ApplyNormalConsensusData` [1](#0-0) , which is called by the view function `GetConsensusExtraDataToPublishOutValue` when generating consensus data [2](#0-1) .

However, when miners submit `UpdateValue` transactions, the contract directly assigns the `SupposedOrderOfNextRound` value from the input without any recalculation or validation [3](#0-2) .

The validation phase only uses `UpdateValueValidationProvider`, which checks that `OutValue` and `Signature` are non-null/non-empty [4](#0-3)  and validates the `PreviousInValue` relationship [5](#0-4) , but does NOT verify the `SupposedOrderOfNextRound` calculation.

The `NextRoundMiningOrderValidationProvider` that could validate mining order is only applied for `NextRound` behavior, not for `UpdateValue` behavior [6](#0-5) . Furthermore, even this validator only checks counts, not individual value correctness [7](#0-6) .

The manipulated `SupposedOrderOfNextRound` becomes `FinalOrderOfNextRound`, which directly determines mining order when `GenerateNextRoundInformation` creates the next round [8](#0-7) .

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
2. Miner constructs a custom `UpdateValueInput` [9](#0-8)  with the valid cryptographic values but replaces `SupposedOrderOfNextRound` with their desired position (e.g., 1 for first)
3. Miner directly calls the public `UpdateValue` method [10](#0-9)  with the modified input
4. The contract accepts this transaction as the validation only checks signature/outvalue existence, not correctness of the order value

**Feasibility**: The attack requires no special conditions beyond normal miner participation. The cost is minimal (standard transaction fees) while the benefit is continuous preferential positioning.

**Detection**: While manipulation could theoretically be detected by comparing submitted values against recalculated ones, there is no on-chain enforcement, and miners are economically incentivized to exploit this advantage.

## Recommendation

Add validation in `ProcessUpdateValue` to verify that the submitted `SupposedOrderOfNextRound` matches the cryptographically-calculated value. The fix should:

1. Calculate the expected order using the same formula as `ApplyNormalConsensusData`: `GetAbsModulus(updateValueInput.Signature.ToInt64(), minersCount) + 1`
2. Compare it against the submitted `updateValueInput.SupposedOrderOfNextRound`
3. Reject the transaction if they don't match

Alternatively, remove the `SupposedOrderOfNextRound` field from `UpdateValueInput` entirely and always recalculate it within `ProcessUpdateValue` using the signature, ensuring miners cannot provide their own values.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MinerCanManipulateMiningOrder()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(5);
    await InitializeConsensus(miners);
    
    // Attacker miner generates valid consensus data
    var attackerMiner = miners[3]; // Not naturally first
    var consensusData = await GetConsensusExtraData(attackerMiner);
    
    // Extract valid cryptographic values
    var validSignature = consensusData.Signature;
    var validOutValue = consensusData.OutValue;
    
    // Create manipulated UpdateValueInput with desired position = 1
    var manipulatedInput = new UpdateValueInput
    {
        Signature = validSignature,
        OutValue = validOutValue,
        PreviousInValue = consensusData.PreviousInValue,
        ActualMiningTime = Timestamp.FromDateTime(DateTime.UtcNow),
        SupposedOrderOfNextRound = 1, // MANIPULATED: Should be ~4 based on signature
        RoundId = currentRound.RoundId,
        ImpliedIrreversibleBlockHeight = currentHeight,
        RandomNumber = GenerateRandomNumber()
    };
    
    // Call UpdateValue - should reject but doesn't
    await attackerMiner.UpdateValue(manipulatedInput);
    
    // Advance to next round
    await TriggerNextRound();
    var nextRound = await GetCurrentRoundInformation();
    
    // VULNERABILITY CONFIRMED: Attacker is now first despite invalid cryptographic order
    Assert.Equal(1, nextRound.RealTimeMinersInformation[attackerMiner.Pubkey].Order);
    // The cryptographically correct order would be different
    var expectedOrder = GetAbsModulus(validSignature.ToInt64(), miners.Count) + 1;
    Assert.NotEqual(1, expectedOrder); // Proves manipulation occurred
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-22)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-88)
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
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-21)
```csharp
        var providedRound = validationContext.ProvidedRound;
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

**File:** protobuf/aedpos_contract.proto (L194-206)
```text
message UpdateValueInput {
    // Calculated from current in value.
    aelf.Hash out_value = 1;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
    // Publish previous in value for validation previous signature and previous out value.
    aelf.Hash previous_in_value = 4;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    google.protobuf.Timestamp actual_mining_time = 5;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
