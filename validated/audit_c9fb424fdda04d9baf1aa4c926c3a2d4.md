# Audit Report

## Title
Missing Validation of Next Round Mining Order Allows Position Manipulation

## Summary
The AEDPoS consensus contract fails to validate that miners provide correctly calculated `SupposedOrderOfNextRound` values derived from their cryptographic signatures. Miners can submit arbitrary order values in `UpdateValue` transactions, allowing them to manipulate their mining position in subsequent rounds for unfair advantages in block rewards and MEV extraction.

## Finding Description

The AEDPoS consensus mechanism is designed to deterministically calculate each miner's position in the next round using the formula: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. However, the contract accepts miner-provided order values without validating they match this calculation.

**Root Cause:**

When processing consensus updates, `ProcessUpdateValue` directly accepts the `SupposedOrderOfNextRound` from the transaction input without verification: [1](#0-0) 

The deterministic calculation exists in `ApplyNormalConsensusData`, which correctly computes the order from the signature: [2](#0-1) 

However, this calculated value is only used when honest mining software generates consensus data - it is not enforced during validation.

**Validation Failures:**

The `UpdateValueValidationProvider` only verifies that `OutValue` and `Signature` fields are present, but does not check if the order matches the signature-based calculation: [3](#0-2) 

The `NextRoundMiningOrderValidationProvider` only validates during `NextRound` behavior (not `UpdateValue`), and only checks that the count of miners with orders equals those who mined: [4](#0-3) [5](#0-4) 

During validation recovery, `RecoverFromUpdateValue` blindly copies all miners' order values from the provided round without recalculation: [6](#0-5) 

**Exploitation Path:**

When the next round is generated, miners are ordered by their `FinalOrderOfNextRound` values (which are set from the unvalidated `SupposedOrderOfNextRound`): [7](#0-6) 

A malicious miner can:
1. Generate custom header extra data with their chosen `SupposedOrderOfNextRound` value (bypassing `ApplyNormalConsensusData`)
2. Generate matching `UpdateValue` transaction with the same manipulated order value
3. Both validations pass because neither checks order correctness against the signature
4. `ProcessUpdateValue` stores the manipulated order value
5. In the next round, this manipulated order determines the miner's position

## Impact Explanation

This vulnerability breaks the cryptographic randomness guarantee of AEDPoS consensus order determination. The impact includes:

**Direct Economic Harm:**
- Miners can position themselves as first producer in the next round, capturing MEV opportunities
- Unfair distribution of block rewards favoring manipulating miners over honest participants
- Manipulation of extra block producer selection, which uses order-based calculations: [8](#0-7) 

**Protocol Integrity:**
- Undermines the deterministic yet unpredictable miner ordering that consensus security relies upon
- Allows strategic miners to consistently obtain favorable positions across multiple rounds
- Could impact Last Irreversible Block (LIB) calculations which depend on proper miner ordering

**Affected Parties:**
- Honest miners experience reduced rewards due to unfair competition
- Network decentralization degraded as consensus becomes predictable and gameable
- Token holders affected by compromised consensus integrity

**Severity: MEDIUM** - While not directly stealing funds, this provides systematic unfair advantages that translate to significant economic benefits over time and fundamentally undermines consensus fairness.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round (privileged but achievable position)
- Requires ability to modify mining node software to generate custom consensus data
- No additional cryptographic keys or governance permissions needed

**Attack Complexity:**
- LOW - Attacker generates both header extra data and transaction with manipulated `SupposedOrderOfNextRound` values
- The honest path uses `ApplyNormalConsensusData` to calculate correctly: [9](#0-8) 

But a malicious miner can skip this calculation and provide arbitrary values.

- The simplified round generation includes order fields: [10](#0-9) 

**Detection Difficulty:**
- Manipulated orders appear as normal consensus data in blockchain state
- No events or alerts triggered when orders deviate from expected signature-based calculations
- Would require offline analysis comparing each miner's signature to their reported order value

**Probability: HIGH** - Straightforward exploit with significant economic incentives and low detection risk.

## Recommendation

Add validation in `UpdateValueValidationProvider` to verify that the provided `SupposedOrderOfNextRound` matches the deterministic calculation based on the miner's signature:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var signature = minerInRound.Signature;
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    
    var expectedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1;
    
    if (minerInRound.SupposedOrderOfNextRound != expectedOrder)
    {
        return false;
    }
    
    return true;
}

private static int GetAbsModulus(long longValue, int intValue)
{
    return (int)Math.Abs(longValue % intValue);
}
```

This validation should be added to the `ValidateHeaderInformation` method and checked before accepting the round data.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateMiningOrder()
{
    // Setup: Initialize consensus with multiple miners
    var miners = await InitializeConsensusWithMiners();
    var maliciousMiner = miners.First();
    
    // Malicious miner generates valid signature but provides arbitrary order
    var validSignature = GenerateValidSignature(maliciousMiner);
    var correctOrder = CalculateOrderFromSignature(validSignature, miners.Count);
    var manipulatedOrder = 1; // Miner chooses to be first
    
    // Create UpdateValueInput with manipulated order
    var input = new UpdateValueInput
    {
        Signature = validSignature,
        OutValue = GenerateOutValue(maliciousMiner),
        SupposedOrderOfNextRound = manipulatedOrder, // Should be correctOrder
        // ... other fields
    };
    
    // Execute UpdateValue - should fail but doesn't
    await ConsensusContract.UpdateValue(input);
    
    // Verify the manipulated order was accepted
    var currentRound = await GetCurrentRoundInformation();
    var minerInfo = currentRound.RealTimeMinersInformation[maliciousMiner];
    
    Assert.Equal(manipulatedOrder, minerInfo.SupposedOrderOfNextRound);
    Assert.NotEqual(correctOrder, minerInfo.SupposedOrderOfNextRound);
    
    // Trigger next round generation
    await GenerateNextRound();
    
    // Verify miner got their chosen position
    var nextRound = await GetCurrentRoundInformation();
    var nextMinerInfo = nextRound.RealTimeMinersInformation[maliciousMiner];
    
    Assert.Equal(manipulatedOrder, nextMinerInfo.Order);
}
```

## Notes

The vulnerability exists because the contract separates the generation of correct values (in `ApplyNormalConsensusData`) from their validation. Honest mining software calls `ApplyNormalConsensusData` to generate correct orders, but a malicious miner can bypass this and provide custom values directly. The validation logic never verifies that the provided order matches what the signature-based calculation would produce, allowing position manipulation in subsequent rounds.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L38-48)
```csharp
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
```
