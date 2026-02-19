# Audit Report

## Title
Miners Can Manipulate FinalOrderOfNextRound to Control Next Round Mining Position

## Summary
The AEDPoS consensus contract accepts miner-provided mining order values in `UpdateValue` without validating that they match the expected deterministic calculation from signature hashes. This allows malicious miners to arbitrarily set their `SupposedOrderOfNextRound` and manipulate other miners' `FinalOrderOfNextRound` values, enabling them to consistently secure favorable mining positions (e.g., first position) in subsequent rounds.

## Finding Description

The `UpdateValue` method is a public entry point that miners call during block production to update consensus information. [1](#0-0) 

The vulnerability exists in `ProcessUpdateValue`, which blindly accepts miner-provided order values without verification. [2](#0-1)  Additionally, miners can modify other miners' final orders through the `TuneOrderInformation` dictionary. [3](#0-2) 

The protocol expects `SupposedOrderOfNextRound` to be deterministically calculated from the miner's signature hash using the formula: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [4](#0-3)  This calculation happens in `ApplyNormalConsensusData`, which is only called during block extra data generation. [5](#0-4) 

However, `ProcessUpdateValue` never invokes this validation logic. Instead, it directly assigns the miner-provided values from the input.

The validation system has critical gaps:

1. `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` fields, but does NOT validate `SupposedOrderOfNextRound` or `TuneOrderInformation`. [6](#0-5) 

2. During validation, `RecoverFromUpdateValue` blindly copies the miner-provided order values without recalculating them from the signature. [7](#0-6) 

3. `NextRoundMiningOrderValidationProvider` only checks that the COUNT of miners with set orders matches the COUNT of miners who produced blocks, not whether the order values themselves are correctly calculated. [8](#0-7)  Moreover, this validator is only used for `NextRound` behavior, not for `UpdateValue`. [9](#0-8) 

The protobuf definition allows miners to provide arbitrary integer values for these fields. [10](#0-9) 

When the next round is generated, the mining order is directly determined by these manipulated `FinalOrderOfNextRound` values. [11](#0-10) 

**Attack Scenario:**
1. Malicious miner crafts a custom `UpdateValueInput` with `supposed_order_of_next_round = 1` (first position)
2. Uses `tune_order_information` to push other miners to later positions
3. Provides valid signature and other required fields
4. Calls `UpdateValue` with this crafted input
5. `ProcessUpdateValue` accepts these values without validation
6. Next round is generated with the malicious miner in first position
7. Process repeats across multiple rounds

## Impact Explanation

**Consensus Integrity Breach:**
The AEDPoS consensus mechanism relies on deterministic mining order calculation from signature hashes to ensure fairness and randomness. By allowing miners to arbitrarily set their mining positions, this vulnerability completely bypasses this critical consensus invariant.

**Economic Impact:**
- Miners in first position gain priority in transaction selection and fee collection
- Enables consistent MEV (Maximal Extractable Value) extraction opportunities
- Honest miners lose their fair share of mining opportunities and associated rewards
- Disrupts the economic balance of the consensus mechanism

**Protocol Damage:**
- Undermines trust in the fairness of the consensus mechanism
- Allows persistent manipulation across multiple rounds without detection
- Violates the protocol's fundamental security guarantees

## Likelihood Explanation

**High Likelihood:**
- Any active miner in the consensus set can execute this attack
- Only requires crafting a custom `UpdateValueInput` structure instead of using the honest `ExtractInformationToUpdateConsensus` helper
- No cryptographic bypass or complex state manipulation required
- Attack complexity is low: simply set desired order values in the input structure

**Feasibility:**
- The `UpdateValue` method is accessible to all miners during their mining time slot
- Precondition check only verifies the miner is in the miner list [12](#0-11) 
- No additional authorization or timing constraints prevent the attack
- Manipulated values appear valid in format, making detection difficult

## Recommendation

Add validation in `ProcessUpdateValue` to verify that `SupposedOrderOfNextRound` matches the expected calculation:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    
    // VALIDATION: Verify SupposedOrderOfNextRound matches expected calculation
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    var sigNum = updateValueInput.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
        "Invalid SupposedOrderOfNextRound: does not match signature-based calculation");
    
    // VALIDATION: Verify TuneOrderInformation only adjusts legitimate conflicts
    // This should be validated against the actual conflict resolution logic
    
    minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
    // ... rest of method
}
```

Additionally, add helper method:
```csharp
private static int GetAbsModulus(long longValue, int intValue)
{
    return (int)Math.Abs(longValue % intValue);
}
```

Alternatively, call `ApplyNormalConsensusData` instead of manually setting values to ensure correct order calculation.

## Proof of Concept

A malicious miner can exploit this vulnerability by:

1. Monitoring when it's their turn to mine
2. Crafting an `UpdateValueInput` with:
   - Valid `out_value` and `signature` from normal block production
   - `supposed_order_of_next_round = 1` (to get first position)
   - `tune_order_information = { "miner2_pubkey": 2, "miner3_pubkey": 3, ... }` (to push others back)
3. Calling `UpdateValue` with this crafted input
4. The contract accepts these values without validation
5. When `GenerateNextRoundInformation` is called, the malicious miner gets order 1
6. Repeat in subsequent rounds to maintain first position consistently

**Test Scenario:**
```csharp
// Assume 5 miners in the consensus set
// Malicious miner creates UpdateValueInput
var maliciousInput = new UpdateValueInput
{
    OutValue = computedOutValue,
    Signature = computedSignature,
    RoundId = currentRoundId,
    PreviousInValue = previousInValue,
    ActualMiningTime = Context.CurrentBlockTime,
    SupposedOrderOfNextRound = 1,  // Force first position
    TuneOrderInformation = {
        { "honest_miner_1", 2 },
        { "honest_miner_2", 3 },
        { "honest_miner_3", 4 },
        { "honest_miner_4", 5 }
    },
    ImpliedIrreversibleBlockHeight = currentHeight,
    RandomNumber = randomNumberBytes
};

// Call UpdateValue - no validation error occurs
consensusContract.UpdateValue(maliciousInput);

// In next round, malicious miner has order 1
var nextRound = consensusContract.GetRoundInformation(nextRoundNumber);
Assert(nextRound.RealTimeMinersInformation[maliciousMinerPubkey].Order == 1);
```

The expected signature-based order calculation would produce a different value (likely between 1-5 based on hash), but the contract accepts the miner's arbitrary choice of order 1.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-86)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```

**File:** protobuf/aedpos_contract.proto (L205-208)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
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
