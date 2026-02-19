# Audit Report

## Title
UpdateValueValidationProvider Allows Manipulation of Next-Round Mining Order

## Summary
The `UpdateValueValidationProvider` fails to validate that `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` values match the deterministic calculation based on miner signatures. A malicious miner can provide arbitrary order values in their block header, manipulating the mining order for the next round and breaking consensus fairness.

## Finding Description

The vulnerability exists in the consensus validation flow for `UpdateValue` behavior. The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are filled, and that `PreviousInValue` hashes correctly. [1](#0-0) 

It does NOT validate the `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` fields.

The critical issue occurs in the validation sequence. Before validation runs, `RecoverFromUpdateValue` is called: [2](#0-1) 

This method blindly copies order values from the provided round into the base round for ALL miners: [3](#0-2) 

These order values should be deterministically calculated from miner signatures using `GetAbsModulus(signature.ToInt64(), minersCount) + 1` with conflict resolution logic: [4](#0-3) 

When honest miners generate blocks, they correctly calculate these values: [5](#0-4) 

And include them in the simplified round: [6](#0-5) 

However, a malicious miner can construct a `Round` with arbitrary order values that will pass validation. When the consensus transaction is processed, `ProcessUpdateValue` directly applies these unvalidated values to state: [7](#0-6) 

And then applies the manipulated `TuneOrderInformation` to other miners: [8](#0-7) 

When the next round is generated, miners are ordered by their `FinalOrderOfNextRound` values, directly using the manipulated values: [9](#0-8) 

## Impact Explanation

**Consensus Integrity Violation**: The attack allows complete control over mining order for the next round, breaking a critical consensus invariant. Mining order determines block reward distribution, transaction ordering (potential MEV opportunities), and network fairness.

**Quantified Damage**: 
- Attacker can guarantee themselves position 1 in every round, maximizing block rewards
- Honest miners are pushed to unfavorable positions
- The randomness mechanism preventing predictable ordering is completely bypassed
- Over multiple rounds, the attacker accumulates significantly more rewards than their fair share

**Affected Parties**: All network participants. Honest miners receive reduced rewards, users experience potential transaction ordering manipulation, and the overall security model of AEDPoS consensus is compromised.

**Severity**: Critical - this breaks the fundamental fairness and randomness guarantees of the consensus mechanism.

## Likelihood Explanation

**Attacker Capabilities**: Any current miner can execute this attack. Requirements:
- Mining slot (already possessed)
- Ability to construct custom block headers with manipulated Round data
- Valid signature, OutValue, and PreviousInValue (standard requirements)

**Attack Complexity**: Low. The attacker:
1. Generates valid consensus values (OutValue, Signature, PreviousInValue) normally
2. Modifies the `Round` structure in block header to set desired order values
3. Submits the block

**Feasibility**: Always feasible when the attacker has a mining slot. No special preconditions required.

**Detection**: Difficult because manipulated blocks pass all validation checks and the impact only becomes visible when the next round starts.

**Economic Rationality**: Highly rational. Zero cost (just different header data), with benefits including preferential mining positions and increased block rewards.

## Recommendation

Add validation in `UpdateValueValidationProvider` to verify that order values match the deterministic calculation:

```csharp
private bool ValidateOrderValues(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Also validate that `TuneOrderInformation` in `UpdateValueInput` correctly resolves conflicts by recalculating from signatures during validation.

## Proof of Concept

The vulnerability can be demonstrated by constructing a test where:
1. A miner obtains the legitimate Round via `GetConsensusExtraData`
2. Modifies `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` to arbitrary values
3. Includes this in block header
4. Validation passes despite manipulated values
5. Next round generation uses the manipulated order values

The key proof points are:
- `UpdateValueValidationProvider.ValidateHeaderInformation` does not check order values [1](#0-0) 
- `ProcessUpdateValue` directly applies input values without recalculation [10](#0-9) 
- `GenerateNextRoundInformation` uses these manipulated values to determine actual mining order [11](#0-10)

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-44)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L35-52)
```csharp
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
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
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-260)
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

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-56)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```
