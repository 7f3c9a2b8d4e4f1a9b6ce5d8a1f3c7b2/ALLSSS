# Audit Report

## Title
Missing Validation of Mining Order Manipulation via TuneOrderInformation in UpdateValue

## Summary
The `UpdateValue` consensus behavior lacks validation for `TuneOrderInformation` entries, allowing a malicious miner to manipulate `FinalOrderOfNextRound` values for any miner in the network. This enables mining order manipulation and potential consensus disruption through invalid order assignments.

## Finding Description

The AEDPoS consensus system maintains two order fields per miner: `SupposedOrderOfNextRound` (deterministically calculated from signature) and `FinalOrderOfNextRound` (adjusted for conflicts). When miners produce blocks, they execute `ApplyNormalConsensusData` locally to calculate orders and resolve conflicts. [1](#0-0) 

Any discrepancies between supposed and final orders are communicated to other nodes via `TuneOrderInformation`, which gets extracted and included in the `UpdateValueInput`. [2](#0-1) 

During block execution, `ProcessUpdateValue` directly applies this tuning information without any validation. [3](#0-2) 

**Root Cause**: The `UpdateValueValidationProvider` performs no validation of `TuneOrderInformation` content, only checking that OutValue and Signature are filled and that PreviousInValue hash is correct. [4](#0-3) 

The `NextRoundMiningOrderValidationProvider` which validates order values is only applied to `NextRound` behavior, not `UpdateValue`. [5](#0-4) 

**Attack Path**: A malicious miner modifies their local `ApplyNormalConsensusData` logic to set arbitrary `FinalOrderOfNextRound` values instead of following legitimate conflict resolution. When `ExtractInformationToUpdateConsensus` runs, these malicious values are collected into `TuneOrderInformation` and included in the consensus extra data. During validation, no check detects the manipulation. During execution, the malicious values are written directly to state.

The after-execution hash validation fails to catch this because `RecoverFromUpdateValue` copies the same malicious `FinalOrderOfNextRound` values from the header to the current round before comparing hashes. [6](#0-5) 

When the next round is generated, these manipulated `FinalOrderOfNextRound` values are used directly to assign mining slots. [7](#0-6) 

## Impact Explanation

This vulnerability breaks consensus integrity by allowing unfair manipulation of the miner schedule:

1. **Mining Order Manipulation**: A malicious miner can set their own `FinalOrderOfNextRound` to 1 to always mine first in the next round, gaining timing advantages.

2. **Invalid Order Values**: Assigning orders of 0, negative values, or values greater than `minersCount` can disrupt round generation logic, potentially causing exceptions or non-deterministic behavior when the system tries to find miners by specific order values.

3. **Duplicate Orders**: Creating multiple miners with identical `FinalOrderOfNextRound` causes non-deterministic mining time assignment when the code uses methods like `FirstOrDefault` to locate miners by order.

4. **Competitor Disruption**: Assigning high or invalid orders to competing miners delays their mining slots or excludes them from valid positions.

The impact is on **consensus integrity** - the deterministic, fair calculation of mining order based on signatures is violated, allowing arbitrary manipulation by any active miner.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Capabilities**: Any active miner in the consensus rotation can perform this attack by modifying their local node's consensus logic in `ApplyNormalConsensusData`.

**Attack Complexity**: Medium
- Requires local node code modification
- No special privileges beyond being an active miner  
- Single transaction (`UpdateValue`) execution
- No dependency on external conditions

**Feasibility**: The attack is practical because:
1. Entry point is the standard `UpdateValue` method called during normal block production
2. No validation exists to detect malicious `TuneOrderInformation`
3. The consensus header hash validation includes order values, but both header and execution result contain the same malicious values, so hashes match

**Detection**: Difficult to detect in real-time as the malicious orders appear in both the consensus header and execution result, passing hash validation.

## Recommendation

Add validation of `TuneOrderInformation` content in `UpdateValueValidationProvider`:

1. Validate that all order values in `TuneOrderInformation` are within valid range (1 to minersCount)
2. Validate that there are no duplicate `FinalOrderOfNextRound` values across all miners
3. Optionally, re-calculate expected tuning based on conflict resolution rules and verify it matches the provided `TuneOrderInformation`

Alternatively, apply `NextRoundMiningOrderValidationProvider` to `UpdateValue` behavior in addition to `NextRound`, ensuring order consistency is validated for both behaviors.

## Proof of Concept

A malicious miner would:

1. Modify their local node's `ApplyNormalConsensusData` method to set:
   - Own `FinalOrderOfNextRound` = 1 (to mine first)
   - Competitor's `FinalOrderOfNextRound` = 999 (invalid, > minersCount)
   - Other miner's `FinalOrderOfNextRound` = 1 (duplicate)

2. Produce a block with `UpdateValue` behavior containing this malicious `TuneOrderInformation`

3. The block passes validation because `UpdateValueValidationProvider` doesn't check tuning values

4. During execution, `ProcessUpdateValue` applies the malicious values to state

5. After-execution validation passes because both header and state contain identical malicious values

6. When `NextRound` is triggered, the round generation uses these manipulated orders, disrupting the fair mining schedule

**Note**: A complete PoC would require a modified AElf node with instrumented consensus contract to demonstrate the manipulation and its effects on round generation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
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

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

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
