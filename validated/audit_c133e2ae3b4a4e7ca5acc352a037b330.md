# Audit Report

## Title
Missing Validation of TuneOrderInformation Allows Miners to Corrupt Next Round Mining Schedule

## Summary
The `ProcessUpdateValue` function in the AEDPoS consensus contract directly applies `TuneOrderInformation` values from miner-submitted `UpdateValueInput` to `FinalOrderOfNextRound` without validating that order values are within the valid range [1, minersCount] or checking for duplicates. This allows a malicious miner to inject arbitrary order values that corrupt the mining schedule and compromise consensus integrity.

## Finding Description

The vulnerability exists in the consensus update flow where mining order information for the next round is processed without validation.

When a miner produces a block, they submit an `UpdateValue` transaction containing an `UpdateValueInput` message. This message includes a `tune_order_information` map that allows setting order values for multiple miners: [1](#0-0) 

In `ProcessUpdateValue`, these values are directly applied to the current round state without any validation: [2](#0-1) 

The validation system for `UpdateValue` behavior only checks cryptographic values (OutValue, Signature, PreviousInValue), not the order information: [3](#0-2) 

The `NextRoundMiningOrderValidationProvider` has a critical bug - it calls `.Distinct()` on `MinerInRound` objects instead of on the order values themselves: [4](#0-3) 

Since `MinerInRound` is a protobuf-generated class with field-by-field equality comparison, each miner's object is always distinct even when they have identical `FinalOrderOfNextRound` values. The validation should instead check `.Select(m => m.FinalOrderOfNextRound).Distinct()` to detect duplicate order values.

When generating the next round, the corrupted `FinalOrderOfNextRound` values are used directly to determine mining order and timing: [5](#0-4) 

If multiple miners have the same `FinalOrderOfNextRound` value, they will both receive the same `Order` value in the next round, violating the protocol invariant that each miner must have a unique order.

## Impact Explanation

This vulnerability breaks consensus integrity with severe network-wide consequences:

**1. Mining Schedule Corruption**: Duplicate order values cause multiple miners to have the same `Order` in the next round, giving them identical `ExpectedMiningTime` values. This creates ambiguity in the mining schedule and conflicts when both miners attempt to mine at the same time.

**2. Miner Exclusion**: Out-of-range order values (e.g., Order=999 when there are 7 miners) push affected miners' `ExpectedMiningTime` far into the future, effectively excluding them from consensus and disrupting the intended round-robin mining schedule.

**3. Protocol Invariant Violation**: The consensus protocol assumes each miner has a unique Order value in [1, minersCount]. Corrupting this invariant breaks the deterministic mining schedule that all nodes rely on.

**4. No Recovery Mechanism**: There is no validation or recovery mechanism to detect and correct corrupted order values once they enter the round state. The corruption persists across subsequent rounds.

The attack breaks the fundamental consensus guarantee that all honest nodes agree on a deterministic mining schedule and block production order.

## Likelihood Explanation

The vulnerability is highly exploitable:

**Attacker Requirements**: The attacker must be an elected miner in the current miner list. This is verified by `PreCheck()`: [6](#0-5) 

**Attack Complexity**: Low. The attacker only needs to:
1. Modify their consensus client to craft a custom `UpdateValueInput` with malicious `TuneOrderInformation` values
2. Submit the transaction during their legitimate mining time slot

**Method Accessibility**: The `UpdateValue` method is publicly accessible: [7](#0-6) 

**No Prevention**: The validation providers check miner permissions, time slots, and continuous block limits, but none validate the order values: [8](#0-7) 

**Probability**: High. Any malicious miner can execute this attack during their time slot in every round they participate in, with only transaction fee costs.

## Recommendation

Implement validation for `TuneOrderInformation` in `ProcessUpdateValue`:

1. **Range Validation**: Verify all order values are within [1, minersCount]
2. **Duplicate Detection**: Check that no two miners have the same `FinalOrderOfNextRound` value
3. **Existence Check**: Verify all keys in `TuneOrderInformation` exist in the current miner list

Additionally, fix the `.Distinct()` bug in `NextRoundMiningOrderValidationProvider`:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
if (distinctOrderCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound: duplicate order values detected.";
    return validationResult;
}
```

Add validation in `ProcessUpdateValue` before applying values:

```csharp
var minersCount = currentRound.RealTimeMinersInformation.Count;
var usedOrders = new HashSet<int>();

foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key), 
        $"Miner {tuneOrder.Key} not found in current round.");
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount,
        $"Order value {tuneOrder.Value} out of valid range [1, {minersCount}].");
    Assert(usedOrders.Add(tuneOrder.Value),
        $"Duplicate order value {tuneOrder.Value} detected.");
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

## Proof of Concept

A test demonstrating the vulnerability would:
1. Set up a consensus round with multiple miners
2. Have one miner submit `UpdateValue` with `TuneOrderInformation` containing duplicate values (e.g., {"miner1": 3, "miner2": 3})
3. Call `GenerateNextRoundInformation` to create the next round
4. Verify that both miners have the same `Order` value in the generated round
5. Demonstrate that `NextRoundMiningOrderValidationProvider` fails to detect the duplicates

The test would confirm that duplicate order values corrupt the mining schedule and are not detected by existing validation.

## Notes

The vulnerability specifically affects the consensus schedule integrity. While the attacker must be an elected miner, this is a reasonable permission level for consensus operations. The attack does not require compromising cryptographic keys or breaking protocol assumptions - it simply exploits missing input validation on a publicly accessible method that miners are expected to call during normal operation.

### Citations

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L13-17)
```csharp
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```
