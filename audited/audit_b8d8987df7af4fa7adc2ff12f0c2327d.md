# Audit Report

## Title
Invalid Order Values Can Corrupt Block Production Sequence Through Unvalidated TuneOrderInformation

## Summary
A malicious miner can inject arbitrary values (including zero or negative integers) into the `TuneOrderInformation` field of `UpdateValue` transactions to corrupt miners' `FinalOrderOfNextRound` values. These corrupted values directly become `Order` values in the next round without validation, breaking critical consensus functions and causing blockchain halt. The `NextRoundMiningOrderValidationProvider` fails to detect this because it validates the newly generated round where `FinalOrderOfNextRound` defaults to 0, rather than validating the actual `Order` values being committed.

## Finding Description

The vulnerability exists across three critical stages of the AEDPoS consensus mechanism:

**Stage 1 - Unvalidated Input Processing:**

In `ProcessUpdateValue`, the `TuneOrderInformation` map from `UpdateValueInput` is applied directly to miners' `FinalOrderOfNextRound` values without any bounds checking or range validation: [1](#0-0) 

A malicious miner can set `TuneOrderInformation[targetMinerPubkey] = 0` (or any negative int32 value), and this value is directly assigned without validation. The protobuf definition explicitly allows int32 values including negatives: [2](#0-1) 

**Stage 2 - Invalid Values Propagated to Next Round:**

When `NextRound` is triggered, `GenerateNextRoundInformation` uses these corrupted `FinalOrderOfNextRound` values as the `Order` for miners in the next round: [3](#0-2) 

The `Order` field is directly assigned from `FinalOrderOfNextRound` at line 32 without any validation that it's a positive integer in the valid range [1, minersCount].

**Stage 3 - Validation Bypass:**

The `NextRoundMiningOrderValidationProvider` is supposed to prevent invalid mining orders, but it validates the wrong data structure. The validator checks the newly generated next round: [4](#0-3) 

The critical flaw is that `providedRound` (line 14) refers to the newly generated round returned from `GenerateNextRoundInformation`. In this newly created round structure, `FinalOrderOfNextRound` is NOT initialized (defaults to 0) and `OutValue` is NOT initialized (defaults to null) for all miners, as seen in the `MinerInRound` constructor: [5](#0-4) 

Therefore, the validation check becomes: `count(FinalOrderOfNextRound > 0) = 0 == count(OutValue != null) = 0`, which passes even when `Order` values are invalid (0 or negative).

**Legitimate Code Path Analysis:**

In the legitimate consensus flow, `FinalOrderOfNextRound` is calculated in `ApplyNormalConsensusData`: [6](#0-5) 

Line 21 calculates `supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1`, producing values in range [1, minersCount]. The conflict resolution loop (lines 31-40) produces values up to `minersCount * 2 - 1`, but never 0 due to the loop condition `i < minersCount * 2`. Therefore, `FinalOrderOfNextRound = 0` can ONLY occur through malicious `TuneOrderInformation` injection.

## Impact Explanation

**Severity: HIGH - Complete Consensus Disruption**

Critical consensus functions rely on valid `Order` values and will fail catastrophically with invalid orders:

1. **GetMiningInterval() Crash:** This function filters miners by `Order == 1` or `Order == 2` and accesses `firstTwoMiners[1]`: [7](#0-6) 

If no miner has `Order == 1` or `Order == 2`, the `firstTwoMiners` list will have fewer than 2 elements, causing an `ArgumentOutOfRangeException` when accessing index [1] at line 79. This function is called during:
- Next round generation (Round_Generation.cs line 20)
- Time slot validation (TimeSlotValidationProvider.cs)
- Multiple consensus operations

2. **FirstMiner() Returns Invalid Data:** This function searches for a miner with `Order == 1`: [8](#0-7) 

If no miner has `Order == 1`, this returns an empty `MinerInRound`, breaking time slot calculations in `IsTimeSlotPassed` (line 92) and other functions that depend on the first miner.

**Attack Outcome:** The blockchain halts as no valid mining schedule exists. Block production stops completely, requiring manual intervention or chain rollback to recover.

## Likelihood Explanation

**Likelihood: HIGH - Easily Exploitable by Any Miner**

**Reachable Entry Point:** The `UpdateValue` method is a public RPC method in the consensus contract accessible to all miners: [9](#0-8) 

**Feasible Preconditions:**
- Attacker must be a current miner (normal operational role)
- Attacker produces a block during their assigned time slot
- Cost: Only requires producing one malicious block with crafted `TuneOrderInformation`

**No Effective Protections:**
The `UpdateValueValidationProvider` only validates `OutValue` and `Signature` fields, NOT the `TuneOrderInformation` values: [10](#0-9) 

**Attack Detection:** The attack only becomes visible when `NextRound` is triggered and critical functions start failing, by which time the corrupted round has been committed to blockchain state.

## Recommendation

**Immediate Fix - Add Bounds Validation:**

Add validation in `ProcessUpdateValue` to ensure `TuneOrderInformation` values are within valid range:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // ... existing code ...
    
    // VALIDATION: Ensure tuned orders are within valid range
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value > 0 && tuneOrder.Value <= minersCount, 
            $"Invalid tuned order {tuneOrder.Value}. Must be in range [1, {minersCount}].");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            $"Cannot tune order for non-existent miner {tuneOrder.Key}.");
    }
    
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
        currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
    
    // ... rest of existing code ...
}
```

**Additional Fix - Strengthen NextRoundMiningOrderValidationProvider:**

Validate the actual `Order` values being committed, not just the count:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    var minersCount = providedRound.RealTimeMinersInformation.Count;
    
    // Validate Order values are in valid range [1, minersCount]
    var invalidOrders = providedRound.RealTimeMinersInformation.Values
        .Where(m => m.Order <= 0 || m.Order > minersCount).ToList();
    if (invalidOrders.Any())
    {
        validationResult.Message = $"Invalid Order values detected: {string.Join(", ", invalidOrders.Select(m => m.Order))}";
        return validationResult;
    }
    
    // Existing validation...
    var distinctCount = providedRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0).Distinct().Count();
    if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
    {
        validationResult.Message = "Invalid FinalOrderOfNextRound.";
        return validationResult;
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanCorruptConsensus_ByInjectingInvalidOrderValues()
{
    // Setup: Initialize consensus with multiple miners
    var initialMiners = await BootMiner();
    var currentRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    var maliciousMiner = initialMiners[0];
    var targetMiner = initialMiners[1];
    
    // Attack: Craft UpdateValueInput with invalid TuneOrderInformation
    var maliciousUpdateInput = new UpdateValueInput
    {
        // ... standard fields (OutValue, Signature, etc.) ...
        TuneOrderInformation = 
        {
            { targetMiner.PublicKey.ToHex(), 0 }  // Invalid order value!
        }
    };
    
    // Execute malicious UpdateValue - should be rejected but isn't
    await ConsensusContract.UpdateValue.SendAsync(maliciousUpdateInput);
    
    // Verify: Check that FinalOrderOfNextRound was corrupted
    currentRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(0, currentRound.RealTimeMinersInformation[targetMiner.PublicKey.ToHex()].FinalOrderOfNextRound);
    
    // Trigger NextRound to propagate corruption
    await ConsensusContract.NextRound.SendAsync(nextRoundInput);
    
    // Verify: GetMiningInterval should crash but validation passed
    var nextRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerWithOrder1 = nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1);
    
    // Critical assertion: No miner has Order == 1, consensus is broken
    Assert.Null(minerWithOrder1);
    
    // Attempting to call GetMiningInterval will throw exception
    // Blockchain is now halted
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L142-148)
```csharp
    public MinerInRound FirstMiner()
    {
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1)
            // Unlikely.
            : new MinerInRound();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
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
