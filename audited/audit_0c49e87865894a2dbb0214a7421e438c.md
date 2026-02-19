# Audit Report

## Title
Missing Bounds Validation on Order Values Allows Mining Schedule Disruption via Malicious Consensus Headers

## Summary
The AEDPoS consensus contract lacks bounds validation on `Order`, `SupposedOrderOfNextRound`, and `FinalOrderOfNextRound` values when processing `UpdateValue` consensus information. A malicious miner can inject out-of-range Order values (e.g., 0, negative, or exceeding miner count) that bypass validation and corrupt the mining schedule, potentially causing consensus failures and chain halt.

## Finding Description

The vulnerability exists in the consensus validation and processing pipeline for `UpdateValue` behavior:

**Entry Point - No Validation During Copy**: The `GetUpdateValueRound()` method copies Order values directly without any bounds checking. [1](#0-0) [2](#0-1) [3](#0-2) 

**Root Cause - Block Validation Accepts Invalid Values**: During block validation, `RecoverFromUpdateValue()` directly copies `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` from the block header's Round object into the current round state without any bounds checking. [4](#0-3) 

**Missing Validation Layer**: The `UpdateValueValidationProvider` only validates `OutValue` and `PreviousInValue` fields, completely ignoring Order-related fields. [5](#0-4)  The validation checks at lines 13-17 only verify consensus information is filled (OutValue/Signature) and PreviousInValue correctness, with no bounds checking on Order values.

**State Corruption Path**: During execution, `ProcessUpdateValue()` accepts Order values from the input without validation and stores them directly in state. [6](#0-5)  Additionally, `TuneOrderInformation` from the input is applied without validation. [7](#0-6) 

**Impact Trigger - Consensus Failure**: When generating the next round, `GenerateNextRoundInformation()` uses these corrupted `FinalOrderOfNextRound` values to set mining schedules. [8](#0-7)  The Order is set directly from `FinalOrderOfNextRound` at line 32, and `ExpectedMiningTime` is calculated by multiplying the Order with the mining interval at line 33. If Order is 0, this produces an immediate mining time; if negative, it produces a past timestamp.

The `BreakContinuousMining()` function assumes valid Order values and will throw an exception when searching for miners with `Order == 1` if no such miner exists. [9](#0-8)  Similarly, line 94 searches for a miner with `Order == minersCount`.

**Validation Pipeline Gap**: The `ValidateBeforeExecution()` method only adds `UpdateValueValidationProvider` for UpdateValue behavior, which doesn't validate Order fields. [10](#0-9)  Note that `NextRoundMiningOrderValidationProvider` (which does validate FinalOrderOfNextRound) is only added for NextRound behavior (line 86), not for UpdateValue.

**Attack Execution**: A malicious miner can:
1. Modify their node software to bypass the normal Order calculation in `ApplyNormalConsensusData` [11](#0-10)  which normally ensures Order is between 1 and minersCount
2. Craft an `UpdateValueInput` with `supposed_order_of_next_round = 0` (or negative, or > minersCount)
3. Create a block header with matching malicious Order values in the Round object
4. Sign and broadcast the block

The block will pass validation because `RecoverFromUpdateValue` is called during validation [12](#0-11)  but no validator checks Order bounds.

## Impact Explanation

**Severity: High - Consensus Integrity Violation**

This vulnerability breaks critical mining schedule invariants with network-wide impact:

1. **Order = 0**: Creates immediate time slot conflicts as `ExpectedMiningTime = currentBlockTimestamp + (miningInterval × 0) = currentBlockTimestamp`. The `BreakContinuousMining()` function will throw `InvalidOperationException` when calling `First(i => i.Order == 1)` if no miner has Order 1 (because someone has Order 0).

2. **Order > minersCount**: Line 94 in `BreakContinuousMining` searches for a miner with `Order == minersCount`, which may not exist. Extra block producer selection at lines 61-65 may also select incorrect miners or fail.

3. **Negative Orders**: In C# with int32 types (as defined in the protobuf), negative values produce past timestamps for `ExpectedMiningTime`, causing incorrect time slot validation and potentially allowing unauthorized block production.

4. **Duplicate Orders**: The `TuneOrderInformation` mechanism allows setting multiple miners to the same Order value, creating ambiguous mining schedules where multiple miners have identical `ExpectedMiningTime`.

**Consensus Impact**: When `NextRound` is called after state corruption, `GenerateNextRoundInformation` will either:
- Throw an exception (halting round progression)
- Create an invalid mining schedule (breaking time slot invariants)
- Allow unauthorized mining (if negative Orders enable mining in the past)

This affects the entire network, not just the malicious miner. Manual intervention would be required to recover from a chain halt.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements**:
- Must be in the active miner list (achievable via staking/election to become a block producer)
- Must modify node software to inject malicious Order values before block signing
- Moderate technical capability to understand consensus protocol internals

**Attack Feasibility**: 
- **Clear Gap**: The validation pipeline has an obvious gap - `UpdateValueValidationProvider` checks OutValue/PreviousInValue but completely ignores Order fields
- **Miner Control**: Block headers and transactions are created by miners who have full control over their content before signing
- **No Detection**: No runtime mechanism exists to detect out-of-bounds Order values before state corruption
- **Repeatable**: Attack can be executed in every block the malicious miner produces

**Economic Considerations**:
- Attacker must invest in becoming a miner (staking requirement)
- However, a malicious miner might execute this to:
  - Disrupt competitors during critical operations
  - Manipulate consensus timing for front-running
  - Force chain halt requiring governance intervention (griefing attack)
  - Gain reputational advantage if they then "rescue" the chain

The combination of clear technical feasibility and potential strategic motivations makes this vulnerability likely to be exploited if discovered.

## Recommendation

Add bounds validation for Order-related fields in multiple layers:

1. **Extend UpdateValueValidationProvider** to validate Order bounds:
```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    if (!NewConsensusInformationFilled(validationContext))
        return new ValidationResult { Message = "Incorrect new Out Value." };

    if (!ValidatePreviousInValue(validationContext))
        return new ValidationResult { Message = "Incorrect previous in value." };

    // ADD THIS: Validate Order bounds
    if (!ValidateOrderBounds(validationContext))
        return new ValidationResult { Message = "Invalid order values." };

    return new ValidationResult { Success = true };
}

private bool ValidateOrderBounds(ConsensusValidationContext validationContext)
{
    var providedRound = validationContext.ProvidedRound;
    var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
    
    foreach (var miner in providedRound.RealTimeMinersInformation.Values)
    {
        if (miner.SupposedOrderOfNextRound < 0 || miner.SupposedOrderOfNextRound > minersCount)
            return false;
        if (miner.FinalOrderOfNextRound < 0 || miner.FinalOrderOfNextRound > minersCount)
            return false;
    }
    
    return true;
}
```

2. **Add validation in ProcessUpdateValue** before storing values:
```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate bounds before storing
    Assert(updateValueInput.SupposedOrderOfNextRound >= 1 && 
           updateValueInput.SupposedOrderOfNextRound <= minersCount,
           "Invalid SupposedOrderOfNextRound.");
    
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount,
               "Invalid order in TuneOrderInformation.");
    }
    
    // ... rest of the function
}
```

3. **Add defensive check in BreakContinuousMining**:
```csharp
private void BreakContinuousMining(ref Round nextRound)
{
    var minersCount = RealTimeMinersInformation.Count;
    if (minersCount <= 1) return;

    // ADD THIS: Defensive check
    var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values
        .FirstOrDefault(i => i.Order == 1);
    if (firstMinerOfNextRound == null) return; // Skip if invalid state
    
    // ... rest of the function
}
```

## Proof of Concept

The POC would demonstrate creating a malicious `UpdateValueInput` with `supposed_order_of_next_round = 0`, showing that:
1. The validation passes (no Order bounds checking)
2. The value is stored in state
3. When `GenerateNextRoundInformation` is called for the next round, `BreakContinuousMining` throws an exception

Since this requires modifying miner behavior and cannot be executed via a simple contract call, a full POC would require:
- Setting up a test consensus contract with multiple miners
- Simulating a malicious miner that injects Order = 0
- Demonstrating that block validation passes
- Showing that subsequent `NextRound` call fails with exception

The vulnerability is confirmed through code analysis showing the missing validation layer and the subsequent exception in `BreakContinuousMining` when Order invariants are violated.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L30-30)
```csharp
                    Order = minerInRound.Order,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L38-40)
```csharp
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L47-49)
```csharp
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-79)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
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
