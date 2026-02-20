# Audit Report

## Title
Missing Bounds Validation on Order Values Allows Mining Schedule Disruption via Malicious Consensus Headers

## Summary
The AEDPoS consensus contract lacks bounds validation on `Order`, `SupposedOrderOfNextRound`, and `FinalOrderOfNextRound` values when processing `UpdateValue` consensus information. A malicious miner can inject out-of-range Order values (e.g., 0, negative, or exceeding miner count) that bypass validation and corrupt the mining schedule, potentially causing consensus failures and chain halt.

## Finding Description

The vulnerability exists in the consensus validation and processing pipeline for `UpdateValue` behavior, creating a critical security gap where Order values are never validated.

**Missing Validation Layer**: The `UpdateValueValidationProvider` only validates `OutValue` and `PreviousInValue` fields, completely ignoring all Order-related fields: [1](#0-0) 

**Unvalidated State Recovery**: During block validation, `RecoverFromUpdateValue()` directly copies `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` from the block header's Round object into the current round state without any bounds checking: [2](#0-1) 

**Validation Pipeline Gap**: The `ValidateBeforeExecution()` method only adds `UpdateValueValidationProvider` for UpdateValue behavior. Critically, `NextRoundMiningOrderValidationProvider` (which validates `FinalOrderOfNextRound > 0`) is only added for NextRound behavior at line 86, not for UpdateValue: [3](#0-2) 

**State Corruption During Execution**: `ProcessUpdateValue()` accepts Order values from the input without validation and stores them directly in state. Additionally, `TuneOrderInformation` from the input is applied without any bounds checking: [4](#0-3) 

**Impact Trigger - Consensus Failure**: When generating the next round, `GenerateNextRoundInformation()` uses these corrupted `FinalOrderOfNextRound` values to set mining schedules. The Order is set directly from `FinalOrderOfNextRound`, and `ExpectedMiningTime` is calculated by multiplying the Order with the mining interval: [5](#0-4) 

If Order is 0, this produces an immediate mining time; if negative, it produces a past timestamp.

**Exception Trigger**: The `BreakContinuousMining()` function assumes valid Order values and will throw an exception when searching for miners with `Order == 1` if no such miner exists: [6](#0-5) 

**No Schema Protection**: The protobuf definitions use unconstrained `int32` fields allowing arbitrary values including negative numbers and values exceeding miner count: [7](#0-6) [8](#0-7) 

**Attack Execution**: A malicious miner can:
1. Modify their node software to bypass the normal Order calculation in `ApplyNormalConsensusData` (which normally ensures Order ∈ [1, minersCount] via modulo operation)
2. Inject malicious `SupposedOrderOfNextRound` values (0, negative, or > minersCount) in the `UpdateValueInput`
3. Use `TuneOrderInformation` to corrupt other miners' `FinalOrderOfNextRound` values
4. Create a block header with matching malicious Order values in the Round object
5. Sign and broadcast the block

The block passes validation because `RecoverFromUpdateValue` is called during validation, but no validator checks Order bounds. State corruption occurs during execution, and consensus failure triggers when `NextRound` is subsequently called.

## Impact Explanation

**Severity: High - Consensus Integrity Violation**

This vulnerability breaks critical mining schedule invariants with network-wide impact:

1. **Order = 0**: Creates immediate time slot conflicts as `ExpectedMiningTime = currentBlockTimestamp + (miningInterval × 0) = currentBlockTimestamp`. If no miner has Order == 1, `BreakContinuousMining()` throws `InvalidOperationException` halting consensus.

2. **Negative Orders**: Produce past timestamps for `ExpectedMiningTime`, breaking time slot validation invariants and potentially allowing unauthorized block production outside assigned time windows.

3. **Order > minersCount**: Extra block producer selection fails, and `BreakContinuousMining` cannot find expected Order values, causing exceptions or incorrect scheduling.

4. **Duplicate Orders via TuneOrderInformation**: Multiple miners assigned the same Order value create ambiguous mining schedules where multiple miners have identical `ExpectedMiningTime`, violating the fundamental consensus invariant of unique time slots per miner.

**Consensus Impact**: When `NextRound` is called after state corruption, `GenerateNextRoundInformation` will either:
- Throw an exception halting round progression
- Create an invalid mining schedule breaking time slot invariants
- Allow scheduling conflicts enabling potential double-production or missed blocks

This affects the entire network, not just the malicious miner. Manual intervention would be required to recover from a chain halt, and the corrupted mining schedule persists until the next term transition.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements**:
- Must be in the active miner list (achievable via staking/election to become a block producer)
- Must modify node software to inject malicious Order values before block signing
- Moderate technical capability to understand consensus protocol internals

**Attack Feasibility**: 
- **Clear Validation Gap**: The validation pipeline has an obvious architectural gap - `UpdateValueValidationProvider` checks OutValue/PreviousInValue but completely ignores Order fields, while `NextRoundMiningOrderValidationProvider` is only used for NextRound behavior
- **Miner Control**: Block headers and transactions are created by miners who have full control over their content before signing
- **No Detection Mechanism**: No runtime mechanism exists to detect out-of-bounds Order values before state corruption occurs
- **Repeatable Attack**: Attack can be executed in every block the malicious miner produces, compounding the damage

**Economic Considerations**:
- Attacker must invest in becoming a miner (staking requirement)
- However, a malicious miner might execute this to:
  - Disrupt competitors during critical operations
  - Manipulate consensus timing for strategic advantage
  - Force chain halt requiring governance intervention (griefing attack)
  - Create market instability or exploit time-sensitive DeFi protocols

The combination of clear technical feasibility, straightforward attack vector, and potential strategic motivations makes this vulnerability likely to be exploited if discovered by a sophisticated adversary.

## Recommendation

Add Order bounds validation in multiple defense layers:

1. **In UpdateValueValidationProvider**: Add validation to check that all Order values are within valid range [1, minersCount]:
```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation
var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
foreach (var miner in validationContext.ProvidedRound.RealTimeMinersInformation.Values)
{
    if (miner.SupposedOrderOfNextRound < 1 || miner.SupposedOrderOfNextRound > minersCount)
        return new ValidationResult { Message = $"Invalid SupposedOrderOfNextRound: {miner.SupposedOrderOfNextRound}" };
    if (miner.FinalOrderOfNextRound < 1 || miner.FinalOrderOfNextRound > minersCount)
        return new ValidationResult { Message = $"Invalid FinalOrderOfNextRound: {miner.FinalOrderOfNextRound}" };
}
```

2. **In ProcessUpdateValue**: Add input validation before storing values:
```csharp
// Before line 246
var minersCount = currentRound.RealTimeMinersInformation.Count;
Assert(updateValueInput.SupposedOrderOfNextRound >= 1 && 
       updateValueInput.SupposedOrderOfNextRound <= minersCount, 
       "Invalid supposed order of next round");

// Before line 259
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
           $"Invalid tune order value: {tuneOrder.Value}");
}
```

3. **In RecoverFromUpdateValue**: Add defensive checks:
```csharp
// After line 24-27
var minersCount = RealTimeMinersInformation.Count;
foreach (var info in RealTimeMinersInformation.Values)
{
    if (info.SupposedOrderOfNextRound < 0 || info.SupposedOrderOfNextRound > minersCount)
        info.SupposedOrderOfNextRound = 0; // Reset invalid values
    if (info.FinalOrderOfNextRound < 0 || info.FinalOrderOfNextRound > minersCount)
        info.FinalOrderOfNextRound = 0; // Reset invalid values
}
```

## Proof of Concept

A malicious miner with modified node software executes the following attack:

1. During their mining turn, intercept the consensus data generation after `ApplyNormalConsensusData` calculates valid orders
2. Modify the `UpdateValueInput` to set `SupposedOrderOfNextRound = 0`
3. Add `TuneOrderInformation` entries setting other miners' `FinalOrderOfNextRound = 0`
4. Modify the block header's Round object with matching malicious Order values
5. Sign and broadcast the block

**Expected Result**: 
- Block validation passes (no Order validation for UpdateValue)
- `ProcessUpdateValue` stores corrupted Order values in state
- When next miner calls NextRound, `GenerateNextRoundInformation` creates mining schedule where multiple miners have Order = 0
- `BreakContinuousMining` throws `InvalidOperationException` when calling `First(i => i.Order == 1)` because no miner has Order == 1
- Consensus halts requiring manual intervention

**Test Verification**: The vulnerability can be verified by examining that UpdateValueValidationProvider lacks Order validation, while NextRoundMiningOrderValidationProvider (which has this validation) is only applied to NextRound behavior, not UpdateValue.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L242-260)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L78-95)
```csharp
        // First miner of next round != Extra block producer of current round
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }

        // Last miner of next round != Extra block producer of next round
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;
```

**File:** protobuf/aedpos_contract.proto (L205-208)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** protobuf/aedpos_contract.proto (L287-290)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
```
