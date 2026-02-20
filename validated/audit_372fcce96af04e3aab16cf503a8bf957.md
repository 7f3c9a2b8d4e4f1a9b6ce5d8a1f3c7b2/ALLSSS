# Audit Report

## Title
Ineffective FinalOrderOfNextRound Uniqueness Validation Allows Mining Order Manipulation

## Summary
The AEDPoS consensus contract contains three interconnected validation gaps that allow a malicious miner with modified node software to inject duplicate `FinalOrderOfNextRound` values through `UpdateValue` transactions. This breaks the consensus invariant requiring unique mining orders and can cause multiple miners to be assigned the same Order value in subsequent rounds, leading to time slot conflicts and potential consensus failure.

## Finding Description

The vulnerability consists of three validated issues:

**Issue 1: Broken Uniqueness Validation Logic**

The `NextRoundMiningOrderValidationProvider` attempts to validate that each miner has a unique `FinalOrderOfNextRound` value, but the implementation is critically flawed. [1](#0-0) 

The code calls `.Distinct()` on the collection of `MinerInRound` objects themselves rather than on their `FinalOrderOfNextRound` property values. Since `MinerInRound` is a protobuf-generated message [2](#0-1) , each miner object instance is distinct regardless of whether their `FinalOrderOfNextRound` values are duplicated. This renders the uniqueness check completely ineffective.

**Issue 2: Missing Validation in ProcessUpdateValue**

When `ProcessUpdateValue` applies `TuneOrderInformation`, it does so without any validation of uniqueness or value ranges: [3](#0-2) 

The `TuneOrderInformation` dictionary from `UpdateValueInput` is directly applied to miners' `FinalOrderOfNextRound` values with zero validation that these values are unique, within valid ranges, or correspond to actual miners in the round.

**Issue 3: Limited Validator Scope**

The `NextRoundMiningOrderValidationProvider` is only registered for `NextRound` behavior, not for `UpdateValue`: [4](#0-3) 

When an `UpdateValue` transaction is validated, only `UpdateValueValidationProvider` and `LibInformationValidationProvider` are registered. The order validation provider is never executed. [5](#0-4) 

**Attack Execution Path**:

1. A malicious miner running modified node software constructs an `UpdateValueInput` with crafted `TuneOrderInformation` containing duplicate `FinalOrderOfNextRound` values
2. The miner produces a block with consensus header containing the same malicious round data
3. During validation, `UpdateValueValidationProvider` executes but does not check `TuneOrderInformation` for uniqueness
4. The malicious transaction executes via `ProcessUpdateValue`, writing duplicate orders to state
5. `ValidateConsensusAfterExecution` compares hashes - since both header and state contain identical malicious data, validation passes [6](#0-5) 
6. When `GenerateNextRoundInformation` is called for the next round, it orders miners by their compromised `FinalOrderOfNextRound` values [7](#0-6) 
7. Multiple miners are assigned the same `Order` value in the next round, violating the consensus invariant

## Impact Explanation

**Severity: HIGH**

This vulnerability directly compromises consensus integrity by breaking the fundamental invariant that each miner must have a unique mining order:

- **Duplicate Order Assignment**: When `GenerateNextRoundInformation` processes miners with duplicate `FinalOrderOfNextRound` values, multiple miners receive the same `Order` value in the next round
- **Time Slot Conflicts**: Multiple miners with identical Order values will have overlapping `ExpectedMiningTime` slots, causing them to simultaneously believe they should produce blocks
- **Validation Failures**: Time slot validation and other consensus checks expect unique orders; duplicate orders cause validation conflicts when blocks are produced
- **Consensus Breakdown**: Nodes may reject each other's blocks as invalid due to order conflicts, potentially fragmenting the network
- **System-Wide Impact**: All network participants are affected as the integrity of the block production schedule is fundamental to blockchain operation

The attack breaks the core security guarantee that all honest nodes must agree on a deterministic mining schedule.

## Likelihood Explanation

**Likelihood: MEDIUM**

Required attack capabilities:
- **Miner Status**: Attacker must be in the current miner set, achievable through the normal election process
- **Modified Node Software**: Attacker must modify their node code to generate malicious `UpdateValueInput` with duplicate `FinalOrderOfNextRound` values
- **Technical Understanding**: Attacker must understand consensus mechanics to craft matching malicious data in both the block header and transaction

The complete absence of validation for `TuneOrderInformation` uniqueness makes exploitation practical once the attacker has modified node software. The hash comparison in `ValidateConsensusAfterExecution` does not prevent the attack because both the header and state contain identical malicious data.

While requiring miner status and code modification raises the barrier, motivated adversaries (e.g., competing miners seeking to disrupt consensus) could execute this attack.

## Recommendation

Implement three defensive fixes:

1. **Fix NextRoundMiningOrderValidationProvider uniqueness check**:
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Add this line
    .Distinct().Count();
```

2. **Add TuneOrderInformation validation in ProcessUpdateValue**:
```csharp
// Before line 259, add:
var tuneOrderValues = updateValueInput.TuneOrderInformation.Values.ToList();
if (tuneOrderValues.Distinct().Count() != tuneOrderValues.Count)
    Assert(false, "Duplicate FinalOrderOfNextRound values in TuneOrderInformation");

var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(tuneOrder.Value > 0 && tuneOrder.Value <= minersCount, 
        "Invalid FinalOrderOfNextRound value");
    Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
        "Unknown miner in TuneOrderInformation");
}
```

3. **Register NextRoundMiningOrderValidationProvider for UpdateValue**:
```csharp
case AElfConsensusBehaviour.UpdateValue:
    validationProviders.Add(new UpdateValueValidationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider()); // Add this
    validationProviders.Add(new LibInformationValidationProvider());
    break;
```

## Proof of Concept

A test demonstrating the vulnerability would:
1. Create a round with multiple miners
2. Construct an `UpdateValueInput` with `TuneOrderInformation` containing duplicate `FinalOrderOfNextRound` values (e.g., two miners both set to order 5)
3. Call `ProcessUpdateValue` - observe it succeeds without validation errors
4. Call `GenerateNextRoundInformation` on the corrupted round
5. Verify that the next round has multiple miners with the same `Order` value
6. Demonstrate that this breaks time slot validation when those miners attempt to produce blocks

The test would confirm that all three validation gaps exist and allow duplicate orders to be written to state and propagated to subsequent rounds.

---

**Notes:**

This is a legitimate consensus integrity vulnerability arising from incomplete validation in the AEDPoS implementation. The three issues are interconnected: the broken validator (Issue 1) doesn't work even when called, it's not registered for the right behavior (Issue 3), and the processing logic has no fallback validation (Issue 2). An attacker with modified node software can exploit these gaps to corrupt the mining schedule, though the attack requires miner status and technical sophistication.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-290)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-33)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
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
