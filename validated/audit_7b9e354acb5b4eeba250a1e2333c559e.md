# Audit Report

## Title
Duplicate FinalOrderOfNextRound Values Bypass Validation Due to Incorrect Distinctness Check and Wrong Round Validation

## Summary
The AEDPoS consensus validation contains two critical bugs that allow miners to inject duplicate `FinalOrderOfNextRound` values, corrupting the next round's mining schedule and potentially halting consensus.

## Finding Description

The AEDPoS consensus mechanism relies on unique mining orders to coordinate block production. However, the validation logic contains two bugs that allow miners to corrupt the mining schedule:

**Bug #1: Incorrect Use of .Distinct()**

The `NextRoundMiningOrderValidationProvider` attempts to verify uniqueness of `FinalOrderOfNextRound` values but incorrectly applies `.Distinct()` to entire `MinerInRound` objects. [1](#0-0) 

Since `MinerInRound` is a protobuf message where each object has a unique `pubkey` field [2](#0-1) , the objects will always be considered distinct even with duplicate `FinalOrderOfNextRound` values. The correct implementation should extract the `FinalOrderOfNextRound` values before applying `.Distinct()`.

**Bug #2: Validating Wrong Round**

The validation checks `providedRound` which is the next round being proposed [3](#0-2) . However, when generating the next round, the `FinalOrderOfNextRound` field is NOT copied to new `MinerInRound` objects: [4](#0-3) 

The new `MinerInRound` objects only have `Order` set from the current round's `FinalOrderOfNextRound`. The `FinalOrderOfNextRound` field itself defaults to 0 in the next round, making the validation check meaningless.

**Attack Vector: Unvalidated TuneOrderInformation**

During `UpdateValue` transactions, miners can set `TuneOrderInformation` with duplicate values that are applied directly without validation: [5](#0-4) 

The `UpdateValueValidationProvider` only validates `OutValue` and `PreviousInValue`: [6](#0-5) 

Furthermore, `NextRoundMiningOrderValidationProvider` is only invoked for `NextRound` behavior, not `UpdateValue`: [7](#0-6) 

**Consensus Corruption**

When the next round is generated with duplicate `FinalOrderOfNextRound` values, multiple miners receive the same `Order`: [8](#0-7) 

The `occupiedOrders` list will contain duplicates: [9](#0-8) 

This causes the `ableOrders` calculation to malfunction, leaving some miners with conflicting time slots and others with no valid assignments.

## Impact Explanation

**Consensus Integrity Failure (Critical)**

This vulnerability allows miners to corrupt the mining schedule for the next round:

1. **Schedule Corruption**: Multiple miners assigned the same `Order` value create conflicts in time slot assignments, preventing proper determination of which miner should produce blocks at each time slot.

2. **Miner Displacement**: The `occupiedOrders` list with duplicates causes incorrect exclusion of available orders, resulting in some miners being assigned to already-occupied slots or left without valid time slots.

3. **Consensus Halt Risk**: A malformed round schedule with conflicting orders prevents proper block production coordination, potentially causing chain halts, skipped blocks, or complete consensus failure.

4. **Fairness Violation**: Colluding miners can manipulate time slot assignments to exclude specific miners or favor certain participants, breaking the consensus algorithm's fairness guarantees.

The attack directly violates the critical invariant that each time slot must have exactly one assigned miner with a unique order value.

## Likelihood Explanation

**High Likelihood - Practical Attack**

1. **Reachable Entry Point**: The attack uses the public `UpdateValue` method that all miners call during normal block production.

2. **Feasible Preconditions**: Only requires 2+ colluding miners (realistic in PoS systems) with no governance approvals or special states needed.

3. **Execution Practicality**: Miner A calls `UpdateValue` with `TuneOrderInformation = {"MinerB": 5, "MinerC": 5}` to inject duplicates. Values are applied directly without validation. When `NextRound` is triggered, the buggy validation passes and the generated round has corrupted assignments.

4. **Economic Rationality**: Low cost (only requires coordinating `UpdateValue` transactions) with high impact (disrupts consensus network-wide).

5. **Detection Constraints**: The bugs are in the validation logic itself, so malicious transactions appear valid until the corrupted round is generated and consensus fails.

## Recommendation

**Fix Bug #1 - Correct Distinctness Check:**
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Extract values first
    .Distinct()
    .Count();
```

**Fix Bug #2 - Validate Current Round:**
```csharp
// Use validationContext.BaseRound (current round) instead of providedRound
var distinctCount = validationContext.BaseRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

**Add TuneOrderInformation Validation:**

Add a validation check in `ProcessUpdateValue` or invoke `NextRoundMiningOrderValidationProvider` for `UpdateValue` behavior to ensure duplicate orders cannot be set via `TuneOrderInformation`.

## Proof of Concept

A test demonstrating the vulnerability would:

1. Create a round with 5 miners (A, B, C, D, E)
2. Have Miner A produce a block with `UpdateValue` containing `TuneOrderInformation = {"B": 3, "C": 3}`
3. Verify that both Miner B and Miner C have `FinalOrderOfNextRound = 3` in the current round
4. Generate the next round using `GenerateNextRoundInformation`
5. Assert that both Miner B and Miner C have `Order = 3` in the next round (consensus corruption)
6. Verify that the `occupiedOrders` list contains duplicate values
7. Demonstrate that the `ableOrders` calculation produces incorrect results

The test would confirm that the validation fails to detect duplicates and the next round generation creates conflicting assignments.

---

**Notes**

This vulnerability affects the core consensus mechanism and can be exploited with standard miner privileges. The two bugs work together: Bug #1 prevents detection of duplicates in the distinctness check, and Bug #2 makes the check operate on the wrong data (next round with all zeros instead of current round with actual values). The attack bypasses validation by using `UpdateValue` behavior which doesn't invoke the `NextRoundMiningOrderValidationProvider`. All referenced files are in-scope production contract code.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L284-290)
```text
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-28)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-49)
```csharp
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
