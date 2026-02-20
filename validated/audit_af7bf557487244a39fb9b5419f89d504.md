# Audit Report

## Title
Mining Order Collision via Unchecked TuneOrderInformation Allows Time Slot Conflicts and Consensus Disruption

## Summary
The AEDPoS consensus contract allows malicious miners to inject colliding `FinalOrderOfNextRound` values through consensus extra data without validation, causing multiple miners to be assigned identical mining time slots in subsequent rounds, breaking the fundamental consensus invariant of unique time slot assignment per miner.

## Finding Description

The vulnerability exists in the `UpdateValue` consensus behavior validation and processing pipeline, where order collision validation is completely missing.

**Root Cause:**

The `ProcessUpdateValue` method directly applies `TuneOrderInformation` from consensus extra data without validating uniqueness of `FinalOrderOfNextRound` values. [1](#0-0) 

These values are blindly written to state for all affected miners with no collision checks.

**Missing Validation:**

For `UpdateValue` behavior, the validation pipeline only includes `UpdateValueValidationProvider` and `LibInformationValidationProvider`: [2](#0-1) 

The `UpdateValueValidationProvider` only validates OutValue/Signature and PreviousInValue correctness - it performs no order collision checks: [3](#0-2) 

The `NextRoundMiningOrderValidationProvider` exists but is only used for `NextRound` behavior, not `UpdateValue`: [4](#0-3) 

**How Legitimate Collision Resolution is Bypassed:**

Normal flow uses collision resolution in `ApplyNormalConsensusData`: [5](#0-4) 

However, this only applies when honest miners generate consensus extra data. A malicious miner can:

1. Generate legitimate consensus extra data with collision-resolved orders
2. Modify the `Round` object in consensus extra data to inject colliding `FinalOrderOfNextRound` values
3. Include this modified data in their block header

During validation, `RecoverFromUpdateValue` directly overwrites the `FinalOrderOfNextRound` values from the provided Round for all miners: [6](#0-5) 

The simplified Round in consensus extra data includes `FinalOrderOfNextRound` for all miners: [7](#0-6) 

**Direct Impact on Next Round Generation:**

When the next round is generated, miners' `Order` values are directly assigned from their `FinalOrderOfNextRound`: [8](#0-7) 

Multiple miners with identical `FinalOrderOfNextRound` values will receive identical `Order` values and identical `ExpectedMiningTime` values. This creates a time slot collision where multiple miners believe they should mine at exactly the same time.

## Impact Explanation

**HIGH Severity - Consensus Integrity Violation:**

- **Broken Invariant:** The core consensus mechanism requires each miner to have a unique time slot. This vulnerability allows multiple miners to be assigned the same time slot, breaking this fundamental guarantee.

- **Consensus Disruption:** When multiple miners have identical `ExpectedMiningTime` values, both will attempt to mine at the same time. The `TimeSlotValidationProvider` will accept blocks from both miners since both are within their "valid" time slot, creating race conditions and consensus conflicts. [9](#0-8) 

- **No Recovery Mechanism:** Once colliding orders are written to state via `ProcessUpdateValue`, they persist until the next term transition. The network may experience reduced block production efficiency or stalls during this period.

- **Blockchain Availability Impact:** Critical miners being assigned duplicate slots can prevent orderly block production if they're unable to coordinate who should actually mine.

- **Exploit Scope:** Any active miner can execute this attack, affecting all subsequent rounds until term transition.

## Likelihood Explanation

**HIGH Likelihood:**

**Attacker Requirements:**
- Must be an active miner (block producer) in the current consensus set
- Requires modified node software to craft malicious consensus extra data
- No additional governance permissions or key compromise needed

**Attack Complexity:**
- Straightforward technical execution - modify the `FinalOrderOfNextRound` values in the Round object before including in block header
- No complex cryptographic operations required
- No timing constraints or race conditions to exploit
- Single malicious block can inject colliding orders

**Feasibility:**
- Being in the active miner set is the intended precondition for participating in consensus
- Modifying consensus extra data before signing the block header is trivial with custom node software
- The malicious data passes all existing validations
- Attack persists across multiple rounds until term transition

**Detection:**
- Malicious input appears structurally valid to all existing validation providers
- Collision only becomes apparent when next round is generated
- No automated on-chain detection or rejection mechanism exists

## Recommendation

Add collision validation for `UpdateValue` behavior by applying the `NextRoundMiningOrderValidationProvider` or creating a dedicated validation provider that checks for duplicate `FinalOrderOfNextRound` values.

**Option 1:** Include `NextRoundMiningOrderValidationProvider` in the `UpdateValue` validation pipeline:

```csharp
case AElfConsensusBehaviour.UpdateValue:
    validationProviders.Add(new UpdateValueValidationProvider());
    validationProviders.Add(new NextRoundMiningOrderValidationProvider()); // Add this
    validationProviders.Add(new LibInformationValidationProvider());
    break;
```

**Option 2:** Create a dedicated order uniqueness validator that explicitly checks for collisions in `FinalOrderOfNextRound` values and add it to the UpdateValue validation pipeline.

**Option 3:** Add collision check directly in `RecoverFromUpdateValue` or `ProcessUpdateValue` before applying the tuned orders.

## Proof of Concept

A proof of concept would require setting up an AEDPoS test environment where:

1. A malicious miner node generates valid consensus extra data using the standard flow
2. Before signing the block, modify the `Round.RealTimeMinersInformation[miner_A].FinalOrderOfNextRound` and `Round.RealTimeMinersInformation[miner_B].FinalOrderOfNextRound` to have the same value (e.g., both set to 5)
3. Sign and broadcast the block
4. Verify the block passes validation
5. When the next round is generated, observe that both miner_A and miner_B have identical `Order` and `ExpectedMiningTime` values in the new round

This would demonstrate the consensus invariant violation where two distinct miners are assigned the same mining time slot.

---

## Notes

The vulnerability is particularly concerning because:

1. **Validation Gap**: The `NextRoundMiningOrderValidationProvider` already exists and checks for order conflicts, but it's only applied to `NextRound` behavior, not `UpdateValue`. This suggests the developers recognized the need for such validation but didn't apply it consistently.

2. **Two Injection Paths**: Colliding orders can be injected both through `RecoverFromUpdateValue` during validation and through `TuneOrderInformation` during execution, providing multiple attack vectors.

3. **Persistence**: Unlike many consensus attacks that might be temporary or self-correcting, this attack's effects persist across multiple rounds until a term transition occurs, potentially causing extended network disruption.

4. **Byzantine Tolerance Assumption**: The AEDPoS consensus is designed to tolerate Byzantine miners, but this vulnerability allows a single Byzantine miner to violate fundamental consensus invariants without detection.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-40)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L35-53)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```
