# Audit Report

## Title
Consensus Disruption via Unvalidated Mining Order Manipulation in UpdateValue Transaction

## Summary
The AEDPoS consensus contract contains multiple interconnected validation flaws that allow malicious miners to manipulate mining orders for subsequent rounds. The combination of missing input validation, insufficient cryptographic checks, and a critical object reference bug in after-execution validation enables attackers to create duplicate mining orders, breaking consensus round transitions and causing network-wide service disruption.

## Finding Description

This vulnerability comprises four interconnected flaws in the consensus validation pipeline:

**Flaw 1: Missing Input Validation in ProcessUpdateValue**

The `ProcessUpdateValue` method directly accepts and applies order values from miner-provided input without verification: [1](#0-0) [2](#0-1) 

The system should calculate `SupposedOrderOfNextRound` from the miner's signature using the deterministic formula in `ApplyNormalConsensusData`: [3](#0-2) 

However, no validation exists to verify the provided value matches this calculation, and `TuneOrderInformation` modifications have no authorization checks.

**Flaw 2: Insufficient UpdateValue Validation**

The `UpdateValueValidationProvider` only validates cryptographic fields (OutValue, Signature, PreviousInValue), not order manipulation: [4](#0-3) 

**Flaw 3: Broken After-Execution Validation**

The `ValidateConsensusAfterExecution` method has a critical logic error where it modifies the `currentRound` object via `RecoverFromUpdateValue`, then assigns this modified object to `headerInformation.Round`: [5](#0-4) 

Since `RecoverFromUpdateValue` modifies and returns `this`, both variables reference the same modified object: [6](#0-5) 

This makes the subsequent hash comparison always pass, as it compares the same object against itself: [7](#0-6) 

**Flaw 4: Inadequate Duplicate Order Detection**

The `NextRoundMiningOrderValidationProvider` attempts to detect duplicate orders but uses `Distinct()` on `MinerInRound` objects rather than on the `FinalOrderOfNextRound` values themselves: [8](#0-7) 

Since each `MinerInRound` has a unique `Pubkey`, the objects are always distinct regardless of whether their `FinalOrderOfNextRound` values are duplicates. The validation should check distinctness of the order values, not the entire objects.

**Attack Execution:**

1. Malicious miner produces a block with correct consensus extra data in the header (generated normally via `GetConsensusBlockExtraData`)
2. But includes a crafted `UpdateValue` transaction with arbitrary `SupposedOrderOfNextRound` and/or `TuneOrderInformation` setting multiple miners to the same order
3. `ValidateConsensusBeforeExecution` passes (validates header, not transaction input directly)
4. `ProcessUpdateValue` executes, writing malicious orders to contract state
5. `ValidateConsensusAfterExecution` passes due to object reference bug
6. When `GenerateNextRoundInformation` runs for the next round, it assigns duplicate `Order` values based on the malicious `FinalOrderOfNextRound`: [9](#0-8) 

## Impact Explanation

**High Severity - Consensus Integrity Violation**

Multiple miners assigned identical mining orders will attempt to produce blocks at the same time slot, causing:

1. **Fork Conditions**: Multiple valid blocks at the same height with the same order number
2. **Round Transition Failure**: The blockchain cannot proceed normally to subsequent rounds as the consensus mechanism breaks down
3. **Network-Wide Impact**: All nodes experience synchronization failures when encountering duplicate mining orders
4. **Complete Service Disruption**: Token transfers, governance votes, cross-chain operations, and all blockchain functions become unavailable
5. **Manual Intervention Required**: Emergency governance action needed to recover consensus

This violates the critical consensus invariant: "Each miner has a unique order in each round ensuring sequential block production."

## Likelihood Explanation

**High Likelihood**

- **Reachable Entry Point**: `UpdateValue` is the standard method called by all miners during normal block production
- **Low Attacker Requirements**: Any authorized miner can exploit this independently; coordination with other miners not required
- **No Special Privileges Needed**: Only requires normal mining permission granted through the election process
- **Trivial Execution**: Simply craft `UpdateValueInput` with desired order values when producing a block
- **No Detection**: All validation checks pass due to the four interconnected bugs identified
- **Minimal Cost**: Standard transaction fees only

The combination of easy execution, low barrier to entry, and multiple bypassed validation layers makes exploitation highly probable in practice.

## Recommendation

**Fix 1: Add Order Validation in ProcessUpdateValue**

Validate that `SupposedOrderOfNextRound` matches the calculated value and authorize `TuneOrderInformation` changes. Add validation before lines 246-247 in `AEDPoSContract_ProcessConsensusInformation.cs` to verify the miner's claimed order matches the deterministic calculation.

**Fix 2: Enhance UpdateValueValidationProvider**

Extend validation to check mining order fields, not just cryptographic data.

**Fix 3: Fix ValidateConsensusAfterExecution Object Reference Bug**

Clone `currentRound` before calling `RecoverFromUpdateValue`, or compare before modifying. Change the logic to properly compare the recovered header state against the actual execution state.

**Fix 4: Correct NextRoundMiningOrderValidationProvider**

Check distinctness of `FinalOrderOfNextRound` values specifically, not the entire `MinerInRound` objects. Replace the validation logic with a check that counts unique order values.

## Proof of Concept

A malicious miner can exploit this by:

1. Generating a valid block header using the normal `GetConsensusBlockExtraData` flow
2. Crafting an `UpdateValue` transaction with `SupposedOrderOfNextRound = 1` (or any desired value) and `TuneOrderInformation` setting their own and another miner's `FinalOrderOfNextRound` to the same value (e.g., both set to 1)
3. Including this transaction in their block
4. The block passes all validations due to the bugs
5. The malicious orders are written to state
6. In the next round, multiple miners receive `Order = 1`, causing consensus failure

The vulnerability is directly observable in the contract code where no validation prevents arbitrary order assignment, the after-execution check compares an object against itself, and the order duplication check examines the wrong data structure.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L87-92)
```csharp
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-17)
```csharp
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
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
