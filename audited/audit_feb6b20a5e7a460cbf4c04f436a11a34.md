# Audit Report

## Title
Mining Order Manipulation via Unchecked FinalOrderOfNextRound in Consensus Extra Data

## Summary
A malicious miner can arbitrarily manipulate the mining order for the next round by crafting consensus extra data with malicious `FinalOrderOfNextRound` values. The validation system fails to verify these values against legitimate calculations, allowing the attacker to reorder the mining schedule through the `TuneOrderInformation` mechanism, directly compromising consensus integrity.

## Finding Description

The AEDPoS consensus mechanism relies on `FinalOrderOfNextRound` values to determine the mining schedule for the next round. However, the validation flow contains a critical flaw that allows miners to inject arbitrary `FinalOrderOfNextRound` values for other miners without detection.

**Vulnerable Flow:**

When a miner produces a block with `UpdateValue` behavior, the validation process calls `RecoverFromUpdateValue` which blindly copies all miners' `FinalOrderOfNextRound` values from the block header into the current round state: [1](#0-0) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, but completely ignores `FinalOrderOfNextRound`: [2](#0-1) 

The `NextRoundMiningOrderValidationProvider` that could validate `FinalOrderOfNextRound` is only applied for `NextRound` behavior, not `UpdateValue`: [3](#0-2) 

**Hash Validation Bypass:**

The hash validation in `ValidateConsensusAfterExecution` fails to catch this manipulation due to a logic error. After calling `RecoverFromUpdateValue`, the method reassigns `headerInformation.Round` to point to the same modified `currentRound` object, then compares its hash to itself: [4](#0-3) 

Since `RecoverFromUpdateValue` returns `this` (the modified currentRound), both sides of the hash comparison reference the same object, making the check always pass.

**State Persistence:**

The malicious `FinalOrderOfNextRound` values are extracted as `TuneOrderInformation` and applied to the persistent state: [5](#0-4) [6](#0-5) 

**Direct Impact on Next Round:**

These manipulated values directly control the mining order when generating the next round: [7](#0-6) 

While the legitimate calculation uses deterministic signature-based ordering with conflict resolution: [8](#0-7) 

This legitimate calculation is never validated against the header-provided values during `UpdateValue` behavior.

## Impact Explanation

**CRITICAL - Consensus Integrity Violation**: This vulnerability directly breaks the core consensus invariant of fair, deterministic miner scheduling. A malicious miner can:

1. **Arbitrarily Reorder Mining Schedule**: Set any order for the next round, positioning themselves or colluding miners in advantageous positions
2. **Enable Targeted Censorship**: Control which miners mine first to censor specific transactions or blocks
3. **Extract MEV**: Optimize block ordering for maximum extractable value across multiple blocks
4. **Disrupt Network Operation**: Force honest miners into unfavorable time slots, potentially causing them to miss blocks and be marked as "evil miners"
5. **Setup Chain Reorganization**: Create specific block production sequences as precursors to more sophisticated attacks

The entire network's consensus mechanism is compromised, affecting all participants - miners lose fair scheduling, and users experience potential transaction censorship and reduced network security.

## Likelihood Explanation

**HIGH Likelihood**: The attack is highly feasible with minimal complexity:

**Attacker Requirements:**
- Must be a valid miner in the current round (normal operational role)
- No special privileges or compromised keys required

**Attack Complexity:**
- Load current round state (publicly available)
- Modify `FinalOrderOfNextRound` values in the Round object before including in block header
- The consensus extra data generation provides the legitimate template that can be trivially modified

**No Effective Barriers:**
- No validation of `FinalOrderOfNextRound` for `UpdateValue` behavior
- Hash check fails due to same-object comparison
- Values within valid ranges appear legitimate
- No detection mechanisms or audit trails

**Economic Incentive:**
- MEV opportunities provide direct financial motivation
- Competitive advantage over other miners
- Can be exploited repeatedly every round

## Recommendation

Implement comprehensive validation of `FinalOrderOfNextRound` values for `UpdateValue` behavior:

1. **Add validation to UpdateValueValidationProvider** to verify that `FinalOrderOfNextRound` matches the value that would be calculated by `ApplyNormalConsensusData` for each miner
2. **Fix the hash validation logic** in `ValidateConsensusAfterExecution` to compare against the original currentRound state before modification
3. **Apply NextRoundMiningOrderValidationProvider** to UpdateValue behavior, or create a dedicated validator
4. **Validate TuneOrderInformation** by recalculating expected conflict resolutions and comparing against provided values

Example fix for the hash validation:

```csharp
public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
{
    var headerInformation = new AElfConsensusHeaderInformation();
    headerInformation.MergeFrom(input.Value);
    if (TryToGetCurrentRoundInformation(out var currentRound))
    {
        // Store original hash BEFORE modification
        var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
        var originalHash = currentRound.GetHash(isContainPreviousInValue);
        
        if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
            currentRound.RecoverFromUpdateValue(headerInformation.Round,
                headerInformation.SenderPubkey.ToHex());
        
        // Compare against original hash
        if (headerInformation.Round.GetHash(isContainPreviousInValue) != originalHash)
        {
            return new ValidationResult { Success = false, Message = "Round hash mismatch" };
        }
    }
    return new ValidationResult { Success = true };
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a test miner that generates legitimate consensus extra data via `GetConsensusExtraData`
2. Modifying the Round object's `FinalOrderOfNextRound` values for other miners
3. Including this modified Round in the block header
4. Observing that `ValidateBeforeExecution` and `ValidateConsensusAfterExecution` both pass
5. Verifying that `ProcessUpdateValue` applies the malicious `TuneOrderInformation`
6. Confirming that `GenerateNextRoundInformation` uses the manipulated orders

The test would verify that:
- A block with manipulated `FinalOrderOfNextRound` values passes validation
- The manipulated values are persisted to state
- The next round's mining order reflects the manipulation
- No validation error or detection occurs

The core issue is architectural: the validation assumes header data is trustworthy after basic signature checks, without verifying derived consensus values against the deterministic calculation they should represent.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
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
