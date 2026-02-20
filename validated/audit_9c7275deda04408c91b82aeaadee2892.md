# Audit Report

## Title
Mining Order Manipulation via Unvalidated TuneOrderInformation in UpdateValue

## Summary
A malicious miner can manipulate the mining order for the next consensus round by providing arbitrary `FinalOrderOfNextRound` values through the `TuneOrderInformation` field in `UpdateValueInput`. These values are applied to state without validation, allowing the attacker to control their mining position, skip legitimate miners, or disrupt the consensus schedule.

## Finding Description

The AEDPoS consensus mechanism allows miners to "tune" the mining order for the next round to resolve conflicts when multiple miners calculate the same supposed order. However, the `ProcessUpdateValue` method applies `TuneOrderInformation` from miner input directly to state without validating that the order values are legitimate or necessary. [1](#0-0) 

The intended behavior is that `TuneOrderInformation` should only contain miners whose `FinalOrderOfNextRound` differs from `SupposedOrderOfNextRound` due to conflict resolution: [2](#0-1) 

However, no validation enforces this constraint. The validation pipeline for UpdateValue behavior includes:

1. `UpdateValueValidationProvider` which only validates cryptographic fields (OutValue, Signature, PreviousInValue): [3](#0-2) 

2. `NextRoundMiningOrderValidationProvider` which validates `FinalOrderOfNextRound`, but is ONLY added for NextRound behavior, not UpdateValue: [4](#0-3) 

3. `RecoverFromUpdateValue` blindly copies `FinalOrderOfNextRound` values during validation without checking their legitimacy: [5](#0-4) 

When the next round is generated, `GenerateNextRoundInformation` uses the manipulated `FinalOrderOfNextRound` values to determine mining order: [6](#0-5) 

The `UpdateValue` method is public and accepts `UpdateValueInput` which includes the `tune_order_information` field: [7](#0-6) 

## Impact Explanation

This vulnerability breaks a critical consensus invariant: **miner schedule integrity**. The AEDPoS consensus guarantees that mining order is determined by cryptographic randomness (signature-based calculation), ensuring fair and unpredictable block producer rotation.

A malicious miner can:
- Set their own `FinalOrderOfNextRound` to 1 to mine first in the next round, gaining priority access to transactions and extra block producer benefits
- Manipulate other miners' orders to disadvantage competitors or create favorable time slots
- Create duplicate order values (e.g., multiple miners with order 1), causing the next round generation logic to produce invalid mining schedules
- Set invalid orders (e.g., orders > miner count), potentially causing DoS when `GenerateNextRoundInformation` calculates available orders

The impact severity is **HIGH** because:
- All miners in the network suffer from unfair schedule manipulation
- The network loses consensus fairness and predictability
- Transaction ordering can be manipulated if the attacker consistently mines first
- The core consensus mechanism's integrity is compromised without requiring sophisticated cryptographic attacks

## Likelihood Explanation

**Attacker Capabilities**: Must be a legitimate miner with mining permissions. This is a realistic precondition in a DPoS system where miners are elected but may have economic incentives to gain unfair advantages.

**Attack Complexity**: LOW. The attack is straightforward:
1. When producing a block with UpdateValue behavior, modify the `TuneOrderInformation` map in `UpdateValueInput`
2. Set arbitrary `FinalOrderOfNextRound` values for self and/or other miners
3. The transaction is included in the block as the normal consensus transaction

No cryptographic challenges, complex state manipulation, or additional privileges are required beyond normal mining operations.

**Economic Rationality**: High probability of exploitation because:
- No additional cost beyond normal mining operations
- Potential benefits include mining first (capturing MEV, extra rewards) or disadvantaging competitors
- Detection is difficult as manipulation occurs within normal UpdateValue transactions

**Execution Practicality**: The attack is directly executable. Any miner producing a block can craft `UpdateValue` with arbitrary `TuneOrderInformation` values through the standard block production mechanism.

## Recommendation

Add validation of `TuneOrderInformation` in `UpdateValueValidationProvider` or create a dedicated validation provider. The validation should ensure:

1. Only miners whose `SupposedOrderOfNextRound` conflicts with existing miners' orders can have `FinalOrderOfNextRound` values in `TuneOrderInformation`
2. All `FinalOrderOfNextRound` values are within valid range (1 to miner count)
3. No duplicate `FinalOrderOfNextRound` values exist after tuning
4. The tuned orders follow the conflict resolution algorithm in `ApplyNormalConsensusData`

Alternatively, add `NextRoundMiningOrderValidationProvider` to the UpdateValue validation pipeline to validate the resulting mining orders.

## Proof of Concept

A proof of concept would demonstrate:
1. A malicious miner producing a block with UpdateValue behavior
2. Crafting `UpdateValueInput` with arbitrary `TuneOrderInformation` (e.g., setting their own order to 1, other miners to higher values)
3. The block passing validation despite manipulated orders
4. The next round being generated with the manipulated mining order
5. The malicious miner mining first in the next round despite not legitimately winning that position through signature-based calculation

The test would verify that `FinalOrderOfNextRound` values in state match the malicious input rather than legitimate cryptographic calculation results.

## Notes

This vulnerability exists because the validation architecture separates UpdateValue validation from NextRound validation, but both behaviors affect the same critical consensus state (`FinalOrderOfNextRound`). The `TuneOrderInformation` mechanism was designed for legitimate conflict resolution but lacks validation to prevent abuse, creating a privilege escalation path for any miner to manipulate consensus scheduling.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
