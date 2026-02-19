# Audit Report

## Title
Missing On-Chain Validation of SupposedOrderOfNextRound Allows Miners to Manipulate Next Round Position

## Summary
The `SupposedOrderOfNextRound` field in `UpdateValueInput` is not validated on-chain against its deterministic calculation formula. Miners can submit arbitrary order values that are accepted without verification, allowing manipulation of their position in the next mining round and breaking the fairness of the AEDPoS consensus ordering mechanism.

## Finding Description

The AEDPoS consensus protocol is designed to deterministically calculate each miner's position in the next round based on their signature hash using the formula `GetAbsModulus(sigNum, minersCount) + 1`. [1](#0-0) 

However, this calculation is only performed off-chain during block generation [2](#0-1)  and is never validated on-chain.

**Root Cause:**

When miners submit consensus data via `UpdateValue`, the `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are present, and that `PreviousInValue` is correct. [3](#0-2)  It does not recalculate or verify `SupposedOrderOfNextRound` against the signature.

**Why Protections Fail:**

1. **Direct assignment without validation**: The `ProcessUpdateValue` method directly assigns the provided `SupposedOrderOfNextRound` value to state without any verification: [4](#0-3) 

2. **Circular validation**: The `RecoverFromUpdateValue` method simply copies the order values from the provided round during validation, creating circular logic where the system validates that state matches the header, but both were derived from the same unvalidated input: [5](#0-4) 

3. **Inadequate order validation**: The `NextRoundMiningOrderValidationProvider` only validates the COUNT of miners with orders matches those who mined blocks, not the correctness of the actual order values: [6](#0-5) 

4. **Next round uses manipulated values**: The next round mining order is determined using `FinalOrderOfNextRound` values derived from the unvalidated `SupposedOrderOfNextRound`: [7](#0-6) 

## Impact Explanation

This vulnerability directly violates the consensus integrity invariant by allowing miners to arbitrarily choose their position in the next mining round. A malicious miner can:

1. **Always position themselves first (order = 1)** to maximize MEV extraction opportunities
2. **Coordinate with other malicious miners** to arrange favorable consecutive positions
3. **Manipulate transaction ordering** for censorship or front-running
4. **Gain unfair advantages** in block production timing and rewards

The deterministic ordering mechanism, which should derive unpredictability from miners' signatures, becomes meaningless when miners can simply submit any order value they desire. This breaks the fundamental fairness guarantee of the AEDPoS consensus.

While this doesn't directly enable fund theft, it undermines the core security properties of the blockchain by allowing selective transaction ordering and timing advantages. The last miner(s) in each round have maximum control to set the order for the entire next round.

**Impact: HIGH** - Consensus integrity violation with systemic fairness implications.

## Likelihood Explanation

Any active miner can exploit this vulnerability with minimal effort:

**Attack Steps:**
1. Run standard miner infrastructure (already possessed)
2. Modify off-chain consensus data generation to set `SupposedOrderOfNextRound` to desired value (e.g., always 1)
3. Generate valid signature for the block (normal mining operation)
4. Submit `UpdateValue` transaction with manipulated order value
5. Validation passes because it only checks signature/OutValue, not order calculation

**Feasibility:**
- No special privileges required beyond being an active miner
- Simple code modification in off-chain data generation
- No detection mechanism exists to identify manipulation
- Later miners in a round can override earlier submissions via `TuneOrderInformation` [8](#0-7) 

**Economic Rationality:**
- Attack cost: Negligible (standard block production cost)
- Benefits: MEV extraction, censorship power, competitive advantages
- Risk: None (no on-chain detection or penalty mechanism)

**Likelihood: HIGH** - Trivial to execute for any miner with clear economic incentives.

## Recommendation

Add on-chain validation in `UpdateValueValidationProvider` to recalculate and verify `SupposedOrderOfNextRound`:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Then add this check to `ValidateHeaderInformation` method in `UpdateValueValidationProvider`:

```csharp
if (!ValidateSupposedOrderOfNextRound(validationContext))
    return new ValidationResult { Message = "Incorrect SupposedOrderOfNextRound calculation." };
```

This ensures the on-chain validation matches the deterministic formula that should govern mining order assignment.

## Proof of Concept

A proof of concept would involve:

1. Setting up an AElf testnet with multiple miners
2. Modifying one miner's consensus data generation to always set `SupposedOrderOfNextRound = 1`
3. Observing that the manipulated miner consistently gets the first position in subsequent rounds
4. Verifying no validation errors occur despite the incorrect order value

The test would demonstrate that `UpdateValue` accepts arbitrary `SupposedOrderOfNextRound` values and uses them to determine next round mining order, without ever validating the value matches the signature-based calculation defined in `ApplyNormalConsensusData`.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
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
