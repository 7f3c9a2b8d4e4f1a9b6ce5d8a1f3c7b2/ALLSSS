# Audit Report

## Title
Duplicate Mining Order Validation Bypass Allows Consensus Disruption Through Time Slot Collisions

## Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` method incorrectly validates uniqueness of `FinalOrderOfNextRound` values by calling `Distinct()` on `MinerInRound` objects rather than on the order values themselves. [1](#0-0)  This allows a malicious miner to assign duplicate `FinalOrderOfNextRound` values to multiple miners, causing them to be scheduled for the same time slot in the next round, breaking the fundamental consensus invariant that each time slot has exactly one designated miner.

## Finding Description

### Core Validation Bug

The validation logic contains a critical flaw in how it checks for distinct mining orders. The code calls `Distinct()` on a collection of `MinerInRound` objects. [1](#0-0)  Since `Distinct()` uses object equality comparison and each `MinerInRound` has a unique `Pubkey` field, [2](#0-1)  all miners are counted as distinct even if they have identical `FinalOrderOfNextRound` values.

The correct validation should be: `.Select(m => m.FinalOrderOfNextRound).Distinct().Count()`

### Attack Vectors

A miner can manipulate `FinalOrderOfNextRound` values through two mechanisms during `UpdateValue` behavior:

**Vector 1:** Direct assignment via `SupposedOrderOfNextRound` in `UpdateValueInput`. [3](#0-2)  When processing the update, the contract directly assigns this value to both `SupposedOrderOfNextRound` and `FinalOrderOfNextRound`. [4](#0-3) 

**Vector 2:** Modification of other miners' values via `TuneOrderInformation`. [5](#0-4)  The contract iterates through the tune order information and directly overwrites other miners' `FinalOrderOfNextRound` values without validation. [6](#0-5) 

The `UpdateValueValidationProvider` does not validate these fields, only checking `OutValue`, `Signature`, and `PreviousInValue`. [7](#0-6) 

### Consequence in Next Round Generation

When `GenerateNextRoundInformation()` transitions to the next round, it directly assigns `FinalOrderOfNextRound` as the miner's `Order` and calculates `ExpectedMiningTime` by multiplying the order by the mining interval. [8](#0-7)  Multiple miners with the same `FinalOrderOfNextRound` receive identical `Order` values and identical `ExpectedMiningTime` values, violating the core consensus invariant that each time slot has exactly one designated miner.

## Impact Explanation

**Consensus Integrity Violation:** This vulnerability directly breaks the fundamental invariant that each time slot has exactly one designated miner. Multiple miners become authorized to produce blocks at the same `ExpectedMiningTime`, creating:

1. **Competing Valid Blocks:** Both miners can produce valid blocks at the same height and timestamp, causing fork conditions
2. **Chain Instability:** The network must resolve which block to accept, potentially requiring manual intervention
3. **Consensus Disruption:** Predictable block production schedule is broken, affecting all applications relying on it
4. **Potential Double-Spend Window:** During fork resolution, transaction finality is compromised

**Severity: HIGH** - Directly compromises consensus protocol integrity without requiring token stake, governance privileges, or cryptographic attacks. The attack breaks a critical safety property of the consensus mechanism.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner (one of the authorized block producers in the current round)
- Must produce a block with `UpdateValue` behavior during their designated time slot
- Can craft malicious `UpdateValueInput` with duplicate order assignments

**Attack Complexity: LOW**
1. Being selected as a miner is part of normal network participation
2. Requires producing a single block with crafted `UpdateValueInput` containing:
   - `SupposedOrderOfNextRound` = X (for attacker)
   - `TuneOrderInformation[victim_pubkey]` = X (for victim)
3. No validation prevents these duplicate values from being processed
4. No economic cost beyond normal mining operations

**Feasibility: HIGH** - The validation bypass is deterministic. The `NextRoundMiningOrderValidationProvider` will count two distinct `MinerInRound` objects (different pubkeys) as valid even though they have the same `FinalOrderOfNextRound` value. Any malicious miner can execute this attack during their mining slot.

## Recommendation

Fix the validation logic in `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` to check for distinct `FinalOrderOfNextRound` values rather than distinct `MinerInRound` objects:

Change line 15-16 from:
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
    .Distinct().Count();
```

To:
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound).Distinct().Count();
```

Additionally, consider adding validation in `ProcessUpdateValue()` to ensure that:
1. The `SupposedOrderOfNextRound` value is within valid range (1 to miner count)
2. The `TuneOrderInformation` does not create duplicate `FinalOrderOfNextRound` values across all miners

## Proof of Concept

A malicious miner can exploit this vulnerability by:

1. During their mining slot, craft an `UpdateValueInput` with:
   - `SupposedOrderOfNextRound` = 5 (for themselves)
   - `TuneOrderInformation["victim_miner_pubkey"]` = 5 (same order)
   
2. Submit this via the `UpdateValue` consensus behavior

3. The validation will pass because:
   - `UpdateValueValidationProvider` doesn't check order values
   - `NextRoundMiningOrderValidationProvider` calls `Distinct()` on objects (which are distinct by pubkey), not on order values
   
4. In the next round generation:
   - Both attacker and victim receive `Order = 5`
   - Both receive identical `ExpectedMiningTime`
   - Both can produce blocks at the same time slot, causing a fork

This creates competing valid blocks at the same height and timestamp, disrupting consensus and compromising transaction finality.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L205-206)
```text
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** protobuf/aedpos_contract.proto (L284-284)
```text
    string pubkey = 9;
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
