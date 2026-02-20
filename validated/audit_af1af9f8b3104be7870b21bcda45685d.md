# Audit Report

## Title
Consensus Halt via Malicious TuneOrderInformation in UpdateValue

## Summary
A malicious miner can inject arbitrary integer values (e.g., `int.MaxValue`) into the `TuneOrderInformation` field of `UpdateValueInput`, corrupting the consensus state. This causes all subsequent `NextRound` transitions to fail validation, permanently halting the blockchain as no miner can progress beyond the corrupted round.

## Finding Description

The vulnerability exists in the AEDPoS consensus contract's update flow where miners submit consensus information during their time slots. The root cause is the absence of bounds validation on the `TuneOrderInformation` field.

**Root Cause:** The `ProcessUpdateValue` method directly assigns arbitrary values from `updateValueInput.TuneOrderInformation` to miners' `FinalOrderOfNextRound` without validating these values are within the valid range of `[1, minersCount]`. [1](#0-0) 

**Missing Validation:** The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` correctness. It performs no validation on `TuneOrderInformation` values. [2](#0-1) 

**Protocol Definition:** The `tune_order_information` field is defined as a map of string to int32 with no constraints on the integer values. [3](#0-2) 

**Attack Propagation:** When `GenerateNextRoundInformation` is called to create the next round, it uses `FinalOrderOfNextRound` as the `Order` field and calculates `ExpectedMiningTime` based on this order. If a miner has `FinalOrderOfNextRound = int.MaxValue`, their expected mining time becomes approximately 272 years in the future. [4](#0-3) 

**Validation Failure:** All `NextRound` transactions are validated through `TimeSlotValidationProvider`, which calls `CheckRoundTimeSlots()` to verify equal time intervals between miners. With corrupted order values, the time interval deviation check fails. [5](#0-4) [6](#0-5) 

**Access Control:** Any miner in the current or previous round can call `UpdateValue`, as verified by `PreCheck()`. [7](#0-6) 

**Insufficient Validation:** The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with positive `FinalOrderOfNextRound` equals those who mined, but does NOT validate the values are within valid range. [8](#0-7) 

## Impact Explanation

This vulnerability has **CRITICAL** impact because it causes complete network failure:

1. **Permanent Consensus Halt**: Once the state is corrupted with invalid `FinalOrderOfNextRound` values, all miners deterministically generate the same invalid next round. Every `NextRound` transaction fails the `CheckRoundTimeSlots()` validation, preventing any round transition.

2. **Network-Wide Availability Loss**: The blockchain cannot progress beyond the corrupted round. All pending transactions become stuck, and all dependent applications cease functioning.

3. **Recovery Complexity**: The network requires coordinated manual intervention or hard fork to recover from this state, as the corrupted round state cannot be fixed through normal consensus mechanisms.

4. **Ecosystem Impact**: All users, applications, cross-chain operations, and dependent services relying on the blockchain are affected. This is more severe than fund theft because it brings down the entire network infrastructure.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **Low Attack Barrier**: Any active miner can execute this attack. There are no special privileges required beyond being in the miner list, which is a role many actors hold in a decentralized network.

2. **Trivial Execution**: The attack requires only a single transaction during the miner's normal time slot with a modified `TuneOrderInformation` field. No complex timing, race conditions, or coordination with other parties is needed.

3. **Zero Detection**: The attack is not detectable until miners attempt the `NextRound` transition, by which point the state is already corrupted and cannot be reversed.

4. **Economic Incentives**: A disgruntled miner, competitor, or attacker who gained miner status could execute this at zero cost (standard transaction fees). The high impact with minimal investment makes this attractive for various malicious actors.

5. **No Prevention Mechanism**: There is no validation or monitoring system to prevent or detect this attack before it succeeds.

## Recommendation

Add bounds validation in `ProcessUpdateValue` to ensure all `TuneOrderInformation` values are within the valid range `[1, minersCount]`:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate TuneOrderInformation values before applying
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
            $"Invalid tune order value {tuneOrder.Value}. Must be in range [1, {minersCount}].");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            "Invalid miner public key in tune order information.");
    }
    
    // ... rest of the method
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
        currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
    // ...
}
```

Alternatively, add validation in `UpdateValueValidationProvider`:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    if (!NewConsensusInformationFilled(validationContext))
        return new ValidationResult { Message = "Incorrect new Out Value." };

    if (!ValidatePreviousInValue(validationContext))
        return new ValidationResult { Message = "Incorrect previous in value." };
    
    // Validate TuneOrderInformation
    if (!ValidateTuneOrderInformation(validationContext))
        return new ValidationResult { Message = "Invalid tune order information values." };

    return new ValidationResult { Success = true };
}

private bool ValidateTuneOrderInformation(ConsensusValidationContext validationContext)
{
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    var tuneOrders = validationContext.ExtraData.TuneOrderInformation;
    
    foreach (var order in tuneOrders.Values)
    {
        if (order < 1 || order > minersCount)
            return false;
    }
    return true;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousTuneOrderInformation_CausesConsensusHalt()
{
    // Setup: Initialize consensus with multiple miners
    var miners = GenerateMiners(5);
    await InitializeConsensusAsync(miners);
    
    // Malicious miner injects int.MaxValue into TuneOrderInformation
    var maliciousMiner = miners[0];
    var updateValueInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = GenerateSignature(),
        RoundId = 1,
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = 
        {
            { maliciousMiner.PublicKey.ToHex(), int.MaxValue } // Malicious value
        },
        RandomNumber = GenerateRandomNumber()
    };
    
    // Attack: Malicious miner calls UpdateValue
    var result = await maliciousMiner.UpdateValueAsync(updateValueInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Impact: All subsequent NextRound calls fail validation
    var nextRoundInput = GenerateNextRoundInput();
    foreach (var miner in miners)
    {
        var nextRoundResult = await miner.NextRoundAsync(nextRoundInput);
        // CheckRoundTimeSlots fails due to corrupted ExpectedMiningTime
        nextRoundResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        nextRoundResult.TransactionResult.Error.ShouldContain("Time slots are so different");
    }
    
    // Consensus is permanently halted - no miner can progress
}
```

## Notes

This vulnerability represents a fundamental flaw in the consensus state validation where user-controlled input (`TuneOrderInformation`) is trusted without bounds checking. The attack is deterministic and irreversible through normal protocol mechanisms, requiring emergency intervention such as a coordinated hard fork to restore network operations. The severity is amplified by the fact that miners are trusted roles in the network, yet a single malicious miner can bring down the entire blockchain with minimal effort.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
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

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
    map<string, int32> tune_order_information = 7;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-20)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
```
