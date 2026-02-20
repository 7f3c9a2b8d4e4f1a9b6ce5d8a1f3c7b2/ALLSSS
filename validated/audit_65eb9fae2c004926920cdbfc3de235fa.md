# Audit Report

## Title
Consensus Halt via Malicious TuneOrderInformation in UpdateValue

## Summary
A malicious miner can inject arbitrary integer values into the `TuneOrderInformation` field of `UpdateValueInput`, corrupting consensus state and causing permanent blockchain halt. The vulnerability exists because no validation checks that `TuneOrderInformation` values are within the valid range of `[1, minersCount]`.

## Finding Description

The AEDPoS consensus contract's `ProcessUpdateValue` method directly assigns values from `updateValueInput.TuneOrderInformation` to miners' `FinalOrderOfNextRound` field without any bounds validation. [1](#0-0) 

The `UpdateValueValidationProvider` validates `OutValue`, `Signature`, and `PreviousInValue` correctness, but performs no validation on `TuneOrderInformation` values. [2](#0-1) 

When `GenerateNextRoundInformation` creates the next round, it uses `FinalOrderOfNextRound` as the `Order` field and calculates `ExpectedMiningTime` based on this order. If a miner has `FinalOrderOfNextRound = int.MaxValue`, their expected mining time becomes far in the future. [3](#0-2) 

All `NextRound` transactions are validated through `TimeSlotValidationProvider`, which calls `CheckRoundTimeSlots()` to verify mining intervals. With corrupted order values exceeding valid bounds, the time interval deviation check fails. [4](#0-3) [5](#0-4) 

The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with positive `FinalOrderOfNextRound` equals those who mined, but does NOT validate the actual values are within the valid range `[1, minersCount]`. [6](#0-5) 

Access control verification in `PreCheck()` only confirms the sender is in the current or previous round's miner list, allowing any miner to call `UpdateValue`. [7](#0-6) 

The legitimate protocol design shows `TuneOrderInformation` should only contain values within `[1, minersCount]` when resolving order conflicts, but this constraint is never enforced. [8](#0-7) [9](#0-8) 

## Impact Explanation

This vulnerability has **CRITICAL** impact causing complete network failure:

1. **Permanent Consensus Halt**: Once state is corrupted with invalid `FinalOrderOfNextRound` values, all miners deterministically generate the same invalid next round. Every `NextRound` transaction fails the `CheckRoundTimeSlots()` validation, preventing any round transition.

2. **Network-Wide Availability Loss**: The blockchain cannot progress beyond the corrupted round. All pending transactions become stuck, and all dependent applications cease functioning.

3. **Recovery Complexity**: The network requires coordinated manual intervention or hard fork to recover, as the corrupted round state cannot be fixed through normal consensus mechanisms.

4. **Ecosystem Impact**: All users, applications, cross-chain operations, and dependent services relying on the blockchain are affected.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **Low Attack Barrier**: Any active miner can execute this attack by running modified node software that crafts malicious `UpdateValueInput` with arbitrary `TuneOrderInformation` values.

2. **Trivial Execution**: The attack requires only a single transaction during the miner's normal time slot with modified `TuneOrderInformation` field.

3. **Zero Detection**: The attack is not detectable until miners attempt the `NextRound` transition, by which point the state is already corrupted.

4. **No Prevention Mechanism**: There is no validation system to prevent or detect this attack before it succeeds.

## Recommendation

Add bounds validation in `ProcessUpdateValue` to ensure all `TuneOrderInformation` values are within the valid range:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate TuneOrderInformation values
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
            $"Invalid FinalOrderOfNextRound value {tuneOrder.Value}. Must be in range [1, {minersCount}].");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            $"Invalid miner pubkey in TuneOrderInformation: {tuneOrder.Key}");
    }
    
    // ... rest of existing logic
}
```

Additionally, add validation in `UpdateValueValidationProvider` to verify `TuneOrderInformation` integrity before state modification.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousTuneOrderInformation_CausesConsensusHalt()
{
    // Setup: Initialize consensus with 5 miners
    var miners = GenerateMiners(5);
    await InitializeConsensus(miners);
    
    // Miner produces legitimate block
    await ProduceNormalBlock(miners[0]);
    
    // Attacker (miner[1]) crafts malicious UpdateValueInput
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateOutValue(),
        Signature = GenerateSignature(),
        SupposedOrderOfNextRound = 2,
        TuneOrderInformation = 
        {
            { miners[2].PublicKey.ToHex(), int.MaxValue } // Inject malicious value
        }
    };
    
    // Attack succeeds - state is corrupted
    await ExecuteConsensusTransaction(nameof(UpdateValue), maliciousInput, miners[1]);
    
    // Verify: All subsequent NextRound attempts fail
    var nextRoundInput = GenerateNextRoundInput();
    var result = await ValidateConsensusBeforeExecution(nextRoundInput);
    
    Assert.False(result.Success);
    Assert.Contains("Time slots are so different", result.Message);
    
    // Verify: Blockchain is permanently halted
    for (int i = 0; i < miners.Count; i++)
    {
        var attemptResult = await TryNextRound(miners[i]);
        Assert.False(attemptResult.Success); // All attempts fail
    }
}
```

## Notes

This vulnerability breaks the fundamental consensus invariant that miner orders must be within `[1, minersCount]`. The missing validation allows any miner to permanently halt the network with a single malicious transaction. Recovery requires manual intervention or a hard fork, making this a critical availability vulnerability affecting the entire blockchain ecosystem.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```
