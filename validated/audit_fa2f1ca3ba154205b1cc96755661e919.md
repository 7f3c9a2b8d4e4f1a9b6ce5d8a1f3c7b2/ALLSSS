# Audit Report

## Title
Unvalidated Negative Order Assignment Enables Mining Schedule Corruption

## Summary
The `ProcessUpdateValue` function in the AEDPoS consensus contract accepts arbitrary `int32` values through `TuneOrderInformation` and directly assigns them to miners' `FinalOrderOfNextRound` without validation. A malicious miner can inject negative order values that corrupt the next round's mining schedule, causing consensus deadlock when `BreakContinuousMining` throws exceptions due to missing expected order positions.

## Finding Description

The vulnerability exists because `ProcessUpdateValue` directly assigns `TuneOrderInformation` values to `FinalOrderOfNextRound` without any bounds checking: [1](#0-0) 

The protobuf schema defines both fields as `int32`, which permits negative values: [2](#0-1) [3](#0-2) 

The validation layer provides no protection. `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` fields, completely ignoring `TuneOrderInformation`: [4](#0-3) 

Access control only verifies the caller is a legitimate miner through `PreCheck`, not the validity of order values: [5](#0-4) 

When `GenerateNextRoundInformation` processes the next round, it directly uses these potentially negative `FinalOrderOfNextRound` values to calculate mining order and expected mining time: [6](#0-5) 

The negative order value is used as a multiplier for calculating `ExpectedMiningTime`, resulting in timestamps in the past. Additionally, `occupiedOrders` can contain negative values while `ableOrders` only generates positive orders (1 to minersCount), creating order gaps: [7](#0-6) 

The `BreakContinuousMining` function expects miners at specific order positions and uses `.First()` which throws `InvalidOperationException` if no element matches: [8](#0-7) [9](#0-8) 

**Attack Scenario:**
1. Malicious miner M1 calls `UpdateValue` with `TuneOrderInformation` mapping multiple miners to negative orders (e.g., M2 → -1, M3 → -2)
2. `ProcessUpdateValue` applies these without validation, storing corrupted `FinalOrderOfNextRound` values
3. When the extra block producer generates the next round using `GenerateNextRoundInformation`:
   - Miners receive negative `Order` values and past-dated `ExpectedMiningTime`
   - The order sequence contains gaps (e.g., [-2, -1, 3, 4, 5] for 5 miners, missing orders 1 and 2)
   - `BreakContinuousMining` attempts to find miners at order 1 using `.First(i => i.Order == 1)`
   - No miner has `Order == 1`, causing `.First()` to throw `InvalidOperationException`
4. The `NextRound` transaction fails, preventing round advancement and stalling consensus

## Impact Explanation

**Consensus Availability Violation:**
This vulnerability breaks the fundamental guarantee that mining rounds progress sequentially. The impacts include:

1. **Mining Schedule Corruption**: Negative orders create past-dated `ExpectedMiningTime` values, breaking the temporal ordering that AEDPoS consensus relies on for time slot validation and LIB calculation
2. **Order Sequence Gaps**: When negative orders displace positive positions, the mining sequence has missing orders in the valid range
3. **Consensus Deadlock**: The `BreakContinuousMining` logic using `.First()` throws exceptions when expected order positions are missing, causing `NextRound` transactions to fail and preventing round transitions
4. **Network-Wide Impact**: All nodes attempting to process the corrupted next round will encounter the same exception, requiring manual intervention to recover

The severity is **MEDIUM** because while it doesn't directly steal funds, it can completely halt block production and require emergency governance intervention to recover consensus.

## Likelihood Explanation

**Attacker Requirements:**
- Must be a legitimate miner (passes `PreCheck` validation that verifies miner list membership)
- This is achievable through the election process or by compromising existing miner infrastructure

**Attack Complexity:**
- **Low**: Single `UpdateValue` transaction with crafted `TuneOrderInformation` parameter
- No timing windows or race conditions required
- Can target any miner's order values, not just the attacker's own
- Attack manifests during next round generation, making attribution difficult

**Economic Incentives:**
- Minimal cost: Standard transaction fee for `UpdateValue` call
- Potential benefits: Disrupting competitor miners, manipulating block production for strategic advantage
- Low risk of detection since corruption only surfaces in the next round

**Probability Assessment: MEDIUM**
While the attacker must be a miner, this is achievable through:
- Compromised miner node infrastructure
- Malicious operators in mining pools
- Intentional exploitation by elected miners with adversarial incentives

The attack's simplicity and complete lack of validation make it highly executable once miner status is obtained.

## Recommendation

Add validation for `TuneOrderInformation` values in `ProcessUpdateValue` to ensure they fall within the valid range (1 to miner count):

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;

    // Existing logic...

    // Validate TuneOrderInformation before applying
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value > 0 && tuneOrder.Value <= minersCount, 
            $"Invalid order value {tuneOrder.Value}. Must be between 1 and {minersCount}.");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            "Cannot tune order for non-existent miner.");
    }

    // Apply validated tunings
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
        currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

    // Rest of the method...
}
```

Additionally, consider using `FirstOrDefault` instead of `First` in `BreakContinuousMining` with appropriate null checks to make the function more resilient to unexpected states.

## Proof of Concept

```csharp
[Fact]
public async Task NegativeOrderAssignment_CausesConsensusDeadlock()
{
    // Setup: Initialize consensus with 5 miners
    await InitializeConsensusAsync();
    
    // Malicious miner crafts UpdateValue with negative TuneOrderInformation
    var maliciousUpdateValue = new UpdateValueInput
    {
        OutValue = GenerateRandomHash(),
        Signature = GenerateValidSignature(),
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = 
        {
            { "Miner2PubKey", -1 },  // Inject negative order
            { "Miner3PubKey", -2 }   // Inject negative order
        },
        RandomNumber = GenerateRandomBytes()
    };
    
    // Attack: Malicious miner calls UpdateValue
    await MaliciousMiner.UpdateValue.SendAsync(maliciousUpdateValue);
    
    // Verify: FinalOrderOfNextRound contains negative values
    var currentRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(-1, currentRound.RealTimeMinersInformation["Miner2PubKey"].FinalOrderOfNextRound);
    Assert.Equal(-2, currentRound.RealTimeMinersInformation["Miner3PubKey"].FinalOrderOfNextRound);
    
    // Trigger: Extra block producer attempts NextRound
    var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
    {
        await ExtraBlockProducer.NextRound.SendAsync(GenerateNextRoundInput());
    });
    
    // Assert: Consensus is deadlocked - NextRound fails with exception
    Assert.Contains("Sequence contains no matching element", exception.Message);
    
    // Verify: Round number has not advanced - consensus is stuck
    var afterRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    Assert.Equal(currentRound.RoundNumber, afterRound.RoundNumber);
}
```

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

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
    map<string, int32> tune_order_information = 7;
```

**File:** protobuf/aedpos_contract.proto (L290-290)
```text
    int32 final_order_of_next_round = 12;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-56)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-90)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L100-107)
```csharp
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
            lastButOneMinerOfNextRound.Order = minersCount;
            lastMinerOfNextRound.Order = minersCount.Sub(1);
            var tempTimestamp = lastButOneMinerOfNextRound.ExpectedMiningTime;
            lastButOneMinerOfNextRound.ExpectedMiningTime = lastMinerOfNextRound.ExpectedMiningTime;
            lastMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```
