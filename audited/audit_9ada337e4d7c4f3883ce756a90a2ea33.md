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
- Create duplicate order values (e.g., multiple miners with order 1), causing the next round generation logic to produce invalid mining schedules or fail
- Set invalid orders (e.g., orders > miner count), potentially causing DoS when `GenerateNextRoundInformation` calculates available orders for miners who didn't produce blocks

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
3. Submit the transaction via the public `UpdateValue` method

No cryptographic challenges, complex state manipulation, or additional privileges are required beyond normal mining operations.

**Economic Rationality**: High probability of exploitation because:
- No additional cost beyond normal mining operations
- Potential benefits include mining first (capturing MEV, extra rewards) or disadvantaging competitors
- Detection is difficult as manipulation occurs within normal UpdateValue transactions

**Execution Practicality**: The attack is directly executable. Any miner can call `UpdateValue` with crafted `TuneOrderInformation` values through the public interface.

## Recommendation

Add validation for `TuneOrderInformation` in the `UpdateValueValidationProvider` or create a dedicated validation provider for UpdateValue behavior:

1. Validate that tuned orders are within valid range [1, minersCount]
2. Validate that tuned orders are unique (no duplicates)
3. Validate that tuned orders only differ from supposed orders when legitimate conflicts exist
4. Consider requiring cryptographic proof or consensus agreement for order tuning

Example validation logic:
```csharp
// In UpdateValueValidationProvider or new TuneOrderValidationProvider
private bool ValidateTuneOrderInformation(ConsensusValidationContext validationContext)
{
    var providedRound = validationContext.ProvidedRound;
    var minersCount = providedRound.RealTimeMinersInformation.Count;
    var tunedOrders = new HashSet<int>();
    
    foreach (var kvp in validationContext.ExtraData.TuneOrderInformation)
    {
        var order = kvp.Value;
        
        // Validate order is in valid range
        if (order < 1 || order > minersCount)
            return false;
            
        // Validate no duplicates
        if (tunedOrders.Contains(order))
            return false;
        tunedOrders.Add(order);
        
        // Validate miner exists
        if (!providedRound.RealTimeMinersInformation.ContainsKey(kvp.Key))
            return false;
    }
    
    return true;
}
```

Additionally, consider whether `TuneOrderInformation` should be removed entirely and order conflicts resolved deterministically by the protocol rather than by miner input.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanManipulateMiningOrder()
{
    // Setup: Initialize consensus with multiple miners
    const int minersCount = 5;
    var initialMiners = GenerateInitialMiners(minersCount);
    await InitializeConsensus(initialMiners);
    
    // Attacker is miner at index 2 (should mine 3rd based on proper calculation)
    var attackerKeyPair = initialMiners[2];
    var attackerPubkey = attackerKeyPair.PublicKey.ToHex();
    
    // Mine first round normally to establish state
    await ProduceNormalBlock(initialMiners[0]);
    
    // Attacker produces block with manipulated TuneOrderInformation
    var currentRound = await GetCurrentRound();
    var maliciousInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("attacker_out"),
        Signature = HashHelper.ComputeFrom("attacker_sig"),
        PreviousInValue = Hash.Empty,
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 3, // Legitimate supposed order
        TuneOrderInformation = 
        {
            // Manipulate: Set attacker's order to 1 (mine first next round)
            { attackerPubkey, 1 },
            // Push legitimate first miner to last position
            { initialMiners[0].PublicKey.ToHex(), 5 }
        },
        RoundId = currentRound.RoundIdForValidation,
        RandomNumber = GenerateRandomNumber()
    };
    
    // Execute attack - should succeed without validation
    var result = await AttackerStub.UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify manipulation took effect
    var updatedRound = await GetCurrentRound();
    updatedRound.RealTimeMinersInformation[attackerPubkey]
        .FinalOrderOfNextRound.ShouldBe(1); // Attacker mines first
    updatedRound.RealTimeMinersInformation[initialMiners[0].PublicKey.ToHex()]
        .FinalOrderOfNextRound.ShouldBe(5); // Legitimate miner pushed back
    
    // Trigger NextRound to see impact
    await ProduceBlocksUntilNextRound(initialMiners);
    
    // Verify next round uses manipulated orders
    var nextRound = await GetCurrentRound();
    var firstMiner = nextRound.RealTimeMinersInformation.Values
        .First(m => m.Order == 1);
    firstMiner.Pubkey.ShouldBe(attackerPubkey); // Attacker mines first!
}
```

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

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```
