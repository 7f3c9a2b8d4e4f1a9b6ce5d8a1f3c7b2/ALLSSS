# Audit Report

## Title
Duplicate Mining Order Injection via Unvalidated TuneOrderInformation Breaks Consensus Schedule Integrity

## Summary
A malicious miner can inject duplicate `FinalOrderOfNextRound` values through unvalidated `TuneOrderInformation` in `UpdateValueInput`, causing multiple miners to receive identical `Order` values in the next round. This violates the critical invariant that each miner must have a unique time slot, disrupting consensus schedule integrity and enabling synchronization conflicts.

## Finding Description

The AEDPoS consensus mechanism maintains a critical invariant: each miner must have a unique `Order` value that determines their exclusive time slot for block production. This vulnerability breaks that invariant through three interconnected flaws:

**Flaw 1: Unvalidated Direct Application of TuneOrderInformation**

The `ProcessUpdateValue` method directly applies miner-provided `TuneOrderInformation` to other miners' `FinalOrderOfNextRound` values without any validation. [1](#0-0) 

A malicious miner can construct an `UpdateValueInput` with arbitrary mappings like `TuneOrderInformation = {"MinerA_Pubkey": 3, "MinerB_Pubkey": 3}`, assigning the same order to multiple miners.

**Flaw 2: Inadequate Validation**

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, completely ignoring the content of `TuneOrderInformation`. [2](#0-1) 

The `PreCheck` method only verifies the sender is in the miner list, not that their input data is honest. [3](#0-2) 

**Flaw 3: Ineffective Duplicate Detection**

When transitioning to the next round, `NextRoundMiningOrderValidationProvider` attempts to detect duplicates but fails because it calls `Distinct()` on `MinerInRound` objects. [4](#0-3) 

Since `MinerInRound` is a protobuf-generated class whose `Equals()` compares all fields (including the unique `Pubkey`), this validation cannot detect miners with duplicate `FinalOrderOfNextRound` values.

The `CheckRoundTimeSlots` validation also fails to catch this issue. [5](#0-4) 

With duplicate orders causing 0 millisecond intervals between miners, the tolerance check `Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval` evaluates to `Math.Abs(0 - 4000) = 4000`, which is NOT greater than 4000, so it passes.

**Propagation to Next Round**

When `GenerateNextRoundInformation` executes, it directly assigns `FinalOrderOfNextRound` to the `Order` field. [6](#0-5) 

The `ExpectedMiningTime` is calculated as `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`, causing miners with duplicate orders to receive identical mining times. [7](#0-6) 

**Contrast with Normal Flow**

In the normal consensus flow, `ApplyNormalConsensusData` includes conflict resolution logic that detects and resolves order conflicts. [8](#0-7) 

However, when a miner directly calls `UpdateValue` with malicious `TuneOrderInformation`, this conflict resolution is completely bypassed.

## Impact Explanation

**Consensus Invariant Violation**: The attack directly violates the fundamental consensus property that each miner must have a unique, non-overlapping time slot. Multiple miners with identical `Order` values will have identical `ExpectedMiningTime` values, creating direct time slot collisions.

**Schedule Corruption**: Duplicate orders cause some order positions to be skipped. For example, if miners A and B both have Order=3, no miner will have Order=4, creating gaps in the schedule. This leads to uneven time slot distributions across the round.

**Synchronization Conflicts**: Miners with duplicate time slots will attempt to produce blocks simultaneously. The consensus mechanism is designed assuming miners produce blocks in sequence, not concurrently. This causes race conditions, potential block production failures, and consensus round instability.

**Network-Wide Impact**: All network participants are affected. Honest miners may miss legitimate time slots due to scheduling conflicts. Block production becomes unreliable, degrading overall network stability and potentially stalling consensus rounds.

## Likelihood Explanation

**Attacker Prerequisites**: The attacker must be an active miner in the current round. This is achievable through the election mechanism - any party can stake tokens and participate in elections to become a miner, making this a semi-privileged but publicly accessible role.

**Attack Simplicity**: The attack requires only constructing an `UpdateValueInput` with malicious `TuneOrderInformation`. No complex timing coordination, state manipulation, or cryptographic bypass is needed. The attacker simply needs to map target miners' public keys to duplicate order values.

**Execution Conditions**: The attack is executable in any consensus round where the attacker is an active miner. Since `UpdateValue` is a public method [9](#0-8)  and the only check is miner list membership, there are no restrictive preconditions.

**Detection Difficulty**: While the malicious `TuneOrderInformation` persists in state and propagates to the next round, detection requires active monitoring of round state transitions and order distributions, which may not be in place.

**High Probability**: Given the low complexity, public accessibility of miner role through elections, and absence of preventive validation, the likelihood of exploitation is high.

## Recommendation

**Immediate Fix**: Add validation to `ProcessUpdateValue` to detect and reject duplicate `FinalOrderOfNextRound` values in `TuneOrderInformation`:

```csharp
// After line 258, before applying TuneOrderInformation
var tunedOrders = updateValueInput.TuneOrderInformation.Values.ToList();
var distinctTunedOrders = tunedOrders.Distinct().ToList();
Assert(tunedOrders.Count == distinctTunedOrders.Count, "Duplicate orders in TuneOrderInformation");

// Also validate no conflicts with existing FinalOrderOfNextRound values
var existingOrders = currentRound.RealTimeMinersInformation.Values
    .Where(m => !updateValueInput.TuneOrderInformation.ContainsKey(m.Pubkey))
    .Select(m => m.FinalOrderOfNextRound)
    .Where(o => o > 0)
    .ToList();
    
foreach (var tunedOrder in tunedOrders)
{
    Assert(!existingOrders.Contains(tunedOrder), 
        $"TuneOrderInformation conflicts with existing order {tunedOrder}");
}
```

**Strengthen NextRoundMiningOrderValidationProvider**: Fix the distinctness check to compare `FinalOrderOfNextRound` values instead of entire objects:

```csharp
var finalOrders = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
    
var distinctCount = finalOrders.Distinct().Count();
if (distinctCount != finalOrders.Count)
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

**Add Validation to UpdateValueValidationProvider**: Extend the provider to validate `TuneOrderInformation` content during pre-execution validation.

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateOrderInjection_ViolatesUniqueTimeSlotInvariant()
{
    // Setup: Initialize consensus with 3 miners
    var initialMiners = new[] { "Miner1", "Miner2", "Miner3" };
    await InitializeConsensusWithMiners(initialMiners);
    
    // Attacker (Miner1) constructs malicious UpdateValueInput
    // Assigns same order (2) to both Miner2 and Miner3
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateValidOutValue(),
        Signature = GenerateValidSignature(),
        PreviousInValue = Hash.Empty,
        ActualMiningTime = Timestamp.FromDateTime(DateTime.UtcNow),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = 
        {
            { GetMinerPubkey("Miner2"), 2 },  // Duplicate order
            { GetMinerPubkey("Miner3"), 2 }   // Duplicate order
        },
        RandomNumber = GenerateValidRandomNumber()
    };
    
    // Execute attack: Miner1 calls UpdateValue with malicious input
    var result = await MinerStub("Miner1").UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Trigger round transition
    await ProduceNextRoundBlocks();
    
    // Verify: Check next round has duplicate orders
    var nextRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    var miner2Info = nextRound.RealTimeMinersInformation[GetMinerPubkey("Miner2")];
    var miner3Info = nextRound.RealTimeMinersInformation[GetMinerPubkey("Miner3")];
    
    // VULNERABILITY: Both miners have identical Order values
    miner2Info.Order.ShouldBe(2);
    miner3Info.Order.ShouldBe(2);
    
    // VULNERABILITY: Both miners have identical ExpectedMiningTime
    miner2Info.ExpectedMiningTime.ShouldBe(miner3Info.ExpectedMiningTime);
    
    // IMPACT: Time slot uniqueness invariant is violated
    // Multiple miners will attempt to produce blocks at the same time
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L49-55)
```csharp
        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-40)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
```
