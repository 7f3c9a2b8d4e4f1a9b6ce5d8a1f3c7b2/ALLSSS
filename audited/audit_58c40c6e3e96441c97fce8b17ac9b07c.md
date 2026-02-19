# Audit Report

## Title
Consensus Denial-of-Service via Unvalidated TuneOrderInformation Leading to GetMiningInterval Crash

## Summary
A malicious miner can inject invalid `FinalOrderOfNextRound` values through the unvalidated `TuneOrderInformation` field in `UpdateValueInput`, creating a corrupted round where no miners have Order 1 or 2. This causes `GetMiningInterval()` to crash with an `IndexOutOfRangeException` when any miner attempts to retrieve consensus commands, permanently halting block production until manual chain intervention.

## Finding Description

The AEDPoS consensus system fails to validate that `TuneOrderInformation` values maintain the critical invariant that miner Order values must form a complete sequence [1, 2, ..., N]. This allows a malicious miner to corrupt round state, breaking the core assumption in `GetMiningInterval()` that Order 1 and 2 always exist.

**Root Cause 1: Unvalidated TuneOrderInformation Application**

In `ProcessUpdateValue`, the `TuneOrderInformation` dictionary is directly applied to miners' `FinalOrderOfNextRound` without any validation: [1](#0-0) 

This allows arbitrary Order values to be set, including mappings like {Miner1→3, Miner2→4, Miner3→5, Miner4→6} that exclude Orders 1 and 2.

**Root Cause 2: GetMiningInterval Assumes Order 1 and 2 Exist**

The `GetMiningInterval()` method filters miners by Order 1 or 2 and unconditionally accesses the second element: [2](#0-1) 

If no miners have Order 1 or 2, `firstTwoMiners` has fewer than 2 elements, and accessing `firstTwoMiners[1]` throws `IndexOutOfRangeException`.

**Root Cause 3: GenerateNextRoundInformation Uses Corrupted Values**

When transitioning to the next round, `FinalOrderOfNextRound` becomes the `Order` field directly: [3](#0-2) 

Invalid `FinalOrderOfNextRound` values propagate to become invalid Order values in the new round state.

**Root Cause 4: Validation Gaps**

The existing validators fail to catch this attack:

**NextRoundMiningOrderValidationProvider** only validates count equality, not actual order values: [4](#0-3) 

This passes as long as the number of distinct `FinalOrderOfNextRound > 0` equals miners who produced blocks, regardless of whether those orders are [1,2,3,4] or [3,4,5,6].

**CheckRoundTimeSlots** only validates time intervals, not order sequence: [5](#0-4) 

It sorts miners by Order but never verifies that Order values are sequential starting from 1.

**UpdateValueValidationProvider** doesn't validate `TuneOrderInformation` at all: [6](#0-5) 

**Attack Execution Path:**

1. Malicious miner produces UpdateValue block with crafted `TuneOrderInformation = {Miner1→3, Miner2→4, Miner3→5, Miner4→6}`
2. `ProcessUpdateValue` applies these values without validation
3. Current round state corrupted with invalid `FinalOrderOfNextRound` values
4. Next miner transitions to NextRound
5. `GenerateNextRoundInformation` creates round with Order values [3,4,5,6]
6. New round passes `CheckRoundTimeSlots` (time intervals still valid) and `NextRoundMiningOrderValidationProvider` (count matches)
7. Corrupted round stored in state
8. Any miner calls `GetConsensusCommand` to produce next block
9. `CommandStrategyBase` constructor stores the corrupted round: [7](#0-6) 

10. Accessing `MiningInterval` property triggers `GetMiningInterval()`
11. Exception thrown - no miners have Order 1 or 2
12. All miners unable to produce blocks - consensus halted

## Impact Explanation

**Severity: HIGH** - Complete Consensus Denial-of-Service

This vulnerability causes catastrophic operational failure:

- **Total Block Production Halt**: All miners crash when attempting to retrieve consensus commands, stopping block production entirely
- **Network-Wide Impact**: Affects every node in the network, not isolated to individual miners
- **Persistent Failure**: Corrupted round remains in state; automatic recovery is impossible
- **Manual Intervention Required**: Chain operators must manually fork or patch the consensus contract to restore functionality
- **State Integrity Violation**: Breaks the fundamental consensus invariant that miner Order values must be [1, N]

While no funds are directly stolen, this represents a complete breakdown of the blockchain's operational integrity - the most severe availability impact possible in a consensus system.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** - Single Malicious Miner Can Execute

The attack has low barriers to execution:

**Attacker Requirements:**
- Must be an authorized miner in current round (passes PreCheck): [8](#0-7) 

- Can produce valid blocks with consensus transactions

**Attack Simplicity:**
- Single `UpdateValue` transaction with malicious `TuneOrderInformation` field
- No complex timing requirements or race conditions
- Deterministic and immediately effective
- No economic cost beyond normal block production

**Realistic Scenarios:**
- Compromised miner node
- Malicious election winner
- Insider threat from mining pool operator

**Detection Difficulty:**
- Malicious `TuneOrderInformation` appears legitimate until next round activates
- No warning or alert mechanisms before consensus breaks
- Root cause analysis requires deep inspection of round state

Given that miners rotate regularly through election and any single miner can execute this attack with one transaction, the probability is substantial in adversarial scenarios.

## Recommendation

Add validation in `ProcessUpdateValue` to ensure `TuneOrderInformation` values maintain valid Order range:

```csharp
// In ProcessUpdateValue, replace lines 259-260 with:
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Validate order is in valid range [1, minersCount]
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
        $"Invalid FinalOrderOfNextRound: {tuneOrder.Value}. Must be in range [1, {minersCount}]");
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}

// Additionally, validate all miners who mined have distinct orders in [1, N]
var finalOrders = currentRound.RealTimeMinersInformation.Values
    .Where(m => m.OutValue != null)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
    
Assert(finalOrders.Distinct().Count() == finalOrders.Count, 
    "FinalOrderOfNextRound values must be distinct");
Assert(finalOrders.All(o => o >= 1 && o <= minersCount),
    "All FinalOrderOfNextRound values must be in valid range");
```

Additionally, add defensive check in `GetMiningInterval()`:

```csharp
// In GetMiningInterval, replace lines 76-80 with:
var firstTwoMiners = RealTimeMinersInformation.Values
    .Where(m => m.Order == 1 || m.Order == 2)
    .OrderBy(m => m.Order)
    .ToList();
    
Assert(firstTwoMiners.Count >= 2, 
    $"Round must contain miners with Order 1 and 2. Found {firstTwoMiners.Count} miners.");

return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
    .Milliseconds());
```

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusDoS_InvalidTuneOrderInformation_CrashesGetMiningInterval()
{
    // Setup: Initialize consensus with 4 miners
    var miners = new[] { "Miner1", "Miner2", "Miner3", "Miner4" };
    await InitializeConsensusAsync(miners);
    
    // Miner1 produces malicious UpdateValue with invalid TuneOrderInformation
    // Maps all miners to orders [3,4,5,6], excluding orders 1 and 2
    var maliciousUpdate = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = HashHelper.ComputeFrom("sig"),
        SupposedOrderOfNextRound = 3,
        TuneOrderInformation = {
            { "Miner1", 3 },
            { "Miner2", 4 },
            { "Miner3", 5 },
            { "Miner4", 6 }
        },
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        RandomNumber = ByteString.CopyFrom(new byte[32])
    };
    
    // Execute malicious UpdateValue - should succeed with current code
    var result = await ExecuteUpdateValueAsync(maliciousUpdate, "Miner1");
    result.Status.ShouldBe(TransactionResultStatus.Mined); // Passes validation
    
    // Transition to next round - corrupted round created
    await TransitionToNextRoundAsync();
    
    // Any miner attempting to get consensus command will crash
    var exception = await Assert.ThrowsAsync<IndexOutOfRangeException>(async () => 
    {
        await GetConsensusCommandAsync("Miner2");
    });
    
    // Verify crash occurs in GetMiningInterval accessing firstTwoMiners[1]
    exception.Message.ShouldContain("Index was outside the bounds of the array");
    
    // Consensus is now permanently broken - no miner can produce blocks
    foreach (var miner in miners)
    {
        await Assert.ThrowsAsync<IndexOutOfRangeException>(async () => 
        {
            await GetConsensusCommandAsync(miner);
        });
    }
}
```

## Notes

This vulnerability demonstrates a critical gap in consensus state validation where client-provided order information is trusted without verification against protocol invariants. The legitimate purpose of `TuneOrderInformation` is to resolve order conflicts calculated via `ApplyNormalConsensusData`, which always produces values in range [1, N]. However, the protocol never validates that submitted `TuneOrderInformation` maintains this constraint, allowing malicious miners to inject arbitrary order values that violate assumptions throughout the consensus command generation logic.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L35-57)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L28-37)
```csharp
        protected CommandStrategyBase(Round currentRound, string pubkey, Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;
            Pubkey = pubkey;
            CurrentBlockTime = currentBlockTime;
        }

        protected MinerInRound MinerInRound => CurrentRound.RealTimeMinersInformation[Pubkey];
        protected int Order => CurrentRound.GetMiningOrder(Pubkey);
        protected int MiningInterval => CurrentRound.GetMiningInterval();
```
