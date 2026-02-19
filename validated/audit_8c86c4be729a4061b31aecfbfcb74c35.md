# Audit Report

## Title
Time Slot Validation Gap Allows Non-Uniform Interval Manipulation in AEDPoS Consensus

## Summary
The `CheckRoundTimeSlots()` validation method allows intervals up to 2x the base mining interval to pass validation, while `GetMiningInterval()` assumes uniformity by only examining the first two miners. A malicious extra block producer can exploit this inconsistency by submitting custom `NextRoundInput` with non-uniform intervals that pass validation but break consensus timing fairness guarantees.

## Finding Description

The AEDPoS consensus protocol contains a critical inconsistency between interval validation and interval usage:

**Root Cause:**

`GetMiningInterval()` determines the mining interval by examining only miners with Order 1 and Order 2: [1](#0-0) 

However, `CheckRoundTimeSlots()` validates consecutive intervals with a tolerance allowing up to 2x variation: [2](#0-1) 

The validation condition `Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval` allows any interval in the range [0, 2*baseMiningInterval] to pass.

**Validation Gap:**

When processing `NextRound` behavior, the `TimeSlotValidationProvider` only invokes `CheckRoundTimeSlots()`: [3](#0-2) 

The validation providers for NextRound behavior do not enforce uniform intervals: [4](#0-3) 

Critically, there is no validation that the submitted Round matches what `GenerateNextRoundInformation()` would produce with uniform intervals.

**Attack Execution:**

The extra block producer can craft malicious consensus extra data. The normal flow generates uniform intervals: [5](#0-4) 

However, since `GetConsensusExtraData` is an off-chain view call, miners can modify the returned data before including it in their block header. The modified Round is then converted directly without regeneration: [6](#0-5) [7](#0-6) 

**Impact Mechanism:**

Multiple consensus methods rely on `GetMiningInterval()` assuming uniform distribution:

1. **Extra block timing calculation**: [8](#0-7) 

2. **Time slot validation for mining permission**: [9](#0-8) 

When intervals are non-uniform but `GetMiningInterval()` returns only the first interval, time slot calculations become inconsistent with actual `ExpectedMiningTime` allocations.

## Impact Explanation

**Severity: Medium**

This vulnerability breaks the fundamental AEDPoS consensus guarantee that all miners receive equal time slots:

1. **Consensus Timing Fairness Violation**: The protocol design assumes uniform interval distribution. Non-uniform intervals with consistent use of `GetMiningInterval()` creates unfair time slot allocations where some miners have more mining time than others.

2. **Extra Block Time Miscalculation**: The extra block producer's mining window is calculated using `GetMiningInterval()` which may not reflect the actual last miner's interval, leading to incorrect timing boundaries.

3. **Time Slot Window Inconsistencies**: The `IsCurrentMiner()` check uses `GetMiningInterval()` uniformly for all miners, but with non-uniform `ExpectedMiningTime` allocations, this creates incorrect time slot boundaries.

While this doesn't directly enable double-spending or fund theft, it undermines the fairness and predictability of consensus timing, which is critical for blockchain operation and miner equality.

## Likelihood Explanation

**Likelihood: Medium**

The attack is feasible with moderate constraints:

**Attacker Prerequisites:**
- Must be in the active miner list (verified by `PreCheck()`): [10](#0-9) 

- Must be selected as extra block producer for the round (determined by signature-based rotation, happens regularly but not controllably)

**Attack Complexity: Low**
1. Wait for selection as extra block producer
2. Call `GetConsensusExtraData` off-chain to obtain normal Round data
3. Modify the Round to have non-uniform intervals (e.g., 4000ms, 8000ms, 8000ms)
4. Ensure `|interval - baseMiningInterval| ≤ baseMiningInterval` for all consecutive pairs
5. Include modified consensus extra data in block header
6. Submit block with malicious Round

**Detection: Medium**
Non-uniform intervals are visible in on-chain data but may not trigger alerts if they fall within the 2x tolerance range that validation permits.

## Recommendation

Implement strict uniformity validation for NextRound intervals:

```csharp
public ValidationResult CheckRoundTimeSlotsStrict()
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

    var baseMiningInterval =
        (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

    if (baseMiningInterval <= 0)
        return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

    // Enforce strict uniformity - all intervals must equal base interval
    for (var i = 1; i < miners.Count - 1; i++)
    {
        var miningInterval =
            (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
        if (miningInterval != baseMiningInterval)
            return new ValidationResult { Message = "Time slots must be uniformly distributed." };
    }

    return new ValidationResult { Success = true };
}
```

Update `TimeSlotValidationProvider` to use the strict validation for NextRound behavior, or alternatively, validate that the provided Round hash matches what `GenerateNextRoundInformation` would produce given the current round state.

## Proof of Concept

```csharp
[Fact]
public async Task NonUniformIntervals_PassValidation_Test()
{
    // Setup: Create a round with 3 miners
    var currentRound = new Round
    {
        RoundNumber = 1,
        TermNumber = 1,
        RealTimeMinersInformation =
        {
            ["miner1"] = new MinerInRound { Order = 1, ExpectedMiningTime = TimestampHelper.GetUtcNow() },
            ["miner2"] = new MinerInRound { Order = 2, ExpectedMiningTime = TimestampHelper.GetUtcNow().AddMilliseconds(4000) },
            ["miner3"] = new MinerInRound { Order = 3, ExpectedMiningTime = TimestampHelper.GetUtcNow().AddMilliseconds(12000) }
        }
    };

    // Intervals: 4000ms (Order 1->2), 8000ms (Order 2->3)
    // GetMiningInterval returns: 4000ms
    var miningInterval = currentRound.GetMiningInterval();
    miningInterval.ShouldBe(4000);

    // CheckRoundTimeSlots should validate: |8000 - 4000| = 4000 <= 4000 (PASSES!)
    var validationResult = currentRound.CheckRoundTimeSlots();
    validationResult.Success.ShouldBeTrue(); // This PASSES despite non-uniform intervals

    // GetExtraBlockMiningTime uses the incorrect 4000ms interval
    var extraBlockTime = currentRound.GetExtraBlockMiningTime();
    var expectedUniformExtraBlockTime = TimestampHelper.GetUtcNow().AddMilliseconds(16000); // If intervals were uniform 4000ms each
    var actualExtraBlockTime = TimestampHelper.GetUtcNow().AddMilliseconds(12000 + 4000); // Last miner + GetMiningInterval()
    
    // This creates timing inconsistencies in consensus
    extraBlockTime.ShouldBe(actualExtraBlockTime);
    extraBlockTime.ShouldNotBe(expectedUniformExtraBlockTime);
}
```

**Notes:**

The vulnerability stems from a design inconsistency where validation permits flexibility (2x tolerance) that the interval calculation logic doesn't account for (assumes uniformity). This breaks the consensus protocol's fundamental assumption that all miners receive equal time allocations, undermining fairness and predictability in block production timing.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L117-122)
```csharp
    public Timestamp GetExtraBlockMiningTime()
    {
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
            .ExpectedMiningTime
            .AddMilliseconds(GetMiningInterval());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L13-18)
```csharp
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-177)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-112)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L157-167)
```csharp
        var miningInterval = currentRound.GetMiningInterval();
        var minerInRound = currentRound.RealTimeMinersInformation[pubkey];
        var timeSlotStartTime = minerInRound.ExpectedMiningTime;

        // Check normal time slot.
        if (timeSlotStartTime <= Context.CurrentBlockTime && Context.CurrentBlockTime <=
            timeSlotStartTime.AddMilliseconds(miningInterval))
        {
            Context.LogDebug(() => "[CURRENT MINER]NORMAL");
            return true;
        }
```
