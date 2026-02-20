# Audit Report

## Title
Missing Absolute Time Validation in NextRound Allows Consensus Timing Manipulation

## Summary
The `CheckRoundTimeSlots()` validation function only validates relative intervals between consecutive miners but never validates absolute timing against `Context.CurrentBlockTime`. A malicious miner can propose a NextRound with arbitrarily shifted time slots as long as inter-miner intervals remain consistent, allowing consensus timing manipulation.

## Finding Description

The vulnerability exists in the NextRound validation flow where absolute timing is never verified against the current block timestamp.

**Root Cause:**

The `CheckRoundTimeSlots()` method validates only relative intervals between miners. [1](#0-0) 

The validation calculates a `baseMiningInterval` from the first two miners and then checks that all subsequent intervals are within tolerance. However, it never validates:
1. Whether `miners[0].ExpectedMiningTime` (the round start time) is correct relative to `Context.CurrentBlockTime`
2. Whether the absolute `ExpectedMiningTime` values match what `GenerateNextRoundInformation` would produce
3. Whether the total round duration is correct

**Validation Flow:**

When NextRound behavior is detected, the validation adds `TimeSlotValidationProvider` for all behaviors. [2](#0-1) 

The `TimeSlotValidationProvider` calls `CheckRoundTimeSlots()` for new rounds without comparing against `Context.CurrentBlockTime`. [3](#0-2) 

**Expected vs. Actual:**

The normal round generation correctly uses `currentBlockTimestamp` as the base for calculating all `ExpectedMiningTime` values. [4](#0-3) 

The generated round calculates `ExpectedMiningTime` as `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`, establishing the expected absolute timing.

However, when a miner provides a `NextRoundInput`, the validation never compares the provided times against what this generation logic would produce. The provided round is simply converted and stored directly. [5](#0-4) 

## Impact Explanation

**Consensus Integrity Violation:**

A malicious miner can craft a `NextRoundInput` with all `ExpectedMiningTime` values shifted by an arbitrary constant (e.g., +100 seconds). As long as the relative intervals remain consistent, `CheckRoundTimeSlots()` validation passes because it only checks that `Math.Abs(miningInterval - baseMiningInterval) <= baseMiningInterval`.

**Concrete Harms:**
1. **Timing Manipulation**: The attacker can delay round transitions arbitrarily, gaining strategic advantages in block production timing and potentially disrupting the normal consensus flow
2. **Unfair Advantages**: By manipulating the timing within tolerance bounds, specific miners can effectively receive extended or reduced time slots, creating unfair competitive advantages in block production
3. **Protocol Degradation**: The manipulated timing breaks the critical invariant that rounds start predictably based on `Context.CurrentBlockTime`, degrading consensus fairness and potentially allowing coordination attacks

**Severity: Medium** - While this doesn't directly steal funds, it breaks critical consensus timing invariants that ensure fair block production and proper round transitions, affecting all network participants and potentially enabling more sophisticated attacks.

## Likelihood Explanation

**Attacker Capabilities:**
- Any miner in the current or previous round's miner list can call `NextRound`, as verified by the `PreCheck()` method. [6](#0-5) 
- The extra block producer is expected to call NextRound by design, but any miner could potentially do so
- No special privileges required beyond being in the miner list

**Attack Complexity:**
- Low complexity: Attacker constructs `NextRoundInput` with manipulated `ExpectedMiningTime` values
- All inter-miner intervals kept within tolerance (difference < baseMiningInterval)
- Passes all validation providers including `TimeSlotValidationProvider` and `RoundTerminateValidationProvider`

**Feasibility:**
- Attack executes through normal NextRound transaction flow [7](#0-6) 
- No race conditions or timing dependencies required
- Manipulation persists in state after successful execution via `AddRoundInformation(nextRound)`

**Probability: High** - Any malicious miner has both incentive and capability to execute this attack for competitive advantage in block production.

## Recommendation

Add absolute time validation in `CheckRoundTimeSlots()` or in a dedicated validation provider. The validation should verify that the first miner's `ExpectedMiningTime` is correctly based on `Context.CurrentBlockTime`.

**Recommended Fix:**

Add a new validation in `TimeSlotValidationProvider` for NextRound behavior:

```csharp
// In TimeSlotValidationProvider.ValidateHeaderInformation
if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
{
    // Validate absolute timing against current block time
    var firstMiner = validationContext.ProvidedRound.RealTimeMinersInformation.Values
        .OrderBy(m => m.Order).FirstOrDefault();
    
    if (firstMiner != null && firstMiner.ExpectedMiningTime != null)
    {
        var miningInterval = validationContext.ProvidedRound.GetMiningInterval();
        var expectedStartTime = validationContext.ExtraData.BlockTime; // or Context.CurrentBlockTime
        var acceptableRange = miningInterval * 2; // Define acceptable tolerance
        
        var timeDiff = Math.Abs((firstMiner.ExpectedMiningTime - expectedStartTime).Milliseconds());
        if (timeDiff > acceptableRange)
        {
            return new ValidationResult 
            { 
                Message = "NextRound timing does not match current block time" 
            };
        }
    }
    
    // Existing relative interval check
    validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
    if (!validationResult.Success) return validationResult;
}
```

## Proof of Concept

A valid test would demonstrate:
1. Creating a legitimate NextRoundInput based on current round state
2. Shifting all `ExpectedMiningTime` values by a constant offset (e.g., +100 seconds)
3. Verifying that `CheckRoundTimeSlots()` returns Success (only checks relative intervals)
4. Calling NextRound with the manipulated input
5. Confirming the manipulated round is stored in state with incorrect absolute timing

The test would show that despite the absolute timing being completely wrong, the validation passes because no provider checks against `Context.CurrentBlockTime`.

## Notes

This vulnerability demonstrates a gap between the intended consensus timing model (where rounds start at predictable absolute times based on `Context.CurrentBlockTime`) and the actual validation enforcement (which only checks relative intervals). The correct generation logic in `Round_Generation.cs` establishes the expected behavior, but the validation layer fails to enforce it, allowing malicious miners to deviate from this model while still passing all checks.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
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
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L10-35)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        // If provided round is a new round
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
        }
        else
        {
            // Is sender respect his time slot?
            // It is maybe failing due to using too much time producing previous tiny blocks.
            if (!CheckMinerTimeSlot(validationContext))
            {
                validationResult.Message =
                    $"Time slot already passed before execution.{validationContext.SenderPubkey}";
                validationResult.IsReTrigger = true;
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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
        }

        // Set miners' information of miners missed their time slot in current round.
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

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
