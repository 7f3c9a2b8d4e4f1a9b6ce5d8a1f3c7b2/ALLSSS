# Audit Report

## Title
NextRound Validation Bypass via RoundId Collision Allows Invalid Time Slot Distribution

## Summary
A malicious block producer can bypass critical time slot validation (`CheckRoundTimeSlots`) when transitioning to a new consensus round by crafting a `ProvidedRound` with the same `RoundId` as `BaseRound`. This allows introduction of a round with invalid time slot distribution (unequal intervals, zero/negative spacing) into consensus state, compromising temporal fairness guarantees of the AEDPoS consensus mechanism.

## Finding Description

The vulnerability exists in the interaction between `TimeSlotValidationProvider` and the `RoundId` calculation mechanism during NextRound transitions.

**Root Cause:**

The `RoundId` property is calculated as the sum of all miners' `ExpectedMiningTime.Seconds` values: [1](#0-0) 

When validating NextRound behavior, `TimeSlotValidationProvider` uses `RoundId` equality to determine validation path: [2](#0-1) 

If `ProvidedRound.RoundId == BaseRound.RoundId`, the critical `CheckRoundTimeSlots()` validation is skipped (line 14 condition fails, jumps to line 20).

**Why Existing Validators Fail:**

For NextRound behavior, these validation providers are registered: [3](#0-2) 

None explicitly enforce that `ProvidedRound.RoundId` must differ from `BaseRound.RoundId`:

1. `RoundTerminateValidationProvider` only validates `RoundNumber` increment and InValues nullity: [4](#0-3) 

2. `NextRoundMiningOrderValidationProvider` only checks `FinalOrderOfNextRound` consistency: [5](#0-4) 

The bypassed `CheckRoundTimeSlots()` method enforces critical temporal invariants: [6](#0-5) 

**Execution Path:**

1. Malicious miner crafts `ProvidedRound` with `RoundNumber = BaseRound.RoundNumber + 1` but `RoundId = BaseRound.RoundId`
2. Achieves RoundId collision by selecting `ExpectedMiningTime` values that sum to target (e.g., for 5 miners with BaseRound.RoundId=15000: [100, 200, 300, 14200, 200] instead of legitimate sequential [1000, 2000, 3000, 4000, 5000])
3. Submits block with NextRound behavior triggering validation: [7](#0-6) 

4. `TimeSlotValidationProvider` sees matching RoundId, executes only `CheckMinerTimeSlot()` against BaseRound (lines 20-31), skipping `CheckRoundTimeSlots()` 
5. Other validators pass (RoundNumber increments correctly, sender is miner)
6. Malicious round accepted and stored in state: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Compromise:**

Once the malicious round is accepted into `State.Rounds`, it becomes the authoritative `BaseRound` for subsequent block validation and mining schedule determination. The invalid time slot distribution enables:

1. **Unfair Mining Windows**: Attacker can allocate disproportionate time slots (e.g., give themselves 90% of round time, compress others into remaining 10%), violating the equal opportunity principle of AEDPoS
2. **Temporal Ordering Violation**: Setting intervals to zero or near-zero breaks the temporal spacing guarantee that prevents block production conflicts and ensures deterministic ordering
3. **Persistent State Corruption**: The malicious round remains in state affecting all consensus operations (GetMiningInterval, IsTimeSlotPassed, etc.) until the next legitimate NextRound overwrites it

**Affected Parties:**
- All miners in the compromised round face distorted time slot allocations
- Network consensus fairness is undermined as block production schedule becomes manipulable
- Subsequent blocks may be incorrectly validated due to corrupted BaseRound reference

**Severity: Medium** - Requires privileged BP position but straightforward exploitation. Impact is limited to one round's duration (temporary), does not directly enable fund theft, but compromises consensus fairness which is a core protocol invariant.

## Likelihood Explanation

**Attacker Requirements:**
- Active block producer with mining permission (achievable in DPoS/PoS via stake or election)
- Ability to produce a NextRound block (any miner can when appropriate timing conditions met, not limited to extra block producer)
- Custom consensus client to craft malicious round data instead of using legitimate `GenerateNextRoundInformation`: [9](#0-8) 

**Attack Complexity:**
- **Moderate** - Requires understanding RoundId calculation and validation flow
- Mathematical constraint satisfaction is straightforward: attacker solves for ExpectedMiningTime values summing to target RoundId (infinite solutions exist for N miners with sum S)
- Example: BaseRound.RoundId=5040 (5 miners) → Malicious times [800, 1060, 1060, 1060, 1060] have wildly unequal spacing but sum to 5040

**Feasibility:**
- No cryptographic or economic barriers beyond being an elected/staked BP
- Validation logic is deterministic and bypassable as demonstrated
- Periodic opportunity at every round transition when miner's turn arrives

**Detection Difficulty:**
- Malicious round appears structurally valid (correct RoundNumber, proper fields populated)
- Other validators pass all checks, masking the manipulation
- Time slot inequality only becomes apparent in subsequent mining operations

**Probability: Medium-High** - Straightforward exploitation for any active BP with custom client, periodic opportunity window, no runtime detection mechanisms exist for this specific bypass.

## Recommendation

Add explicit RoundId validation for NextRound behavior in `RoundTerminateValidationProvider`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // NEW: Enforce RoundId must differ for NextRound
    if (extraData.Round.RoundId == validationContext.BaseRound.RoundId)
        return new ValidationResult { Message = "NextRound must have different RoundId than BaseRound." };
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

Alternatively, modify `TimeSlotValidationProvider` to always call `CheckRoundTimeSlots()` for NextRound behavior regardless of RoundId equality, or add separate validation logic for NextRound behavior that enforces RoundId difference.

## Proof of Concept

```csharp
// Test demonstrates RoundId collision bypass
// Assumes test environment with 5 miners, BaseRound at RoundNumber=10, RoundId=15000

[Fact]
public async Task NextRound_RoundIdCollision_BypassesTimeSlotValidation()
{
    // Setup: Current round with fair time slots
    var baseRound = new Round
    {
        RoundNumber = 10,
        RealTimeMinersInformation = 
        {
            ["miner1"] = new MinerInRound { Order = 1, ExpectedMiningTime = Timestamp.FromSeconds(1000) },
            ["miner2"] = new MinerInRound { Order = 2, ExpectedMiningTime = Timestamp.FromSeconds(2000) },
            ["miner3"] = new MinerInRound { Order = 3, ExpectedMiningTime = Timestamp.FromSeconds(3000) },
            ["miner4"] = new MinerInRound { Order = 4, ExpectedMiningTime = Timestamp.FromSeconds(4000) },
            ["miner5"] = new MinerInRound { Order = 5, ExpectedMiningTime = Timestamp.FromSeconds(5000) }
        }
    };
    // BaseRound.RoundId = 1000+2000+3000+4000+5000 = 15000
    
    // Attack: Craft malicious round with same RoundId but unfair distribution
    var maliciousRound = new Round
    {
        RoundNumber = 11, // Correct increment
        RealTimeMinersInformation = 
        {
            ["miner1"] = new MinerInRound { Order = 1, ExpectedMiningTime = Timestamp.FromSeconds(100), FinalOrderOfNextRound = 1 },
            ["miner2"] = new MinerInRound { Order = 2, ExpectedMiningTime = Timestamp.FromSeconds(200), FinalOrderOfNextRound = 2 },
            ["miner3"] = new MinerInRound { Order = 3, ExpectedMiningTime = Timestamp.FromSeconds(300), FinalOrderOfNextRound = 3 },
            ["miner4"] = new MinerInRound { Order = 4, ExpectedMiningTime = Timestamp.FromSeconds(14200), FinalOrderOfNextRound = 4, OutValue = Hash.Empty }, // Unfair advantage
            ["miner5"] = new MinerInRound { Order = 5, ExpectedMiningTime = Timestamp.FromSeconds(200), FinalOrderOfNextRound = 5, OutValue = Hash.Empty }
        }
    };
    // MaliciousRound.RoundId = 100+200+300+14200+200 = 15000 (SAME AS BASE!)
    
    // Submit NextRound with malicious data
    var result = await ConsensusContract.NextRound.SendAsync(NextRoundInput.Create(maliciousRound, randomNumber));
    
    // Verify: Transaction succeeds (validation bypassed)
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Malicious round is stored
    var storedRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    storedRound.RoundNumber.ShouldBe(11);
    storedRound.RoundId.ShouldBe(15000); // Same as before!
    
    // Verify: Unfair time distribution persists
    var miner4Slot = (storedRound.RealTimeMinersInformation["miner4"].ExpectedMiningTime.Seconds - 
                      storedRound.RealTimeMinersInformation["miner3"].ExpectedMiningTime.Seconds);
    miner4Slot.ShouldBe(13900); // Massive advantage vs fair 1000ms
    
    // CheckRoundTimeSlots would have rejected this:
    var validationResult = maliciousRound.CheckRoundTimeSlots();
    validationResult.Success.ShouldBe(false); // Proves bypass occurred
}
```

## Notes

The core vulnerability is confirmed through code analysis. The claim's assertion about "extra block producer" requirement is slightly inaccurate - any active miner can trigger NextRound when timing conditions permit, per `MiningPermissionValidationProvider` which only checks miner list membership. This actually increases likelihood slightly. The mathematical feasibility of RoundId collision is straightforward (constraint satisfaction problem with many solutions). The security impact is real but time-bounded to one round's duration, justifying Medium severity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L15-24)
```csharp
    public long RoundId
    {
        get
        {
            if (RealTimeMinersInformation.Values.All(bpInfo => bpInfo.ExpectedMiningTime != null))
                return RealTimeMinersInformation.Values.Select(bpInfo => bpInfo.ExpectedMiningTime.Seconds).Sum();

            return RoundIdForValidation;
        }
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-104)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };

        // Skip the certain initial miner during first several rounds. (When other nodes haven't produce blocks yet.)
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
        }

        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };

        /* Ask several questions: */

        // Add basic providers at first.
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

        var service = new HeaderInformationValidationService(validationProviders);

        Context.LogDebug(() => $"Validating behaviour: {extraData.Behaviour.ToString()}");

        var validationResult = service.ValidateInformation(validationContext);

        if (validationResult.Success == false)
            Context.LogDebug(() => $"Consensus Validation before execution failed : {validationResult.Message}");

        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
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
