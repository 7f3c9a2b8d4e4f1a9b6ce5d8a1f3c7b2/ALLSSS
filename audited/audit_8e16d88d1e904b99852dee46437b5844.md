### Title
Time Slot Validation Gap Allows Extra Block Producer to Mine Earlier via Non-Uniform Interval Manipulation

### Summary
The `GetMiningInterval()` method only examines the first two miners to determine the mining interval, while `CheckRoundTimeSlots()` validates consecutive intervals with a tolerance allowing up to 2x variation. A malicious extra block producer can craft a round with non-uniform intervals that passes validation but causes the extra block mining time to be calculated incorrectly, allowing them to mine earlier than intended and breaking consensus timing fairness.

### Finding Description

The vulnerability exists in the interaction between two methods in the `Round` class: [1](#0-0) [2](#0-1) 

**Root Cause:**
`GetMiningInterval()` returns the absolute time difference between miners with Order 1 and Order 2 only. However, `CheckRoundTimeSlots()` validates that ALL consecutive intervals are within tolerance: `|interval - baseMiningInterval| <= baseMiningInterval`. This allows intervals ranging from 0 to 2x the base interval to pass validation.

**Why Protections Fail:**
When a miner submits a `NextRound` transaction, the provided round is validated through `TimeSlotValidationProvider`: [3](#0-2) 

The validation only checks that intervals fit the 2x tolerance rule but does not enforce uniform spacing. There is no additional validation preventing non-uniform intervals in: [4](#0-3) [5](#0-4) 

**Execution Path:**
A malicious extra block producer can craft a custom `NextRoundInput` with non-uniform intervals and submit it directly: [6](#0-5) 

### Impact Explanation

**Consensus Timing Integrity Violation:**

1. **Extra Block Mining Time Miscalculation:** [7](#0-6) 

This method takes the last miner's `ExpectedMiningTime` and adds `GetMiningInterval()`. If the last miner's actual interval should be 8000ms but `GetMiningInterval()` returns 4000ms, the extra block time is calculated 4000ms earlier than intended.

2. **Time Slot Validation Inconsistency:** [8](#0-7) 

The mining permission check uses `GetMiningInterval()` uniformly for all miners, creating time slot windows that don't match the actual intervals in a non-uniform round.

3. **Round Duration Miscalculation:** [9](#0-8) 

This affects abnormal mining time arrangements when miners miss slots, as the total round duration calculation assumes uniform intervals.

**Severity:** High - Breaks the fairness guarantee of AEDPoS consensus where each miner should have equal time slots. The extra block producer gains an unfair advantage by mining earlier, potentially front-running other miners' blocks or manipulating round transitions.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be selected as the extra block producer (rotates among miners based on signature)
- Can construct arbitrary transaction payloads to the consensus contract
- No special permissions beyond being in the miner list

**Attack Complexity:**
Low - The attacker simply needs to:
1. Craft a `NextRoundInput` with non-uniform intervals (e.g., 4000ms, 8000ms, 8000ms)
2. Ensure intervals pass the 2x tolerance check in `CheckRoundTimeSlots()`
3. Submit via the `NextRound` public method [10](#0-9) 

**Feasibility:** High - Normal round generation creates uniform intervals, but nothing prevents a miner from constructing a custom round: [11](#0-10) 

The `ToRound()` conversion is straightforward and the input structure is controllable by the submitter.

**Detection Difficulty:** Medium - Non-uniform intervals would be visible in the round data, but monitoring systems might not flag this as suspicious if intervals fall within the 2x tolerance.

### Recommendation

**1. Enforce Uniform Interval Validation:**
Add a stricter validation in `CheckRoundTimeSlots()` that requires ALL intervals to match the base interval within a much tighter tolerance (e.g., ±5% instead of ±100%):

```csharp
// In CheckRoundTimeSlots() around line 53
const int tolerancePercent = 5;
var maxDeviation = baseMiningInterval * tolerancePercent / 100;
if (Math.Abs(miningInterval - baseMiningInterval) > maxDeviation)
    return new ValidationResult { Message = "Time slots must be nearly uniform." };
```

**2. Validate Against Expected Generation:**
Add a validation provider that compares the provided round against what `GenerateNextRoundInformation()` would produce: [12](#0-11) 

Verify that all `ExpectedMiningTime` values match the formula: `currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order))`

**3. Add Invariant Check:**
In `GetExtraBlockMiningTime()`, assert that the last miner's actual interval matches `GetMiningInterval()` to detect inconsistencies early.

**4. Test Cases:**
- Test round submission with intervals [4000, 8000, 8000] - should reject
- Test round submission with intervals [4000, 4000, 4000] - should accept
- Test extra block mining time calculation with non-uniform round - should fail validation

### Proof of Concept

**Initial State:**
- 4 miners in the consensus
- Standard mining interval: 4000ms
- Attacker is selected as extra block producer for current round

**Attack Steps:**

1. Attacker crafts malicious `NextRoundInput` with `RealTimeMinersInformation`:
   - Miner 1: Order=1, ExpectedMiningTime=T+0ms
   - Miner 2: Order=2, ExpectedMiningTime=T+4000ms
   - Miner 3: Order=3, ExpectedMiningTime=T+12000ms (8000ms interval)
   - Miner 4: Order=4, ExpectedMiningTime=T+20000ms (8000ms interval)

2. Submit `NextRound` transaction with the crafted input

3. Validation occurs:
   - `CheckRoundTimeSlots()` calculates baseMiningInterval = 4000ms
   - Checks interval(Miner3, Miner2) = 8000ms: |8000-4000| = 4000 ≤ 4000 ✓
   - Checks interval(Miner4, Miner3) = 8000ms: |8000-4000| = 4000 ≤ 4000 ✓
   - Round **passes validation**

4. Round is accepted and stored

5. When calculating extra block mining time:
   - `GetExtraBlockMiningTime()` returns: 20000ms + 4000ms = 24000ms
   - If intervals were consistent at 8000ms, should be: 20000ms + 8000ms = 28000ms

**Expected Result:** Extra block should be minable at T+28000ms (if all intervals were 8000ms like the last miners)

**Actual Result:** Extra block is minable at T+24000ms (using first two miners' 4000ms interval)

**Success Condition:** Attacker mines extra block at T+24000ms, gaining 4000ms advantage and potentially disrupting the intended fair time slot allocation of the consensus protocol.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ArrangeAbnormalMiningTime.cs (L68-72)
```csharp
    public int TotalMilliseconds(int miningInterval = 0)
    {
        if (miningInterval == 0) miningInterval = GetMiningInterval();

        return RealTimeMinersInformation.Count * miningInterval + miningInterval;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-36)
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
```
