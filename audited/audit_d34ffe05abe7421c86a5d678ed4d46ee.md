### Title
Missing Mining Interval Validation in Next Round Consensus Transition

### Summary
The `ValidationForNextRound()` function fails to validate that the mining interval in the submitted next round matches the consensus parameter `State.MiningInterval.Value`. A malicious miner can submit a next round with arbitrarily modified expected mining times, causing consensus timing disruption and cumulative interval drift across subsequent rounds.

### Finding Description

The vulnerability exists in the validation logic for next round transitions: [1](#0-0) 

The `ValidationForNextRound()` function only validates round number increment and null InValues, but does not validate the mining interval. The consensus contract stores a `MiningInterval` parameter in state: [2](#0-1) 

This parameter is set during initialization: [3](#0-2) 

However, when validating a next round submission, the only time-related validation performed is `CheckRoundTimeSlots()`: [4](#0-3) 

The `CheckRoundTimeSlots()` method only ensures internal consistency (intervals between consecutive miners are equal and greater than 0), but does not compare against `State.MiningInterval.Value`: [5](#0-4) 

When generating the next round, the system uses `GetMiningInterval()` which dynamically calculates from current round timing: [6](#0-5) 

A malicious miner can modify the `NextRoundInput` before submission, changing all expected mining times to use a different interval (e.g., doubling or halving them), and as long as the intervals remain internally consistent, all validations pass.

### Impact Explanation

**Consensus Timing Disruption**: A malicious miner can manipulate the mining interval to slow down or speed up block production. For example, changing from 4000ms to 8000ms would halve the block production rate, while changing to 2000ms would double it.

**Cumulative Drift**: Since each round's interval is calculated from the previous round's expected mining times, the manipulated interval persists and compounds across subsequent rounds. Once one malicious round is accepted, all future rounds inherit the corrupted timing.

**Protocol Integrity**: The mining interval is a fundamental consensus parameter that should remain fixed per the initial configuration. Allowing arbitrary modification breaks this invariant and enables timing-based attacks on the network.

**Affected Parties**: All network participants are affected as block production timing deviates from expected parameters, potentially breaking timing assumptions in dependent systems.

### Likelihood Explanation

**Reachable Entry Point**: Any miner in the current rotation can call the `NextRound` method: [7](#0-6) 

**Attack Complexity**: Low. The attacker only needs to:
1. Obtain the legitimate next round via `GetConsensusExtraData`
2. Modify all `ExpectedMiningTime` values to use a different interval
3. Submit the modified `NextRoundInput`

**Feasible Preconditions**: The attacker must be an active miner in the rotation, which is a standard participant role rather than a privileged position requiring compromise.

**Detection Difficulty**: The attack is subtle as the modified round still appears internally consistent. No validation compares against the expected `State.MiningInterval.Value`.

### Recommendation

Add validation in `ValidationForNextRound()` to ensure the mining interval matches the consensus parameter:

1. Calculate the actual mining interval from the submitted next round's expected mining times
2. Compare against `State.MiningInterval.Value` with appropriate tolerance
3. Reject rounds where the interval deviates beyond acceptable bounds

Alternatively, add validation in `TimeSlotValidationProvider` to check the first miner's expected mining time against current block time plus expected interval.

Example check to add in `RoundTerminateValidationProvider.ValidationForNextRound()`:
```
var submittedInterval = extraData.Round.GetMiningInterval();
var expectedInterval = validationContext.MiningInterval; // from State.MiningInterval.Value
if (Math.Abs(submittedInterval - expectedInterval) > toleranceThreshold)
    return new ValidationResult { Message = "Mining interval deviates from consensus parameter." };
```

### Proof of Concept

**Initial State**:
- Consensus initialized with `MiningInterval = 4000ms`
- Current round R has miners with consistent 4000ms intervals

**Attack Steps**:
1. Malicious miner M is the extra block producer for round R
2. M calls `GetConsensusExtraData` to obtain legitimate next round R+1 with 4000ms intervals
3. M modifies the `NextRoundInput` for R+1:
   - Changes all `ExpectedMiningTime` values to use 8000ms intervals instead
   - Maintains internal consistency (all intervals equal)
4. M submits the modified `NextRoundInput` to `NextRound()` method
5. Validation executes:
   - `ValidationForNextRound()`: Passes (only checks round number and InValues)
   - `CheckRoundTimeSlots()`: Passes (intervals are internally consistent at 8000ms)
   - `NextRoundMiningOrderValidationProvider`: Passes (mining order correct)
6. Round R+1 is accepted with 8000ms intervals
7. Future rounds (R+2, R+3, ...) inherit the 8000ms interval via `GetMiningInterval()`

**Expected Result**: Validation should reject the round due to interval mismatch with `State.MiningInterval.Value`

**Actual Result**: Round is accepted, block production slows to half speed, and the manipulated interval persists indefinitely

**Success Condition**: Query `State.Rounds[R+1].GetMiningInterval()` returns 8000ms instead of expected 4000ms, and this persists in subsequent rounds.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L28-28)
```csharp
    public ReadonlyState<int> MiningInterval { get; set; }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L83-83)
```csharp
        State.MiningInterval.Value = input.GetMiningInterval();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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
