### Title
Missing Null Validation for ExpectedMiningTime Causing Consensus Halt via NullReferenceException in GetExtraBlockMiningTime()

### Summary
The `GetExtraBlockMiningTime()` function attempts to call `AddMilliseconds()` on a potentially null `ExpectedMiningTime` field without null checking. If a Round object with null `ExpectedMiningTime` for the last miner is stored in state (bypassing incomplete validation), subsequent calls to `IsCurrentMiner()` will trigger a NullReferenceException, halting the ability to determine extra block production timing and disrupting consensus.

### Finding Description

The vulnerability exists in the `GetExtraBlockMiningTime()` method: [1](#0-0) 

This method retrieves the last miner by order and directly calls `AddMilliseconds()` on `ExpectedMiningTime` without null checking. Since `ExpectedMiningTime` is a protobuf `Timestamp` message field, it can be null if not set during serialization.

Evidence that null values are possible - the codebase includes explicit null checking in `CheckRoundTimeSlots()`: [2](#0-1) 

However, this validation method is never invoked during the consensus validation flow. The validation in `ValidateBeforeExecution()` uses several providers but none check for null `ExpectedMiningTime`: [3](#0-2) 

Round objects reach state storage through `ProcessNextRound()` and `ProcessNextTerm()`, which convert input to Round via `ToRound()` that directly copies `RealTimeMinersInformation`: [4](#0-3) [5](#0-4) 

The vulnerable function is called in the critical path when checking if a miner can produce blocks, specifically for extra block time slot validation: [6](#0-5) 

### Impact Explanation

**Consensus Disruption (High Severity):**
- When `GetExtraBlockMiningTime()` throws NullReferenceException, the `IsCurrentMiner()` method fails
- This prevents the system from determining when extra block production should occur
- Extra blocks are critical in AEDPoS for terminating rounds and initiating round/term transitions
- Without proper extra block timing checks, consensus progression halts
- The exception propagates through the public `IsCurrentMiner()` method, affecting all callers attempting to validate mining permissions

**Affected Parties:**
- All network participants - consensus freezes prevent block production
- Miners cannot determine valid time slots for extra block production
- Network requires emergency intervention to recover

### Likelihood Explanation

**Attack Complexity: Medium**

While normal round generation always sets `ExpectedMiningTime`, the vulnerability can be triggered through:

1. **Malformed Consensus Data**: A miner generating NextRound/NextTerm consensus data could manipulate the protobuf serialization to omit `ExpectedMiningTime` fields before block submission. Since protobuf3 message fields are optional, omitted fields deserialize as null.

2. **Validation Gap**: The `ValidateBeforeExecution()` method validates behavioral aspects (mining permissions, time slots, round numbers) but never validates the structural integrity of Round data, specifically never calling the existing `CheckRoundTimeSlots()` method that checks for null.

3. **State Persistence**: Once a malformed Round passes validation and is stored via `AddRoundInformation()`, it remains in state until the round expires, creating a persistent DoS condition.

**Attacker Requirements:**
- Must be an active miner with block production rights
- Can construct consensus extra data (available to all miners)
- Needs to manipulate protobuf bytes (technically feasible)

**Detection Difficulty:** Low - the NullReferenceException would be immediately visible in logs when the next miner attempts to validate their time slot.

### Recommendation

**1. Add mandatory null validation before using ExpectedMiningTime:**

Add validation in `GetExtraBlockMiningTime()` itself:
```csharp
public Timestamp GetExtraBlockMiningTime()
{
    var lastMiner = RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value;
    Assert(lastMiner.ExpectedMiningTime != null, "Last miner ExpectedMiningTime cannot be null");
    return lastMiner.ExpectedMiningTime.AddMilliseconds(GetMiningInterval());
}
```

**2. Integrate CheckRoundTimeSlots() into validation flow:**

Modify `ValidateBeforeExecution()` to include structural validation:
```csharp
// After line 60 in AEDPoSContract_Validation.cs
var roundValidation = extraData.Round.CheckRoundTimeSlots();
if (!roundValidation.Success)
    return roundValidation;
```

**3. Add validation in NextRound/NextTerm validation providers:**

Enhance `RoundTerminateValidationProvider` to call `CheckRoundTimeSlots()` on the provided round.

**4. Defensive programming in IsCurrentMiner:**

Wrap the `GetExtraBlockMiningTime()` call in a try-catch or add explicit null check before calling.

### Proof of Concept

**Initial State:**
- Network running with normal consensus
- Attacker is an active miner with extra block producer rights

**Attack Steps:**

1. Attacker's turn to produce extra block for NextRound
2. Call `GenerateConsensusTransactions()` to get consensus data
3. Intercept the generated `NextRoundInput` protobuf data
4. Modify the protobuf bytes to set `expected_mining_time` field of the last miner to null (omit field in serialization)
5. Sign and submit block with malformed consensus data
6. Block passes `ValidateBeforeExecution()` because no validation checks null `ExpectedMiningTime`
7. `ProcessNextRound()` stores malformed Round via `AddRoundInformation()`

**Expected Result:** Round stored successfully, next operations proceed normally

**Actual Result:**
- Round stored with null ExpectedMiningTime
- Next miner calls `IsCurrentMiner()` to check their time slot
- `GetExtraBlockMiningTime()` is invoked at validation line 173
- NullReferenceException thrown when calling `AddMilliseconds()` on null
- Extra block production check fails
- Consensus cannot progress past current round

**Success Condition:** Exception logs show "NullReferenceException" in `GetExtraBlockMiningTime()` and no further blocks produced until manual intervention.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L40-41)
```csharp
        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L172-178)
```csharp
        // Check extra block time slot.
        if (Context.CurrentBlockTime >= currentRound.GetExtraBlockMiningTime() &&
            supposedExtraBlockProducer == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]EXTRA");
            return true;
        }
```
