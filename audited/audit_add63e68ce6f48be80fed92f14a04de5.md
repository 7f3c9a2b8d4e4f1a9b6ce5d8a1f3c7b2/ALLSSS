### Title
TermNumber Increment Bypass via NextRound Behavior Validation Gap

### Summary
A malicious miner can craft a consensus block header with NextRound behavior but an incremented TermNumber, bypassing term-specific validation in `ValidationForNextRound()`. This allows skipping critical term transition logic including mining reward distribution, election snapshots, miner list updates, and missed time slot penalties, while causing persistent state inconsistency between `State.CurrentTermNumber` and the stored round's TermNumber.

### Finding Description

The vulnerability exists in the `RoundTerminateValidationProvider.ValidateHeaderInformation()` method. When a block header specifies `AElfConsensusBehaviour.NextRound`, validation immediately returns the result of `ValidationForNextRound()` at line 14 without checking TermNumber consistency. [1](#0-0) 

The `ValidationForNextRound()` function only validates two conditions: (1) round number is incremented by exactly 1, and (2) InValues are null. Critically, it does NOT validate that TermNumber remains unchanged. [2](#0-1) 

In contrast, `ValidationForNextTerm()` explicitly checks that TermNumber is incremented by exactly 1, demonstrating that TermNumber consistency is a critical invariant. [3](#0-2) 

When `GenerateNextRoundInformation()` legitimately creates a next round, it explicitly preserves the current TermNumber, confirming that NextRound transitions should NOT change the term. [4](#0-3) 

However, `NextRoundInput.ToRound()` blindly copies the TermNumber from the input without validation, allowing a malicious value to propagate. [5](#0-4) 

During execution, `ProcessNextRound()` only updates `State.CurrentRoundNumber` via `TryToUpdateRoundNumber()` but never calls `TryToUpdateTermNumber()`, creating a desynchronization. [6](#0-5) 

Meanwhile, `AddRoundInformation()` stores the malicious round (with incremented TermNumber) directly into `State.Rounds[round.RoundNumber]`. [7](#0-6) 

### Impact Explanation

**State Inconsistency**: After the attack, `State.CurrentTermNumber` remains at the old value while `State.Rounds[currentRoundNumber].TermNumber` is incremented, creating a persistent desynchronization that corrupts term-based lookups and validations. [8](#0-7) 

**Bypassed Critical Term Logic**: The attacker skips all term transition operations in `ProcessNextTerm()`:

1. **Mining Reward Misallocation**: `DonateMiningReward()` and `TreasuryContract.Release()` are not executed, preventing mining rewards from being distributed and treasury funds from being released for the term. [9](#0-8) 

2. **Election Corruption**: `ElectionContract.TakeSnapshot()` is skipped, breaking the election snapshot mechanism that records mined blocks and voting power for the term. [10](#0-9) 

3. **Miner List Desynchronization**: `SetMinerList()` and `State.FirstRoundNumberOfEachTerm` updates are skipped, corrupting the term-to-miner-list mapping. [11](#0-10) 

4. **Missed Penalty Evasion**: `CountMissedTimeSlots()` is not called, allowing evil miners to escape penalties for missed time slots. [12](#0-11) 

The cumulative impact affects the entire economic and governance system: mining rewards are not distributed correctly, election voting power calculations become corrupted, and malicious miners evade accountability.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be a miner in the current miner list, which is achievable through the election process or initial genesis configuration. The attacker must also be selected as the extra block producer for the round, which occurs deterministically based on the signature calculation. [13](#0-12) 

**Attack Execution**: 
1. The miner receives a legitimate `GetConsensusCommand` indicating NextRound behavior
2. The miner calls `GetConsensusExtraData` to generate the block header data
3. Before submitting the block, the miner manually modifies `extraData.Round.TermNumber` to increment it by 1
4. The miner submits the block with the modified header

**Feasibility**: The attack requires no special economic cost beyond normal block production. The validation gap guarantees success with 100% probability. Detection is difficult as the modified TermNumber appears in the stored round data but `State.CurrentTermNumber` remains unchanged, creating subtle inconsistencies that may not immediately trigger alerts.

**Operational Constraints**: The attack can be executed whenever the miner is the extra block producer, which happens periodically in the round-robin rotation. There are no additional permission checks or rate limits preventing repeated exploitation across multiple rounds.

### Recommendation

**Immediate Fix**: Modify `ValidationForNextRound()` to enforce TermNumber immutability:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD: Validate TermNumber remains unchanged for NextRound
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "TermNumber must not change during NextRound transition." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

**Invariant Enforcement**: Add an assertion in `ProcessNextRound()` to detect inconsistencies:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // ADD: Enforce TermNumber invariant
    Assert(nextRound.TermNumber == currentRound.TermNumber, 
        "NextRound must preserve TermNumber");
    
    // ... existing logic
}
```

**Regression Testing**: Add test cases that attempt to submit NextRound blocks with incremented TermNumber and verify they are rejected during validation.

### Proof of Concept

**Initial State**:
- Current round: RoundNumber = 10, TermNumber = 2
- Attacker is a miner and selected as extra block producer
- State.CurrentRoundNumber = 10
- State.CurrentTermNumber = 2

**Attack Steps**:

1. **Attacker crafts malicious block header**:
   - Behaviour = AElfConsensusBehaviour.NextRound
   - Round.RoundNumber = 11 (legitimate increment)
   - Round.TermNumber = 3 (malicious increment)
   - Round.RealTimeMinersInformation with null InValues (passes validation)

2. **Validation Before Execution**:
   - `ValidateConsensusBeforeExecution` parses the header
   - `RoundTerminateValidationProvider.ValidateHeaderInformation` is called
   - Line 14: Behaviour == NextRound → calls `ValidationForNextRound`
   - `ValidationForNextRound` checks: RoundNumber 11 == 10+1 ✓, InValues null ✓
   - **TermNumber NOT checked** → Validation PASSES

3. **Transaction Execution**:
   - `NextRound` transaction executes with TermNumber=3 in input
   - `ProcessNextRound` called
   - `AddRoundInformation` stores Round with TermNumber=3 at State.Rounds[11]
   - `TryToUpdateRoundNumber(11)` updates State.CurrentRoundNumber to 11
   - **TryToUpdateTermNumber NOT called**

4. **Final State**:
   - State.CurrentRoundNumber = 11 ✓
   - State.CurrentTermNumber = 2 (unchanged)
   - State.Rounds[11].TermNumber = 3 (corrupted)
   - **Inconsistency Created**: Global term state (2) != Round's term state (3)

**Expected vs Actual**:
- Expected: NextRound should preserve TermNumber=2, or validation should reject the modified header
- Actual: Validation passes, execution succeeds, creating persistent state inconsistency and bypassing all term transition logic including reward distribution, election snapshots, and miner list updates

**Success Condition**: After block execution, `State.Rounds[11].TermNumber == 3` while `State.CurrentTermNumber == 2`, and no term transition operations (mining rewards, treasury release, election snapshot, miner list update) were executed.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L14-14)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.NextRound) return ValidationForNextRound(validationContext);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L22-22)
```csharp
        nextRound.TermNumber = TermNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L33-33)
```csharp
            TermNumber = TermNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-159)
```csharp
        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L167-168)
```csharp
        // Count missed time slot of current round.
        CountMissedTimeSlots();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-193)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L55-55)
```csharp
            CurrentTermNumber = State.CurrentTermNumber.Value,
```
