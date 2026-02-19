### Title
Missing TermNumber Validation in NextRound Allows Consensus Time Slot Bypass

### Summary
The `ToRound()` function in `NextRoundInput.cs` performs no validation on the TermNumber field, and the pre-execution validation for NextRound behavior does not verify that TermNumber remains unchanged during round transitions within the same term. A malicious miner can exploit this to store a Round object with an incorrect TermNumber, causing subsequent blocks to incorrectly bypass time slot validation and break consensus schedule integrity.

### Finding Description

**Root Cause:**

The `ToRound()` function blindly copies all fields from `NextRoundInput` to `Round` without any validation: [1](#0-0) 

The pre-execution validation for NextRound behavior only validates RoundNumber increment and InValue nullity, but does NOT validate that TermNumber remains unchanged: [2](#0-1) 

The correct behavior when generating next round information is to keep TermNumber the same (not increment it): [3](#0-2) 

**Execution Path:**

1. When `ProcessNextRound` is called, it converts the input using the unvalidated `ToRound()`: [4](#0-3) 

2. The Round object with manipulated TermNumber is stored in state: [5](#0-4) 

3. Note that `ProcessNextRound` only updates RoundNumber, NOT TermNumber (unlike `ProcessNextTerm`): [6](#0-5) 

4. In subsequent blocks, the time slot validation checks if it's the first round of a new term by comparing the previous round's TermNumber against the current term number: [7](#0-6) 

5. When this check incorrectly returns true, time slot validation is bypassed: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Compromise:**

This vulnerability breaks the fundamental consensus invariant of time slot validation. Miners are assigned specific time slots to produce blocks, ensuring fair distribution and preventing any single miner from dominating block production. By bypassing time slot checks, a malicious miner can:

1. **Produce blocks outside their assigned time slot**, violating the consensus schedule
2. **Continuously produce blocks** by exploiting the bypass in subsequent rounds
3. **Gain unfair advantage** in block rewards and transaction fee collection
4. **Centralize block production**, undermining the decentralized nature of the network
5. **Create state inconsistency** where stored Round objects have incorrect TermNumbers diverging from the global `State.CurrentTermNumber`

**Affected Parties:**
- Honest miners lose their fair share of block production opportunities
- Network security is weakened by reduced decentralization
- Users may experience degraded service if one miner dominates

**Severity Justification:**
This is a **Medium** severity issue because while it compromises consensus integrity (critical invariant violation), it requires the attacker to be an active miner in the current round, limiting the attack surface. However, the impact on consensus fairness and schedule integrity is concrete and significant.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a valid miner in the current round's miner list (checked by `PreCheck()`)
- This is realistic as miners rotate based on election/staking mechanisms

**Attack Complexity:**
- **Low**: Simply craft a `NextRoundInput` with:
  - Valid `RoundNumber = currentRoundNumber + 1`
  - Invalid `TermNumber = currentTermNumber + 1` (or any other value)
  - Other valid fields
- Call the public `NextRound()` method [9](#0-8) 

**Feasibility:**
- No special privileges required beyond being a miner
- No economic cost beyond normal transaction fees
- Validation will pass because `ValidationForNextRound` doesn't check TermNumber
- Immediately exploitable once in miner list

**Detection:**
- Difficult to detect as the incorrect TermNumber is stored but global state remains correct
- Subsequent behavior appears as "first round of term" which can happen legitimately
- No explicit alerts or checks for TermNumber consistency

**Probability:** 
High for any malicious miner seeking unfair advantage in block production or rewards.

### Recommendation

**Immediate Fix:**

Add TermNumber validation to `ValidationForNextRound`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round number increment
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD THIS: Validate TermNumber remains unchanged for NextRound
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Term number must not change during NextRound transition." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

**Alternative/Additional Fix:**

Add validation directly in `ToRound()` or in `ProcessNextRound()` to assert that the input's TermNumber matches the current state:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    
    // ADD THIS: Validate TermNumber consistency
    Assert(TryToGetTermNumber(out var currentTermNumber), "Failed to get current term number.");
    Assert(nextRound.TermNumber == currentTermNumber, 
        "NextRound must maintain the same term number.");
    
    RecordMinedMinerListOfCurrentRound();
    // ... rest of the method
}
```

**Test Cases:**

1. Test that NextRound with manipulated TermNumber (current + 1) is rejected
2. Test that NextRound with correct TermNumber passes
3. Test that NextTerm correctly increments both RoundNumber and TermNumber
4. Add integration test verifying time slot validation is not bypassed after attempted TermNumber manipulation

### Proof of Concept

**Initial State:**
- Current round number: 100
- Current term number: 5
- Attacker is a valid miner in current round

**Attack Steps:**

1. Attacker crafts malicious `NextRoundInput`:
   ```
   RoundNumber: 101 (valid: current + 1)
   TermNumber: 6 (invalid: should be 5)
   RealTimeMinersInformation: {...valid...}
   ExtraBlockProducerOfPreviousRound: {...valid...}
   RandomNumber: {...valid...}
   ```

2. Attacker calls `NextRound(maliciousInput)`

3. Validation executes:
   - `ValidationForNextRound` checks RoundNumber: 100 + 1 == 101 ✓ PASS
   - `ValidationForNextRound` checks InValues are null ✓ PASS
   - **TermNumber is NOT validated** ✓ PASS

4. `ProcessNextRound` executes:
   - Calls `ToRound()` which copies TermNumber = 6
   - Stores Round with `State.Rounds[101]` having `TermNumber = 6`
   - Updates `State.CurrentRoundNumber = 101`
   - **Does NOT update `State.CurrentTermNumber`** (remains 5)

5. **Result State:**
   - `State.CurrentRoundNumber.Value = 101`
   - `State.CurrentTermNumber.Value = 5` (correct)
   - `State.Rounds[101].TermNumber = 6` (INCORRECT)

6. **Next Block (Round 102):**
   - Validation retrieves previous round: `State.Rounds[101]` with `TermNumber = 6`
   - `IsFirstRoundOfCurrentTerm` checks: `previousRound.TermNumber (6) != currentTermNumber (5)` → TRUE
   - Time slot validation BYPASSED on line 39 (returns early)
   - Attacker can produce block outside assigned time slot

**Expected vs Actual:**
- **Expected**: NextRound with TermNumber ≠ current should be rejected
- **Actual**: Accepted and stored, causing subsequent consensus bypass

**Success Condition:** 
Attacker successfully stores Round with incorrect TermNumber and can bypass time slot checks in subsequent blocks.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L21-22)
```csharp
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-158)
```csharp
        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-174)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-50)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L53-58)
```csharp
    private bool IsFirstRoundOfCurrentTerm(out long termNumber, ConsensusValidationContext validationContext)
    {
        termNumber = validationContext.CurrentTermNumber;
        return validationContext.PreviousRound.TermNumber != termNumber ||
               validationContext.CurrentRoundNumber == 1;
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
