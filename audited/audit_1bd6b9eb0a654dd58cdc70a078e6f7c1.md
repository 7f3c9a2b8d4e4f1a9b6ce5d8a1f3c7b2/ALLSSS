### Title
Silent Fallback to Empty Round Bypasses Critical Consensus Validations

### Summary
When `TryToGetPreviousRoundInformation` fails to fetch the previous round, `ValidateBeforeExecution` silently falls back to an empty `Round()` object, causing `UpdateValueValidationProvider` and `TimeSlotValidationProvider` to incorrectly bypass critical validation checks. This allows invalid blocks to pass validation when storage reads fail, compromising consensus integrity and the random beacon mechanism.

### Finding Description

The vulnerability exists in the `ValidateBeforeExecution` function where the previous round information is fetched: [1](#0-0) 

When `TryToGetPreviousRoundInformation` returns false, the code falls back to `new Round()` which creates an empty Round object with default values: `RoundId = 0`, `TermNumber = 0`, and an empty `RealTimeMinersInformation` map. [2](#0-1) 

The `TryToGetPreviousRoundInformation` implementation can fail when `State.Rounds[targetRoundNumber]` returns empty: [3](#0-2) 

This empty Round is then passed to validation providers which depend on PreviousRound for critical checks:

**1. UpdateValueValidationProvider Bypass:**
The validator checks if the miner's public key exists in `PreviousRound.RealTimeMinersInformation`. With an empty Round, this map is empty, causing the function to return true immediately without validating PreviousInValue: [4](#0-3) 

This bypasses validation of `Hash(PreviousInValue) == PreviousOutValue`, which is critical for the secret sharing and random number generation mechanism.

**2. TimeSlotValidationProvider Bypass:**
The validator checks if it's the first round of the current term by comparing `PreviousRound.TermNumber` with current term number: [5](#0-4) 

With an empty Round where `TermNumber = 0`, if the current term is greater than 0, this check always returns true, causing the validator to skip actual time slot validation: [6](#0-5) 

### Impact Explanation

The vulnerability breaks two critical consensus safety mechanisms:

**1. Time Slot Enforcement:** Miners are assigned specific time slots to produce blocks. By bypassing TimeSlotValidationProvider checks, a malicious miner could:
- Produce blocks outside their allocated time slot
- Produce multiple consecutive blocks
- Violate the consensus schedule and fairness guarantees

**2. Random Beacon Integrity:** The PreviousInValue validation ensures that each miner's secret contribution to the random number generation is correct. By bypassing this check:
- Miners can provide incorrect or manipulated PreviousInValue
- The consensus random number can be biased or manipulated
- Secret sharing mechanism integrity is compromised

This affects all network participants who depend on:
- Fair block production order
- Unbiased random number generation for elections, rewards, and other protocol decisions
- Consensus time slot guarantees for transaction finality

The severity is **HIGH** because it directly compromises consensus safety properties that are fundamental to the blockchain's security model.

### Likelihood Explanation

While the vulnerability requires a storage read failure to trigger, such failures are realistic in distributed blockchain systems:

**Trigger Conditions:**
1. Transient storage read failures (network issues, node failures)
2. State database corruption or inconsistencies
3. Race conditions during concurrent round updates
4. Cache invalidation issues in distributed deployments

**Exploitation Path:**
1. System experiences storage read failure when accessing `State.Rounds[N-1]` during block validation at round N
2. `TryToGetPreviousRoundInformation` returns false
3. `PreviousRound` is set to empty `Round()`
4. A miner (malicious or not) produces a block with:
   - Incorrect or missing PreviousInValue
   - Block produced outside their time slot
5. Both validations incorrectly pass
6. Invalid block is accepted into the chain

**Likelihood Assessment:**
- **Entry Point**: Reachable via `ValidateConsensusBeforeExecution`, a public method called by the consensus validation system
- **Preconditions**: Storage system must fail to return `State.Rounds[N-1]` when it should exist
- **Frequency**: While not common, storage failures occur in production distributed systems
- **Detection**: The silent fallback makes this difficult to detect until consensus violations occur

The likelihood is **MEDIUM** - not directly exploitable by an attacker, but represents a defensive failure that could be triggered by system issues or opportunistically exploited during infrastructure problems.

### Recommendation

**1. Explicit Failure Handling:**
Replace the silent fallback with explicit validation failure:

```csharp
PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) 
    ? previousRound 
    : State.CurrentRoundNumber.Value < 2 
        ? new Round()  // Only legitimate for round 1
        : null;  // Signal that fetch failed for rounds > 1

if (validationContext.PreviousRound == null)
    return new ValidationResult { 
        Success = false, 
        Message = "Failed to retrieve previous round information for validation." 
    };
```

**2. Add Defensive Checks in Validators:**
In `UpdateValueValidationProvider`, add explicit check for empty PreviousRound:

```csharp
if (validationContext.CurrentRoundNumber > 1 && 
    validationContext.PreviousRound.IsEmpty)
    return new ValidationResult { 
        Success = false, 
        Message = "Previous round information missing for UpdateValue validation." 
    };
```

Similarly in `TimeSlotValidationProvider`:

```csharp
private bool IsFirstRoundOfCurrentTerm(out long termNumber, ConsensusValidationContext validationContext)
{
    termNumber = validationContext.CurrentTermNumber;
    
    // Explicit check for invalid empty previous round
    if (validationContext.CurrentRoundNumber > 1 && validationContext.PreviousRound.IsEmpty)
        return false;  // Cannot determine, should fail validation
        
    return validationContext.PreviousRound.TermNumber != termNumber ||
           validationContext.CurrentRoundNumber == 1;
}
```

**3. Add Logging:**
Log when `TryToGetPreviousRoundInformation` fails for rounds > 1 to enable detection and debugging of storage issues.

**4. Test Coverage:**
Add test cases that simulate storage read failures during validation to ensure proper error handling.

### Proof of Concept

**Initial State:**
- Chain at round 100, term 5
- Miner M attempting to produce block for round 100
- Storage system experiences transient failure reading round 99

**Exploitation Sequence:**

1. Miner M requests consensus command for round 100
2. Block validation begins via `ValidateConsensusBeforeExecution`
3. `TryToGetCurrentRoundInformation` succeeds, returns round 100
4. `TryToGetPreviousRoundInformation` attempts to read round 99 from `State.Rounds[99]`
5. Storage read fails, returns empty Round object
6. `TryToGetPreviousRoundInformation` returns false (due to `previousRound.IsEmpty == true`)
7. Line 57: `PreviousRound` is set to `new Round()` (default values)
8. Validation context created with:
   - `BaseRound` = round 100 (valid)
   - `PreviousRound` = empty Round (RoundId=0, TermNumber=0, empty map)

9. **UpdateValueValidationProvider validation** (if behavior is UpdateValue):
   - Line 40: `PreviousRound.RealTimeMinersInformation.ContainsKey(M)` returns false (empty map)
   - Returns `true` immediately
   - **Expected**: Should validate Hash(PreviousInValue) == PreviousOutValue
   - **Actual**: Validation completely skipped

10. **TimeSlotValidationProvider validation**:
    - Line 56: `PreviousRound.TermNumber (0) != CurrentTermNumber (5)` = true
    - Line 39: Returns `true` immediately
    - **Expected**: Should check if block is within M's time slot
    - **Actual**: Time slot validation completely skipped

11. Block passes all validations despite potentially:
    - Having incorrect PreviousInValue
    - Being produced outside allocated time slot

**Success Condition:**
Invalid block accepted into blockchain, compromising:
- Consensus time slot guarantees
- Random beacon integrity

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L26-26)
```csharp
    public bool IsEmpty => RoundId == 0;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L56-64)
```csharp
    private bool TryToGetPreviousRoundInformation(out Round previousRound)
    {
        previousRound = new Round();
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        if (roundNumber < 2) return false;
        var targetRoundNumber = roundNumber.Sub(1);
        previousRound = State.Rounds[targetRoundNumber];
        return !previousRound.IsEmpty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
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
    }
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
