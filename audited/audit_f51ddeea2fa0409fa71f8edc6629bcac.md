### Title
Term Change Indefinitely Delayed via Timestamp Manipulation by Coalition of ~1/3 Miners

### Summary
The `NeedToChangeTerm` function relies on miners' self-reported `ActualMiningTime` timestamps to determine when a term change should occur, requiring a two-thirds consensus. However, there is no validation that the `ActualMiningTime` provided in consensus transactions matches `Context.CurrentBlockTime`, allowing miners to submit backdated timestamps. A coalition controlling approximately one-third of miners can indefinitely prevent term changes by continuously reporting timestamps from before the term threshold.

### Finding Description

The vulnerability exists in the term change detection mechanism across multiple files: [1](#0-0) 

This function calls `NeedToChangeTerm` to determine whether to return `NextTerm` or `NextRound` behavior. [2](#0-1) 

The `NeedToChangeTerm` method counts how many miners have their **last** `ActualMiningTime` indicating it's time to change term (via `IsTimeToChangeTerm` check). It requires at least `MinersCountOfConsent` miners. [3](#0-2) 

Where `MinersCountOfConsent = N * 2 / 3 + 1` for N total miners. [4](#0-3) 

The `IsTimeToChangeTerm` check compares the timestamp against the term period to determine if a term change is needed.

**Root Cause:** [5](#0-4) 

When processing `UpdateValue` transactions, the `ActualMiningTime` from the input is directly added to the miner's list **without any validation** that it equals `Context.CurrentBlockTime`. [6](#0-5) 

The same issue exists for `TinyBlock` transactions.

**Why Existing Protections Fail:** [7](#0-6) 

The `TimeSlotValidationProvider` only validates the **previous** `ActualMiningTime` (line 41), not the new one being added in the current transaction. This check uses `OrderBy(t => t).LastOrDefault()` which gets the latest existing timestamp before the current transaction executes, allowing the current transaction to add any timestamp unchecked. [8](#0-7) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` - it does not check `ActualMiningTime` at all.

### Impact Explanation

**Consensus Integrity Breach:**
An attacker controlling K miners where K ≥ N/3 (approximately) can prevent term changes indefinitely. For example, with 21 total miners (N=21), `MinersCountOfConsent = 15`. If 7 malicious miners (K=7, exactly 1/3) provide old timestamps, only 14 honest miners indicate term change, which is less than the required 15, blocking the term transition.

**Concrete Harm:**
1. **Miner Rotation Blocked**: Term changes are designed to rotate the miner set based on election results. Preventing term changes allows the current miner set to remain in power indefinitely.
2. **Election Results Ignored**: Voters' choices through the election system are nullified as new elected miners cannot take their positions.
3. **Governance Disruption**: Any governance mechanisms that depend on term transitions (such as Treasury releases triggered by term changes) are halted.
4. **Centralization Risk**: Allows entrenched miners to maintain control, defeating the purpose of periodic miner rotation for decentralization.

**Severity**: High - This breaks a fundamental consensus invariant (correct term transitions) and enables indefinite control by a minority coalition.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Control approximately 1/3 of the active miner nodes (~7 out of 21 miners)
- Ability to modify node software to provide backdated `ActualMiningTime` values
- Continuous participation as active miners

**Attack Complexity:**
- **Low Technical Barrier**: Requires only modifying the consensus transaction generation logic to use an old timestamp instead of `Context.CurrentBlockTime`
- **No Special Permissions**: Uses existing miner capabilities through normal block production
- **Persistent Effect**: Once started, can be maintained indefinitely as long as the coalition remains active

**Feasibility Conditions:**
- Miners are not perfectly distributed (realistic in many blockchain networks)
- Coalition coordination among ~1/3 of miners (significant but achievable)
- No detection mechanism exists since backdated timestamps within reasonable bounds appear valid

**Detection/Operational Constraints:**
- Difficult to detect without comparing each miner's `ActualMiningTime` against actual block timestamps
- No automatic circuit breaker or alerting mechanism
- Manual intervention required to identify and address the attack

**Probability**: Medium-High - While requiring control of ~1/3 of miners is non-trivial, it's not unrealistic in networks with concentrated mining power or where miners can collude. The attack is technically simple to execute once the coalition is formed.

### Recommendation

**Immediate Fix**: Add validation in `ProcessUpdateValue` and `ProcessTinyBlock` to enforce that the provided `ActualMiningTime` matches the current block time:

```csharp
// In ProcessUpdateValue (after line 240)
Assert(updateValueInput.ActualMiningTime == Context.CurrentBlockTime, 
    "ActualMiningTime must match current block time.");

// In ProcessTinyBlock (after line 301)  
Assert(tinyBlockInput.ActualMiningTime == Context.CurrentBlockTime,
    "ActualMiningTime must match current block time.");
```

**Additional Safeguards:**
1. Add timestamp validation in `TimeSlotValidationProvider` to check the **new** timestamp being added, not just historical ones
2. Implement monitoring to detect miners whose `ActualMiningTime` consistently lags behind actual block production times
3. Add a fallback mechanism: if term change is blocked for an excessive period (e.g., 2x the normal term duration), force a term change with reduced threshold

**Test Cases:**
1. Test that `UpdateValue` with `ActualMiningTime != Context.CurrentBlockTime` is rejected
2. Test that term change succeeds when exactly MinersCountOfConsent miners have valid timestamps
3. Test that term change fails when fewer than MinersCountOfConsent miners have valid timestamps
4. Test detection of miners providing systematically old timestamps

### Proof of Concept

**Initial State:**
- 21 active miners in current term
- `MinersCountOfConsent = 15`
- Current term period expires at timestamp T_threshold
- 7 miners controlled by attacker, 14 honest miners

**Attack Sequence:**

1. **Normal Term Progression**: Time advances past T_threshold. Honest miners continue producing blocks with `ActualMiningTime = Context.CurrentBlockTime > T_threshold`.

2. **Malicious Behavior**: When each of the 7 attacker-controlled miners produces a block at time T_current (where T_current > T_threshold):
   - Modify node to generate `UpdateValueInput` with `ActualMiningTime = T_old` (where T_old < T_threshold)
   - Submit block with this backdated timestamp
   - Transaction executes successfully (no validation rejects it)

3. **Term Change Evaluation**: When any miner attempts to produce `NextTerm` block:
   - `NeedToChangeTerm` is evaluated
   - Counts miners with `IsTimeToChangeTerm(..., ActualMiningTimes.Last(), ...) == true`
   - 14 honest miners: `ActualMiningTimes.Last() > T_threshold` → returns `true`
   - 7 malicious miners: `ActualMiningTimes.Last() = T_old < T_threshold` → returns `false`
   - Total count: 14 < 15 (MinersCountOfConsent)
   - `NeedToChangeTerm` returns `false`

4. **Result**: 
   - Expected: Term change should occur (current time is past threshold)
   - Actual: `GetConsensusBehaviourToTerminateCurrentRound` returns `NextRound` instead of `NextTerm`
   - Term change is blocked indefinitely

**Success Condition**: The attack succeeds when the attacker coalition maintains K ≥ N - MinersCountOfConsent + 1 miners continuously providing old timestamps, preventing the system from ever reaching the MinersCountOfConsent threshold for term change approval.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-243)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
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
