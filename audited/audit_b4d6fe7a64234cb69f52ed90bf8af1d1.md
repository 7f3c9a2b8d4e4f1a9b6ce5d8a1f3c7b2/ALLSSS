### Title
Timestamp Precision Loss in IsTimeSlotPassed Causes Premature Time Slot Expiration

### Summary
The `IsTimeSlotPassed` method in the Round class loses millisecond precision when calculating time slot boundaries by using integer division instead of the `AddMilliseconds` extension method. This causes miners to incorrectly believe their time slot has expired up to 999 milliseconds early, resulting in lost block production opportunities and reduced network throughput.

### Finding Description

The core issue is an inconsistency in how time slot boundaries are calculated across the consensus system:

**Incorrect Implementation (loses millisecond precision):** [1](#0-0) 

The `IsTimeSlotPassed` method uses `new Duration { Seconds = miningInterval.Div(1000) }` which performs integer division, truncating the millisecond remainder. For example, if `miningInterval` is 4500 milliseconds, `4500 / 1000 = 4` seconds, losing the 500 millisecond remainder.

**Correct Implementations (preserve millisecond precision):**

1. TimeSlotValidationProvider uses AddMilliseconds correctly: [2](#0-1) 

2. IsCurrentMiner uses AddMilliseconds correctly: [3](#0-2) 

3. NormalBlockCommandStrategy uses AddMilliseconds correctly: [4](#0-3) 

4. Test implementations use AddMilliseconds correctly: [5](#0-4) 

**Root Cause:**
The `GetMiningInterval` method returns milliseconds as an `int`: [6](#0-5) 

When `IsTimeSlotPassed` converts this back to a Duration, it divides by 1000 using integer division, losing the millisecond remainder.

**How AddMilliseconds Should Work:**
The `AddMilliseconds` extension method correctly preserves millisecond precision: [7](#0-6) 

It splits milliseconds into `Seconds = milliseconds / 1000` and `Nanos = (milliseconds % 1000) * 1000000`, preserving the millisecond remainder as nanoseconds.

**Execution Path:**
The flawed `IsTimeSlotPassed` method is called by `ConsensusBehaviourProviderBase`: [8](#0-7) 

This determines whether a miner can continue producing TinyBlocks or should terminate their time slot.

### Impact Explanation

**Concrete Impact:**
- When mining interval is 4500ms and a miner's expected mining time is 1000.0s, the actual time slot ends at 1004.5s
- `IsTimeSlotPassed` incorrectly checks against 1004.0s (losing 500ms)
- If current time is 1004.3s, the method returns true (time slot passed) even though 200ms remain
- Miner stops producing blocks prematurely, losing up to 999ms of allocated time per time slot

**Protocol Damage:**
- Reduced network throughput as miners produce fewer blocks than allocated
- Inconsistent behavior between consensus command generation (uses correct calculation) and time slot checking (uses incorrect calculation)
- In tight timing scenarios, could affect round transitions and consensus reliability

**Affected Parties:**
- All miners lose block production opportunities proportional to their mining interval's millisecond remainder
- Network overall experiences reduced block production capacity

**Severity Justification:**
Low severity - does not enable theft or unauthorized actions, but reduces operational efficiency and creates consensus timing inconsistencies. Validation still uses correct calculation preventing actual security breaches.

### Likelihood Explanation

**Occurrence Conditions:**
- Happens automatically whenever mining interval has a non-zero millisecond remainder
- Mining interval is calculated from timestamp differences between miners: [9](#0-8) 
- Common occurrence in normal operation as timestamps rarely align to exact seconds

**Probability:**
- HIGH - affects all normal consensus rounds where mining intervals have millisecond precision
- No attacker action needed - inherent bug in production code
- Test code shows correct implementation, indicating this is unintended behavior

**Detection:**
- Difficult to detect without detailed timing analysis
- Manifests as slightly reduced block production that could be attributed to network latency or other factors

### Recommendation

**Code-Level Fix:**
Replace the Duration creation in `IsTimeSlotPassed` to use `AddMilliseconds`:

```csharp
// In Round.cs, line 89, change from:
return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } < currentBlockTime;

// To:
return minerInRound.ExpectedMiningTime.AddMilliseconds(miningInterval) < currentBlockTime;
```

**Invariant Checks:**
- Ensure all time slot boundary calculations use `AddMilliseconds` for consistency
- Add unit tests comparing `IsTimeSlotPassed` results with `AddMilliseconds` calculations
- Verify no other locations perform manual Duration construction with integer division

**Test Cases:**
- Test with mining intervals having millisecond remainders (e.g., 4500ms, 4001ms)
- Verify `IsTimeSlotPassed` matches behavior of `TimeSlotValidationProvider.CheckMinerTimeSlot`
- Confirm miners can produce blocks for full allocated time including millisecond precision

### Proof of Concept

**Initial State:**
- Round configured with two miners
- Miner A ExpectedMiningTime: `{ Seconds = 1000, Nanos = 0 }`
- Miner B ExpectedMiningTime: `{ Seconds = 1004, Nanos = 500000000 }` (1004.5s)
- Mining interval calculated: 4500 milliseconds

**Test Sequence:**
1. Call `GetMiningInterval()` → returns 4500
2. Set current block time to `{ Seconds = 1004, Nanos = 300000000 }` (1004.3s)
3. Call `IsTimeSlotPassed(MinerA, currentBlockTime)`

**Expected Result:**
- Time slot should end at 1004.5s
- Current time 1004.3s < 1004.5s
- Should return `false` (time slot not passed)

**Actual Result:**
- `IsTimeSlotPassed` calculates: 1000s + 4s = 1004.0s
- Current time 1004.3s > 1004.0s
- Returns `true` (time slot incorrectly marked as passed)
- Miner loses remaining 200ms of allocated time

**Success Condition:**
After applying the fix, `IsTimeSlotPassed` returns `false` at 1004.3s and only returns `true` after 1004.5s, matching the behavior of validation and command generation logic.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L83-90)
```csharp
    public bool IsTimeSlotPassed(string publicKey, Timestamp currentBlockTime)
    {
        var miningInterval = GetMiningInterval();
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
        if (RoundNumber != 1)
            return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } <
                   currentBlockTime;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L44-45)
```csharp
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L162-163)
```csharp
        if (timeSlotStartTime <= Context.CurrentBlockTime && Context.CurrentBlockTime <=
            timeSlotStartTime.AddMilliseconds(miningInterval))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L38-38)
```csharp
                MiningDueTime = CurrentRound.GetExpectedMiningTime(Pubkey).AddMilliseconds(MiningInterval),
```

**File:** test/AElf.Contracts.MultiToken.Tests/Types/Round.cs (L48-48)
```csharp
        return minerInRound.ExpectedMiningTime.ToDateTime().AddMilliseconds(miningInterval) <= dateTime;
```

**File:** src/AElf.CSharp.Core/Extension/TimestampExtensions.cs (L16-20)
```csharp
    public static Timestamp AddMilliseconds(this Timestamp timestamp, long milliseconds)
    {
        return timestamp + new Duration
            { Seconds = milliseconds / 1000, Nanos = (int)(milliseconds % 1000).Mul(1000000) };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L35-35)
```csharp
            _isTimeSlotPassed = CurrentRound.IsTimeSlotPassed(_pubkey, _currentBlockTime);
```
