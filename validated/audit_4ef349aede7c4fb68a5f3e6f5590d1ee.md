# Audit Report

## Title
Time Slot Validation Gap Allows Consensus Timing Manipulation via Non-Uniform Mining Intervals

## Summary
The AEDPoS consensus contract contains a critical architectural inconsistency between `GetMiningInterval()` and `CheckRoundTimeSlots()` methods. `GetMiningInterval()` only examines the interval between miners with Order 1 and 2, while `CheckRoundTimeSlots()` permits consecutive intervals to vary by up to 2x the base interval. This allows a malicious miner producing a NextRound block to craft non-uniform time slot allocations that pass validation but cause incorrect extra block timing and time slot window calculations, breaking consensus fairness guarantees.

## Finding Description

The vulnerability stems from an architectural mismatch in the `Round` class where two critical methods have incompatible assumptions:

**Root Cause - GetMiningInterval() Limited Scope:**

The `GetMiningInterval()` method returns only the interval between miners with Order 1 and Order 2, completely ignoring all other consecutive miner intervals in the round. [1](#0-0) 

**Validation Gap - CheckRoundTimeSlots() Permissive Tolerance:**

The validation method allows consecutive intervals to vary by up to 2x the base interval through the condition `Math.Abs(miningInterval - baseMiningInterval) <= baseMiningInterval`. [2](#0-1) 

**Attack Execution Path:**

When a miner produces a NextRound block, they submit a `NextRoundInput` transaction containing the full round data including `ExpectedMiningTime` values for all miners. [3](#0-2)  The transaction input is controlled by the sender and can contain arbitrary values.

The round data is validated through `TimeSlotValidationProvider`, which calls `CheckRoundTimeSlots()` when a new round is detected. [4](#0-3) 

If validation passes, the malicious round data is stored via `ProcessNextRound`. [5](#0-4) 

**Impact Mechanisms:**

1. **Extra Block Time Miscalculation:** The extra block mining time is calculated by taking the last miner's `ExpectedMiningTime` and adding `GetMiningInterval()`. [6](#0-5)  Since `GetMiningInterval()` only uses miners 1-2, if the last miner's actual interval is different, the extra block time will be miscalculated.

2. **Time Slot Window Inconsistency:** All miners' time slot windows are calculated as `ExpectedMiningTime + GetMiningInterval()`. [7](#0-6)  When actual intervals vary but `GetMiningInterval()` returns a fixed value from miners 1-2, this creates mismatched time slot windows.

**Concrete Attack Example:**
- Normal uniform intervals: Miners at 0ms, 4000ms, 8000ms; Extra block at 12000ms
- Attack scenario: Miners at 0ms, 4000ms, 4001ms
  - `baseMiningInterval` = 4000ms (miners[1] - miners[0])
  - Interval 2→3 = 1ms: `|1 - 4000| = 3999 <= 4000` ✓ Passes validation
  - `GetMiningInterval()` = 4000ms (uses only miners 1-2)
  - Extra block at 4001ms + 4000ms = 8001ms (instead of expected 12000ms)
  - Miner 3 receives only 1ms time slot instead of 4000ms
  - Extra block producer mines 3999ms earlier than intended

## Impact Explanation

**Severity: High**

This vulnerability breaks the fundamental fairness guarantee of the AEDPoS consensus protocol:

1. **Time Slot Manipulation**: Attackers can compress competing miners' time slots down to near-zero milliseconds while maintaining their own full 4000ms slots, gaining unfair block production advantage and potentially causing other miners to miss their slots entirely.

2. **Round Transition Control**: By manipulating the extra block mining time calculation, attackers can terminate rounds significantly earlier than intended (up to 3999ms in a 3-miner scenario), potentially front-running transactions or manipulating round-dependent logic.

3. **Mining Window Gaps/Overlaps**: Non-uniform actual intervals combined with uniform `GetMiningInterval()` calculations create periods where either no miner can legally mine (gaps) or multiple miners have overlapping windows, causing timing conflicts in the consensus mechanism.

4. **Consensus Integrity Violation**: The protocol's design assumes equal time slots for fairness in the DPoS model. This assumption is violated, compromising the security model where minority miners should have proportional mining opportunities. This undermines the core consensus layer upon which all on-chain security depends.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Must be an active miner (achievable through the election process by staking tokens)
- Must produce a NextRound block (occurs regularly as the extra block producer role rotates among all miners)
- Must run modified client code to generate malicious consensus data

**Complexity: Low**
- The modification is straightforward: craft a `NextRoundInput` with non-uniform `ExpectedMiningTime` values
- No complex cryptographic attacks or multi-step exploits required
- Validation bypass is trivial due to the 2x tolerance in `CheckRoundTimeSlots()`

**Detection Difficulty: Medium**
- Non-uniform intervals are visible on-chain but appear valid (within the 2x tolerance)
- Monitoring systems may not flag 2x variations as suspicious since they pass validation
- Attribution to a specific attacker is possible through on-chain analysis but requires detailed forensics

**Preconditions:**
- Attacker is elected as miner (realistic for actors willing to stake tokens)
- No additional privileges beyond miner list membership required

The attack is feasible for any malicious miner willing to run modified node software, which is a realistic threat model for consensus-level vulnerabilities in blockchain systems.

## Recommendation

**Option 1: Enforce Strict Uniformity in CheckRoundTimeSlots()**

Modify the validation to require near-exact equality between consecutive intervals rather than allowing 2x variation:

```csharp
// Replace the permissive check with strict tolerance (e.g., 100ms)
const int MaxToleranceMs = 100;
if (Math.Abs(miningInterval - baseMiningInterval) > MaxToleranceMs)
    return new ValidationResult { Message = "Time slots must be uniform." };
```

**Option 2: Fix GetMiningInterval() to Check All Intervals**

Modify `GetMiningInterval()` to validate uniformity across all consecutive miners and return the verified uniform interval:

```csharp
public int GetMiningInterval()
{
    if (RealTimeMinersInformation.Count == 1)
        return 4000;
    
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    var intervals = new List<int>();
    
    for (var i = 0; i < miners.Count - 1; i++)
    {
        intervals.Add((int)(miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds());
    }
    
    // Verify all intervals are the same
    var baseInterval = intervals[0];
    if (intervals.Any(interval => Math.Abs(interval - baseInterval) > 100))
        return 0; // Signal error
    
    return baseInterval;
}
```

**Option 3: Calculate Extra Block Time Using Actual Last Interval**

Modify `GetExtraBlockMiningTime()` to use the actual last miner's interval instead of `GetMiningInterval()`:

```csharp
public Timestamp GetExtraBlockMiningTime()
{
    var orderedMiners = RealTimeMinersInformation.OrderBy(m => m.Value.Order).ToList();
    var lastMiner = orderedMiners.Last().Value;
    
    if (orderedMiners.Count == 1)
        return lastMiner.ExpectedMiningTime.AddMilliseconds(4000);
    
    var secondLastMiner = orderedMiners[orderedMiners.Count - 2].Value;
    var actualLastInterval = (int)(lastMiner.ExpectedMiningTime - secondLastMiner.ExpectedMiningTime).Milliseconds();
    
    return lastMiner.ExpectedMiningTime.AddMilliseconds(actualLastInterval);
}
```

**Recommended Approach:** Implement Option 1 (strict uniformity enforcement) as it prevents the attack at the validation layer and maintains the simplicity of `GetMiningInterval()`. This ensures the protocol's fairness assumption is enforced by the contract itself.

## Proof of Concept

A proof of concept would involve:

1. Setting up an AEDPoS test environment with 3+ miners
2. Creating a modified NextRoundInput with non-uniform intervals (e.g., [0ms, 4000ms, 4001ms])
3. Submitting the NextRound transaction
4. Verifying that `CheckRoundTimeSlots()` passes (|4001-4000| = 3999 <= 4000)
5. Observing that `GetMiningInterval()` returns 4000ms (from miners 1-2)
6. Confirming `GetExtraBlockMiningTime()` calculates 8001ms instead of the expected uniform case of 12000ms
7. Demonstrating that Miner 3's time slot window is calculated incorrectly (4001ms + 4000ms instead of using the actual 1ms interval)

The test would confirm that the validation accepts non-uniform intervals while the timing calculations assume uniformity, creating the exploitable inconsistency.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L49-55)
```csharp
        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-19)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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
