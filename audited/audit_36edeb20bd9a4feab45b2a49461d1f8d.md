### Title
Duplicate Mining Order Validation Bypass Allows Consensus Schedule Corruption

### Summary
The `NextRoundMiningOrderValidationProvider` validation logic incorrectly applies `.Distinct()` to miner objects instead of their `FinalOrderOfNextRound` values, allowing a malicious miner to provide next-round data where multiple miners share the same mining order. This breaks the fundamental consensus invariant of unique order assignments and causes unpredictable behavior in mining schedule logic.

### Finding Description

**Code Location:** [1](#0-0) 

**Root Cause:**
The validation performs `.Distinct()` on `MinerInRound` objects rather than on their `FinalOrderOfNextRound` integer values. Since `RealTimeMinersInformation.Values` already contains distinct miner objects (from a dictionary), this check becomes meaningless for detecting duplicate order values. The protobuf-generated `MinerInRound` class equality compares all fields, so two miners with identical orders but different pubkeys are considered distinct objects.

**Why Protection Fails:**
The check at line 17 compares:
- Count of distinct `MinerInRound` objects with `FinalOrderOfNextRound > 0`
- Count of miners with `OutValue != null` (who produced blocks)

This passes even when multiple miners have the same order value (e.g., two miners both with order 1), as long as the number of mining miners equals the number with assigned orders.

**Execution Path:**
1. Miner triggers `NextRound` consensus behavior [2](#0-1) 
2. Validation pipeline includes `NextRoundMiningOrderValidationProvider` 
3. Malicious `NextRoundInput` passes validation despite duplicate orders
4. Invalid round data stored directly via `ProcessNextRound` [3](#0-2) 
5. The provided round becomes authoritative state [4](#0-3) 

### Impact Explanation

**Consensus Integrity Compromise:**
Multiple critical consensus functions assume order uniqueness and use `.First(m => m.Order == X)` lookups:
- Extra block producer selection becomes unpredictable [5](#0-4) 
- `BreakContinuousMining` logic fails to correctly swap miners [6](#0-5) 
- Mining interval calculation may select wrong miner pairs [7](#0-6) 

**Mining Schedule Corruption:**
- Duplicate orders create time slot conflicts (multiple miners with same `ExpectedMiningTime`)
- Order sequence gaps emerge (e.g., [1, 1, 3, 4, 5] leaves no order 2)
- Consensus round progression becomes non-deterministic

**Affected Parties:**
- All network nodes experience consensus disruption
- Honest miners may lose block production opportunities
- Chain liveness can be degraded or halted

**Severity:** High - Violates critical "miner schedule integrity" invariant, directly exploitable to corrupt consensus state.

### Likelihood Explanation

**Attacker Capabilities:**
Any active mining node in the consensus set can execute this attack when it's their turn to propose `NextRound`.

**Attack Complexity:**
Low - Attacker simply crafts a `NextRoundInput` message with duplicate `FinalOrderOfNextRound` values while maintaining correct counts and reasonable time intervals to bypass other validation checks.

**Feasibility Conditions:**
- Attacker must be in the current miner list (normal miner requirement)
- Must have mining turn to submit `NextRound` transaction
- Can set arbitrary order values in the provided round data [8](#0-7) 

**Economic Rationality:**
Zero cost to execute - mining nodes already pay gas for legitimate `NextRound` transactions. Attack provides strategic advantage by disrupting competitor mining schedules.

**Detection Constraints:**
The invalid state persists in storage and affects all subsequent round logic, making detection difficult until consensus anomalies manifest.

**Probability:** High - Simple exploit, no special privileges needed beyond being a miner, can be executed repeatedly.

### Recommendation

**Code-Level Mitigation:**
Modify the validation to check for unique order values:

```csharp
var ordersAssigned = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
var distinctOrderCount = ordersAssigned.Distinct().Count();
if (distinctOrderCount != ordersAssigned.Count || 
    distinctOrderCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
{
    validationResult.Message = "Invalid FinalOrderOfNextRound: duplicate or missing orders.";
    return validationResult;
}
```

**Additional Invariant Checks:**
1. Verify orders form contiguous sequence [1..N] or explicitly allow gaps with documentation
2. Cross-validate `ExpectedMiningTime` matches calculated time from order
3. Add assertion that `ordersAssigned.Min() == 1 && ordersAssigned.Max() == distinctOrderCount`

**Test Cases:**
1. Test rejection of duplicate orders (two miners with order 1)
2. Test rejection of order gaps with all miners mining (e.g., orders [1, 3, 4, 5])
3. Test acceptance of valid unique order assignments
4. Regression test ensuring `.Select(m => m.FinalOrderOfNextRound).Distinct()` is used

### Proof of Concept

**Required Initial State:**
- 5 active miners in consensus set: A, B, C, D, E
- Current round where miners A, B, C produced blocks
- Miner A has turn to propose `NextRound`

**Attack Steps:**
1. Miner A constructs `NextRoundInput` with:
   - Miner A: `FinalOrderOfNextRound = 1`, `ExpectedMiningTime = T+4000ms`, `OutValue != null`
   - Miner B: `FinalOrderOfNextRound = 1`, `ExpectedMiningTime = T+8000ms`, `OutValue != null` (DUPLICATE ORDER)
   - Miner C: `FinalOrderOfNextRound = 3`, `ExpectedMiningTime = T+12000ms`, `OutValue != null`
   - Miner D: `FinalOrderOfNextRound = 2`, no OutValue
   - Miner E: `FinalOrderOfNextRound = 4`, no OutValue

2. Submit `NextRound` transaction with crafted input

**Expected vs Actual Result:**
- **Expected:** Validation rejects due to duplicate order 1
- **Actual:** Validation passes because:
  - Distinct miner count (A, B, C) = 3 ✓
  - Miners with OutValue (A, B, C) = 3 ✓
  - Time slots properly spaced ✓

**Success Condition:**
Transaction succeeds, round stored with miners A and B both having Order = 1. Subsequent calls to `.First(m => m.Order == 1)` return non-deterministic results between A and B.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L59-65)
```csharp
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.gs (L79-89)
```text

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```
