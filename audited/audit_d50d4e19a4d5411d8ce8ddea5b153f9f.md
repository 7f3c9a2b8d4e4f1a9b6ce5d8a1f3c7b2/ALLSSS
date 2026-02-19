# Audit Report

## Title
Missing Absolute Time Validation in NextRound Allows Consensus Timing Manipulation

## Summary
The `CheckRoundTimeSlots()` validation function only validates relative intervals between consecutive miners but never validates absolute timing against `Context.CurrentBlockTime`. A malicious miner can propose a NextRound with arbitrarily shifted time slots as long as inter-miner intervals remain consistent, allowing consensus timing manipulation.

## Finding Description

The vulnerability exists in the NextRound validation flow where absolute timing is never verified against the current block timestamp.

**Root Cause:**

The `CheckRoundTimeSlots()` method validates only relative intervals between miners: [1](#0-0) 

The validation calculates a `baseMiningInterval` from the first two miners and then checks that all subsequent intervals are within tolerance. However, it never validates:
1. Whether `miners[0].ExpectedMiningTime` (the round start time) is correct relative to `Context.CurrentBlockTime`
2. Whether the absolute `ExpectedMiningTime` values match what `GenerateNextRoundInformation` would produce
3. Whether the total round duration is correct

**Validation Flow:**

When NextRound behavior is detected, the validation adds `TimeSlotValidationProvider`: [2](#0-1) 

The `TimeSlotValidationProvider` calls `CheckRoundTimeSlots()` for new rounds: [3](#0-2) 

**Expected vs. Actual:**

The normal round generation correctly uses `Context.CurrentBlockTime` as the base: [4](#0-3) 

The generated round calculates `ExpectedMiningTime` properly: [5](#0-4) 

However, when a miner provides a `NextRoundInput`, the validation never compares the provided times against what this generation logic would produce. The provided round is simply stored: [6](#0-5) 

## Impact Explanation

**Consensus Integrity Violation:**

A malicious miner can craft a `NextRoundInput` with all `ExpectedMiningTime` values shifted by an arbitrary constant (e.g., +100 seconds). As long as the relative intervals remain consistent, `CheckRoundTimeSlots()` validation passes because it only checks that `Math.Abs(miningInterval - baseMiningInterval) <= baseMiningInterval`.

**Concrete Harms:**
1. **Timing Manipulation**: The attacker can delay round transitions arbitrarily, gaining strategic advantages in block production timing
2. **Unfair Advantages**: Specific miners can receive extended effective time slots within tolerance bounds, increasing their block production probability
3. **Protocol Degradation**: The manipulated timing breaks the invariant that rounds start predictably at `Context.CurrentBlockTime + miningInterval * order`, degrading consensus fairness

**Severity: Medium** - While this doesn't directly steal funds, it breaks critical consensus timing invariants that ensure fair block production and proper round transitions, affecting all network participants.

## Likelihood Explanation

**Attacker Capabilities:**
- Any miner who is the extra block producer can call `NextRound`: [7](#0-6) 
- No special privileges required beyond being in the miner list
- Attack is deterministic and repeatable

**Attack Complexity:**
- Low complexity: Attacker constructs `NextRoundInput` with manipulated `ExpectedMiningTime` values
- All inter-miner intervals kept within tolerance (difference < baseMiningInterval)
- Passes all validation providers including `TimeSlotValidationProvider` and `RoundTerminateValidationProvider`

**Feasibility:**
- Attack executes through normal NextRound transaction flow
- No race conditions or timing dependencies
- Manipulation persists in state after successful execution

**Probability: High** - Any malicious miner has both incentive and capability to execute this attack for competitive advantage.

## Recommendation

Add absolute time validation in the NextRound validation flow. Create a new validation provider or enhance `TimeSlotValidationProvider` to:

1. Regenerate the expected next round using `GenerateNextRoundInformation(baseRound, Context.CurrentBlockTime, out var expectedRound)`
2. Compare the provided round's `GetRoundStartTime()` against the expected round's start time
3. Validate that all miners' `ExpectedMiningTime` values are within a reasonable tolerance (e.g., a few seconds) of the expected values

Example validation logic:
```csharp
// In TimeSlotValidationProvider or a new AbsoluteTimeValidationProvider
var expectedStartTime = Context.CurrentBlockTime; // or with small offset
var providedStartTime = validationContext.ProvidedRound.GetRoundStartTime();
var tolerance = validationContext.BaseRound.GetMiningInterval() / 2;

if (Math.Abs((providedStartTime - expectedStartTime).Milliseconds()) > tolerance)
{
    return new ValidationResult 
    { 
        Message = "NextRound start time deviates significantly from expected time based on CurrentBlockTime" 
    };
}
```

## Proof of Concept

I cannot provide a runnable PoC test due to tool limitations (no ability to create and execute test files). However, the vulnerability can be demonstrated by:

1. Creating a test that obtains current round information
2. Crafting a `NextRoundInput` where all `ExpectedMiningTime` values are shifted by +100 seconds
3. Maintaining all relative intervals (e.g., 4000ms between consecutive miners)
4. Submitting the `NextRound` transaction
5. Observing that validation passes despite the absolute time shift
6. Verifying the manipulated round is stored in state

The key assertion would be that `CheckRoundTimeSlots()` returns `Success = true` even when absolute times are manipulated, as it only validates relative intervals per the code at [8](#0-7) 

## Notes

This vulnerability is particularly concerning because:
1. The validation gap is systematic - it applies to every NextRound transition
2. The manipulated timing becomes the authoritative schedule for the entire round
3. There is no on-chain detection mechanism
4. The attack appears as legitimate consensus behavior since all relative checks pass

The root issue is that validation assumes provided rounds are honestly generated using the correct base timestamp, but never enforces this assumption.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-156)
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
