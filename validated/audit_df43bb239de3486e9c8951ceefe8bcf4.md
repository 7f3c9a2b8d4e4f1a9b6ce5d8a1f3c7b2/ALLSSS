# Audit Report

## Title
Premature Round Termination Allows Miner Exclusion and Consensus Liveness Violation

## Summary
The AEDPoS consensus protocol allows any miner whose time slot has passed to terminate the current round prematurely by submitting a NextRound transaction, even before the designated extra block mining time is reached. This enables censorship attacks against miners with later time slots and violates fundamental consensus liveness guarantees.

## Finding Description

The vulnerability exists in the consensus command generation and validation flow where timing constraints for round termination are not properly enforced.

**Root Cause - Command Generation:**

When a miner has already produced their block (OutValue != null) and their individual time slot has passed, the behavior provider unconditionally returns NextRound/NextTerm behavior. [1](#0-0) 

The time slot check only verifies if the individual miner's own slot has ended, not whether the round should legitimately terminate. [2](#0-1) 

**Missing Validation - No Extra Block Time Check:**

The validation pipeline for NextRound transactions applies multiple validators but none enforce extra block timing. [3](#0-2) 

The TimeSlotValidationProvider only validates that the NEW round's time slots are properly arranged when RoundId differs, without checking if the current time allows terminating the old round. [4](#0-3) 

The RoundTerminateValidationProvider only checks that round numbers increment correctly and InValues are null, without any timing validation. [5](#0-4) 

The NextRoundMiningOrderValidationProvider only validates consistency between FinalOrderOfNextRound and miners who produced blocks. [6](#0-5) 

**Extra Block Time Definition:**

The protocol defines extra block mining time as the last miner's expected time plus one mining interval, representing when rounds should legitimately end. [7](#0-6) 

**Critical Gap:**

While the IsCurrentMiner view method correctly validates extra block timing and producer designation, this logic is not used in the validation pipeline during block execution. [8](#0-7) 

**Attack Execution:**
1. Attacker (a legitimate miner at position 3 of 5) produces their block
2. Attacker's time slot ends
3. Miners at positions 4 and 5 have not yet produced blocks
4. Extra block mining time has not been reached
5. Attacker generates NextRound command and submits transaction
6. All validators pass (no timing enforcement)
7. ProcessNextRound executes, terminating the round
8. Miners 4 and 5 are excluded from producing blocks

## Impact Explanation

**Consensus Integrity Violation:**
The attack directly violates the AEDPoS protocol's liveness guarantee that all active miners receive their allocated time slot. Miners scheduled for later positions are systematically denied their opportunity to produce blocks and participate in consensus.

**Censorship Attack Vector:**
A malicious miner can repeatedly target specific miners by terminating rounds before their time slots arrive. This reduces the effective validator set without formal removal through governance, enabling sustained censorship of targeted participants.

**Network Security Degradation:**
Fewer blocks per round means reduced network security and blockchain throughput. The concentration of block production among early-slot miners increases centralization risk and reduces the protocol's Byzantine fault tolerance in practice.

**Economic Impact:**
Excluded miners lose block rewards and transaction fees for their skipped time slots. This creates unfair economic advantages for miners with earlier time slots and could drive honest miners to exit the network, further reducing decentralization.

Severity: **HIGH** - Directly compromises consensus correctness, enables censorship, and violates fundamental protocol guarantees.

## Likelihood Explanation

**Attack Feasibility:**
The attack requires only standard miner privileges—no special authority, governance control, or technical sophistication. Any active miner can execute the attack by simply submitting a NextRound transaction after their time slot ends.

**Realistic Preconditions:**
- Attacker must be in current round's miner list (standard for any active miner)
- Attacker must have produced their block (normal operation)
- Attacker's time slot must have passed (inevitable as rounds progress)
- At least one later miner must not have produced yet (common with network latency)

**Natural Occurrence:**
Network latency, temporary node issues, or processing delays naturally create situations where some miners haven't produced blocks when earlier miners' slots end. These conditions occur frequently in real-world distributed systems.

**Detection Difficulty:**
The attack is indistinguishable from legitimate round termination in transaction logs. Network observers would likely attribute early termination to slow or offline miners rather than malicious behavior, as there is no obvious on-chain evidence of intent.

Probability: **HIGH** - The exploit conditions occur naturally during normal network operation, requiring no special circumstances or resources.

## Recommendation

Add validation to enforce proper round termination timing. The RoundTerminateValidationProvider should verify:

1. **Extra Block Time Constraint:** For NextRound behavior, validate that current block time has reached or exceeded the extra block mining time
2. **Producer Authorization:** Verify the transaction sender is the designated extra block producer (IsExtraBlockProducer field) when terminating rounds
3. **Time Slot Coverage:** Ensure all miners have had their allocated time slots before allowing round termination

Implementation approach:
```csharp
// In RoundTerminateValidationProvider.ValidationForNextRound()
// Add after line 29:

var extraBlockMiningTime = validationContext.BaseRound.GetExtraBlockMiningTime();
if (validationContext.CurrentBlockTime < extraBlockMiningTime)
    return new ValidationResult { 
        Message = "Cannot terminate round before extra block mining time." 
    };

var extraBlockProducer = validationContext.BaseRound.RealTimeMinersInformation
    .Single(m => m.Value.IsExtraBlockProducer).Key;
if (validationContext.SenderPubkey != extraBlockProducer)
    return new ValidationResult { 
        Message = "Only extra block producer can terminate round." 
    };
```

## Proof of Concept

The vulnerability can be demonstrated by examining the validation flow:

1. Set up a round with 5 miners where miner 3 has completed their block
2. Advance time past miner 3's slot but before extra block time
3. Have miner 3 call GetConsensusCommand → returns NextRound behavior
4. Submit NextRound transaction from miner 3
5. Observe that ValidateBeforeExecution passes all checks
6. Observe that ProcessNextRound executes successfully
7. Verify that miners 4 and 5 never received their time slots
8. Confirm round terminated prematurely before extra block time

The test would validate that:
- No validator rejects the premature NextRound transaction
- The round terminates before the calculated extra block time
- Later-scheduled miners are excluded from block production
- No error or revert occurs despite violating round timing constraints

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L49-82)
```csharp
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
            }

            return GetConsensusBehaviourToTerminateCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L83-99)
```csharp
    public bool IsTimeSlotPassed(string publicKey, Timestamp currentBlockTime)
    {
        var miningInterval = GetMiningInterval();
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
        if (RoundNumber != 1)
            return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } <
                   currentBlockTime;

        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;

        var actualStartTime = actualStartTimes.First();
        var runningTime = currentBlockTime - actualStartTime;
        var expectedOrder = runningTime.Seconds.Div(miningInterval.Div(1000)).Add(1);
        return minerInRound.Order < expectedOrder;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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
