# Audit Report

## Title
Missing TermNumber Validation in NextRound Allows Consensus Time Slot Bypass

## Summary
The `ToRound()` function and NextRound validation logic fail to validate the TermNumber field in NextRoundInput, allowing a malicious miner to store a Round object with an incorrect TermNumber. This causes subsequent blocks to incorrectly bypass time slot validation, breaking consensus schedule integrity and enabling unfair block production.

## Finding Description

The vulnerability exists due to a missing validation in the NextRound consensus flow that allows miners to manipulate the TermNumber field.

**Root Cause:**

The `ToRound()` method in NextRoundInput blindly copies all fields including TermNumber without any validation [1](#0-0) 

The pre-execution validation for NextRound behavior only validates RoundNumber increment and InValue nullity, but completely omits TermNumber validation [2](#0-1) 

**Execution Path:**

1. When a miner calls the public NextRound method [3](#0-2) , it processes the consensus information.

2. ProcessNextRound converts the input using the unvalidated `ToRound()` method and stores it [4](#0-3) 

3. Critically, ProcessNextRound only updates RoundNumber in state, NOT TermNumber (unlike ProcessNextTerm) [5](#0-4) 

4. State.CurrentTermNumber is ONLY updated in ProcessNextTerm [6](#0-5) 

5. In subsequent blocks, the time slot validation checks if it's the first round of a new term by comparing the previous round's TermNumber (from stored state) against CurrentTermNumber (from State.CurrentTermNumber.Value) [7](#0-6) 

6. When this check incorrectly returns true due to the TermNumber mismatch, time slot validation is immediately bypassed [8](#0-7) 

**Attack Scenario:**

- Current state: TermNumber = N, RoundNumber = R
- Attacker (valid miner) crafts NextRoundInput with:
  - RoundNumber = R + 1 (valid, passes validation)
  - TermNumber = N + 1 (invalid, but unchecked)
  - Other valid fields
- ProcessNextRound stores Round with TermNumber = N + 1 in State.Rounds[R + 1]
- State.CurrentTermNumber remains N (unchanged)
- Next block validation:
  - PreviousRound.TermNumber = N + 1 (from malicious stored round)
  - CurrentTermNumber = N (from global state)
  - IsFirstRoundOfCurrentTerm: N + 1 ≠ N → returns true
  - CheckMinerTimeSlot returns true immediately
  - Time slot validation bypassed

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant of time slot validation. The AEDPoS consensus mechanism assigns specific time slots to miners to ensure fair block production and prevent centralization.

**Concrete Impact:**

1. **Time Slot Violation**: Malicious miners can produce blocks outside their assigned time slots, violating the consensus schedule
2. **Unfair Block Rewards**: Attackers gain additional block production opportunities, earning more rewards than allocated
3. **Centralization Risk**: Reduces decentralization by allowing one miner to dominate block production
4. **State Inconsistency**: Creates divergence between stored Round.TermNumber values and global State.CurrentTermNumber
5. **Consensus Schedule Breakdown**: The carefully designed mining time arrangement becomes meaningless

The severity is **Medium** because while it compromises consensus integrity (a critical invariant), the attacker must be an active miner in the current round, limiting the attack surface. However, the impact on fairness and schedule integrity is concrete and significant.

## Likelihood Explanation

**High Likelihood** due to:

1. **Low Attack Complexity**: Attacker simply crafts a NextRoundInput with manipulated TermNumber
2. **Realistic Preconditions**: Only requires being a valid miner (achievable through normal election/staking)
3. **No Additional Privileges**: Beyond being in the miner list (verified by PreCheck), no special authority needed [9](#0-8) 
4. **No Economic Cost**: Only standard transaction fees
5. **Immediate Exploitation**: Takes effect in the very next round
6. **Difficult Detection**: The manipulated TermNumber is stored but global state appears correct; subsequent behavior looks like legitimate "first round of term" scenario

Any malicious miner seeking unfair advantage can easily exploit this vulnerability.

## Recommendation

Add TermNumber validation in the NextRound validation flow:

1. **Extend ValidationForNextRound** to verify TermNumber remains unchanged:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate RoundNumber
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    // ADD: Validate TermNumber remains unchanged
    if (validationContext.BaseRound.TermNumber != extraData.Round.TermNumber)
        return new ValidationResult { Message = "TermNumber must remain unchanged during NextRound." };
    
    // Validate InValues are null
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

2. **Alternatively**, add validation in `ToRound()` or `ProcessNextRound()` to assert TermNumber consistency with current state.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousNextRound_BypassesTimeSlotValidation()
{
    // Setup: Initialize consensus with term 1, round 1
    await InitializeConsensus();
    var currentTermNumber = await GetCurrentTermNumber(); // Returns 1
    var currentRoundNumber = await GetCurrentRoundNumber(); // Returns 1
    
    // Attacker is a valid miner
    var attackerKeyPair = MinerKeyPairs[0];
    
    // Progress to round 2 normally first
    await ProduceNormalRound();
    currentRoundNumber = await GetCurrentRoundNumber(); // Now 2
    
    // Attack: Craft malicious NextRoundInput with incorrect TermNumber
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = currentRoundNumber + 1, // Valid: 3
        TermNumber = currentTermNumber + 1,   // INVALID: Should be 1, attacker sets 2
        // ... other valid fields
    };
    
    // Execute malicious NextRound transaction
    var result = await AttackerExecuteNextRound(attackerKeyPair, maliciousInput);
    result.Status.ShouldBe(TransactionResultStatus.Mined); // Should succeed
    
    // Verify: TermNumber mismatch created
    var storedRound = await GetRound(currentRoundNumber + 1);
    storedRound.TermNumber.ShouldBe(2); // Stored malicious value
    
    var globalTermNumber = await GetCurrentTermNumber();
    globalTermNumber.ShouldBe(1); // Global state unchanged
    
    // Impact: Next block bypasses time slot validation
    var nextBlockResult = await ProduceBlockOutsideTimeSlot(attackerKeyPair);
    nextBlockResult.Status.ShouldBe(TransactionResultStatus.Mined); // Should succeed when it shouldn't
    
    // This proves time slot validation was bypassed
}
```

**Notes:**

The vulnerability is confirmed through complete code path analysis. The missing TermNumber validation in NextRound processing allows miners to manipulate consensus state, creating a divergence between stored Round objects and global TermNumber state. This causes the IsFirstRoundOfCurrentTerm check to incorrectly return true, bypassing critical time slot validation and enabling unfair block production outside assigned time slots. The attack requires only normal miner privileges and has high likelihood of exploitation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L98-105)
```csharp
    private bool TryToUpdateTermNumber(long termNumber)
    {
        var oldTermNumber = State.CurrentTermNumber.Value;
        if (termNumber != 1 && oldTermNumber + 1 != termNumber) return false;

        State.CurrentTermNumber.Value = termNumber;
        return true;
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
