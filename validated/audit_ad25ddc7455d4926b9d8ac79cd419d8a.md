# Audit Report

## Title
Missing Order Value Validation in NextTerm Allows Consensus DoS via Malformed Round Data

## Summary
The AEDPoS consensus contract lacks Order value validation during NextTerm transitions, allowing a malicious block producer to inject Round data with invalid Order values (e.g., zero). This corrupts consensus state and causes exceptions in subsequent blocks, halting block production chain-wide.

## Finding Description

The vulnerability stems from a validation asymmetry between NextRound and NextTerm consensus behaviors.

**Validation Gap:**

For NextTerm behavior, only `RoundTerminateValidationProvider` is added to the validation pipeline, which validates only round and term number increments. [1](#0-0) 

The provider's implementation confirms it performs no Order value validation: [2](#0-1) 

In contrast, NextRound behavior includes `NextRoundMiningOrderValidationProvider` which validates mining order information: [3](#0-2) 

**Unvalidated Data Flow:**

The `NextTermInput.Create()` method directly copies `RealTimeMinersInformation` without validation: [4](#0-3) 

During NextTerm processing, this data is converted back to a Round object and stored directly into state: [5](#0-4) 

The storage operation performs no validation: [6](#0-5) 

**Attack Vector:**

A malicious miner producing a NextTerm transition block can modify their node software to inject malformed consensus extra data with Order = 0 for all miners, bypassing the normal generation logic that correctly assigns sequential Order values: [7](#0-6) 

**Critical Failure Point:**

Once corrupted Round data is stored, subsequent block validation triggers an exception. The `GetMiningInterval()` method filters miners by Order and accesses array indices without bounds checking: [8](#0-7) 

With Order = 0, the filtered list is empty, causing `IndexOutOfRangeException` when accessing `firstTwoMiners[1]`. This method is called during time slot validation for every block: [9](#0-8) 

Additional failure occurs in `BreakContinuousMining()` which uses `.First(i => i.Order == 1)`: [10](#0-9) 

## Impact Explanation

**Severity: Critical - Complete Consensus Halt**

Once a malicious NextTerm block with Order = 0 is accepted and stored in state:

1. The next block's validation calls `TimeSlotValidationProvider.CheckMinerTimeSlot()`
2. This invokes `GetMiningInterval()` on the corrupted Round stored in state
3. The method throws `IndexOutOfRangeException` due to empty filtered list
4. Block validation fails for all subsequent blocks across all nodes
5. **Consensus permanently halts**

The impact is immediate and affects:
- Block production and validation (complete halt)
- Transaction processing (no new blocks)
- All dependent operations (transfers, smart contract calls, governance)

Recovery requires manual intervention such as chain rollback, state migration, or emergency protocol upgrade. This breaks the fundamental consensus invariant that Order values must be sequential positive integers starting from 1.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Must be an active miner in the current term (achievable through election process)
- Must be scheduled to produce a NextTerm transition block (happens periodically through rotation)
- Must modify node software to inject malformed consensus data (technically straightforward)

**Feasibility:**
The attack is feasible because:
1. Miners control consensus extra data included in blocks they produce
2. Validation has a documented gap - no Order value checking for NextTerm
3. Modification requires only bypassing local data generation
4. Any miner eventually gets scheduled for NextTerm blocks

**Realistic Scenarios:**
- Compromised miner node (malware/remote exploit)
- Malicious insider miner attempting network disruption
- Buggy node software update inadvertently generating invalid Order values
- Economic attack by competitor to halt chain operations

**Detection:**
The attack is detectable only after execution when exceptions appear in validation logs, but corrupted state is already persisted and damage complete.

## Recommendation

Add Order value validation to the NextTerm validation pipeline:

1. Create an `OrderValueValidationProvider` that verifies:
   - All miners have Order values > 0
   - Order values form a contiguous sequence from 1 to N
   - No duplicate Order values exist

2. Add this provider to the NextTerm validation chain alongside `RoundTerminateValidationProvider` in `AEDPoSContract_Validation.cs`

3. Alternatively, add Order validation directly in `RoundTerminateValidationProvider.ValidationForNextTerm()`:
```csharp
// Validate Order values
var orders = extraData.Round.RealTimeMinersInformation.Values.Select(m => m.Order).OrderBy(o => o).ToList();
if (orders.Count == 0 || orders[0] != 1 || orders[orders.Count - 1] != orders.Count)
    return new ValidationResult { Message = "Invalid Order values in NextTerm round." };
```

## Proof of Concept

A test demonstrating the vulnerability would:

1. Generate a valid NextTerm input with proper miner list
2. Manually corrupt all Order values to 0 in the Round's RealTimeMinersInformation
3. Call `NextTerm()` with this corrupted input
4. Observe that validation passes and corrupted Round is stored
5. Attempt to call `GetMiningInterval()` on the stored Round
6. Confirm `IndexOutOfRangeException` is thrown

The key vulnerability is that step 3 succeeds when it should fail - NextTerm validation does not reject Order = 0 values, allowing consensus state corruption that causes subsequent failures.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
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

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L23-37)
```csharp
        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L73-90)
```csharp
    private void BreakContinuousMining(ref Round nextRound)
    {
        var minersCount = RealTimeMinersInformation.Count;
        if (minersCount <= 1) return;

        // First miner of next round != Extra block producer of current round
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```
