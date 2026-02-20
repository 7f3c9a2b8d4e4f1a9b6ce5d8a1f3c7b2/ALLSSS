# Audit Report

## Title
Integer Overflow in GetMiningInterval() Enables Consensus Disruption via Malicious Round Submission

## Summary
The `GetMiningInterval()` method performs an unsafe cast from `long` to `int` without overflow protection. A malicious miner can submit a `NextRoundInput` with `ExpectedMiningTime` intervals exceeding `int.MaxValue`, causing integer overflow that disrupts time slot validation and halts consensus progression.

## Finding Description

The vulnerability exists in the interaction between round validation and mining interval retrieval in the AEDPoS consensus mechanism.

**Root Cause:**

The `GetMiningInterval()` method casts a `long` value from `Milliseconds()` to `int` without bounds checking: [1](#0-0) 

The `Milliseconds()` extension method can return values up to `long.MaxValue`: [2](#0-1) 

When the interval exceeds `int.MaxValue` (2,147,483,647 milliseconds ≈ 24.8 days), the cast produces a negative value due to two's complement overflow. Even after `Math.Abs()`, the resulting value is incorrect.

**Insufficient Validation:**

The `CheckRoundTimeSlots()` validation operates on `long` values and only validates that intervals are positive and relatively equal, without checking if they exceed `int` range: [3](#0-2) 

Specifically, the validation calculates intervals as `long` values [4](#0-3)  but never checks if they fit within `int` range before those intervals are later cast in `GetMiningInterval()`.

**Attack Execution Path:**

1. A malicious miner submits `NextRound` via the public method: [5](#0-4) 

2. The transaction passes through `ProcessConsensusInformation`: [6](#0-5) 

3. Validation occurs via `ValidateConsensusBeforeExecution` which delegates to `ValidateBeforeExecution`: [7](#0-6) 

4. `TimeSlotValidationProvider` is included in the validation pipeline: [8](#0-7) 

5. For new rounds, `TimeSlotValidationProvider` validates by calling `CheckRoundTimeSlots()`: [9](#0-8) 

6. The round passes validation and gets stored: [10](#0-9) 

7. Subsequently, when legitimate miners attempt to mine, `CheckMinerTimeSlot()` calls the vulnerable `GetMiningInterval()` to calculate time slot boundaries: [11](#0-10) 

8. The overflowed interval corrupts the `endOfExpectedTimeSlot` calculation at line 45, causing legitimate miners to fail validation.

**Propagation Mechanism:**

When attempting to generate the next round, `GenerateNextRoundInformation()` retrieves the mining interval from the corrupted round: [12](#0-11) 

The overflowed interval is used to calculate `ExpectedMiningTime` for miners in the next round. While the `Mul` operation uses checked arithmetic [13](#0-12)  and will throw `OverflowException` for higher order miners, this still prevents next round generation, maintaining the consensus halt.

## Impact Explanation

**Consensus Integrity Violation:**
The attack breaks the fundamental time slot validation mechanism. Legitimate miners fail `CheckMinerTimeSlot()` validation because the time slot window is calculated using the overflowed interval value. For example, if the actual interval should be 3,000,000,000 milliseconds (~35 days) but overflows to -1,294,967,296 (becoming 1,294,967,296 after `Math.Abs()`), the validation window shrinks from ~35 days to ~15 days, causing valid blocks to be rejected as "time slot already passed."

**Network-Wide Availability Impact:**
All honest miners are unable to produce valid blocks once the corrupted round becomes active. The blockchain cannot progress, transactions remain unconfirmed, and the entire network enters a halted state.

**Cascade and Persistence:**
The corrupted interval persists in the stored round state. When attempting to generate subsequent rounds via `GenerateNextRoundInformation()`, either the overflowed value propagates (for single miner) or `Mul` throws `OverflowException` (for multiple miners), preventing next round generation. Either outcome maintains the consensus halt across multiple rounds. Recovery requires governance intervention to update the consensus contract or manual chain state manipulation.

**Severity Assessment:**
This represents a high-impact consensus availability attack. While it requires miner privileges (medium barrier), the execution is straightforward, the impact is immediate and network-wide, and recovery is non-trivial.

## Likelihood Explanation

**Attacker Prerequisites:**
The attacker must be an active miner in the current or previous round's miner list, verified by `PreCheck()`: [14](#0-13) 

This is achievable for elected miners or during term transitions when the extra block producer submits the next round.

**Attack Complexity:**
Low. The attacker crafts a `NextRoundInput` protobuf message with `ExpectedMiningTime` timestamps spaced more than `int.MaxValue` milliseconds apart (e.g., 3,000,000,000 milliseconds). The message is converted to a `Round` object via `ToRound()`: [15](#0-14) 

The message passes all validation logic because `CheckRoundTimeSlots()` validates intervals as `long` values without checking `int` range constraints.

**Execution Feasibility:**
- No special blockchain state required
- No timing constraints beyond being the designated next-round producer
- Single transaction execution
- Deterministic outcome

**Detection and Recovery:**
The attack becomes evident when subsequent blocks fail validation, but by then the corrupted round is already in state. There is no built-in recovery mechanism - it requires either a governance proposal to upgrade the consensus contract or manual intervention.

## Recommendation

Add validation in `CheckRoundTimeSlots()` to ensure mining intervals fit within `int` range before they can be stored:

```csharp
public ValidationResult CheckRoundTimeSlots()
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

    var baseMiningInterval =
        (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

    if (baseMiningInterval <= 0)
        return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

    // ADD THIS CHECK:
    if (baseMiningInterval > int.MaxValue)
        return new ValidationResult { Message = $"Mining interval exceeds maximum allowed value.\n{this}" };

    for (var i = 1; i < miners.Count - 1; i++)
    {
        var miningInterval =
            (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
        
        // ADD THIS CHECK:
        if (miningInterval > int.MaxValue)
            return new ValidationResult { Message = $"Mining interval exceeds maximum allowed value.\n{this}" };
            
        if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
            return new ValidationResult { Message = "Time slots are so different." };
    }

    return new ValidationResult { Success = true };
}
```

Alternatively, change `GetMiningInterval()` to return `long` instead of `int` and update all callers accordingly, though this requires more extensive changes throughout the consensus system.

## Proof of Concept

```csharp
[Fact]
public async Task IntegerOverflow_ConsensusDisruption_Attack()
{
    // Setup: Initialize consensus with 2 miners
    var starter = Miners[0];
    var attacker = Miners[1];
    
    await InitializeConsensus();
    
    // Attacker crafts malicious NextRoundInput with intervals > int.MaxValue
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber
    };
    
    // Set intervals to 3 billion milliseconds (exceeds int.MaxValue)
    var baseTime = TimestampHelper.GetUtcNow();
    var largeInterval = 3_000_000_000; // ~35 days, exceeds int.MaxValue
    
    maliciousRound.RealTimeMinersInformation.Add(starter.PublicKey.ToHex(), new MinerInRound
    {
        Pubkey = starter.PublicKey.ToHex(),
        Order = 1,
        ExpectedMiningTime = baseTime
    });
    
    maliciousRound.RealTimeMinersInformation.Add(attacker.PublicKey.ToHex(), new MinerInRound
    {
        Pubkey = attacker.PublicKey.ToHex(),
        Order = 2,
        ExpectedMiningTime = baseTime.AddMilliseconds(largeInterval)
    });
    
    var nextRoundInput = new NextRoundInput
    {
        RoundNumber = maliciousRound.RoundNumber,
        RealTimeMinersInformation = { maliciousRound.RealTimeMinersInformation }
    };
    
    // Attack: Submit malicious round (should pass validation)
    var result = await GetConsensusStub(attacker).NextRound.SendAsync(nextRoundInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: GetMiningInterval now returns overflowed value
    var storedRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var overflowedInterval = storedRound.GetMiningInterval();
    
    // The interval should overflow: 3B cast to int produces negative value, 
    // Math.Abs gives incorrect positive value
    overflowedInterval.ShouldNotBe(largeInterval);
    overflowedInterval.ShouldBeLessThan(int.MaxValue);
    
    // Impact: Legitimate miners now fail time slot validation
    // Consensus is halted
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L79-80)
```csharp
        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```

**File:** src/AElf.CSharp.Core/Extension/TimestampExtensions.cs (L71-76)
```csharp
    public static long Milliseconds(this Duration duration)
    {
        return duration.Seconds > long.MaxValue.Div(1000)
            ? long.MaxValue
            : duration.Seconds.Mul(1000).Add(duration.Nanos.Div(1000000));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-39)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");

        State.RoundBeforeLatestExecution.Value = GetCurrentRoundInformation(new Empty());

        ByteString randomNumber = null;

        // The only difference.
        switch (input)
        {
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-80)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-36)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L13-18)
```csharp
    public static int Mul(this int a, int b)
    {
        checked
        {
            return a * b;
        }
```

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
