# Audit Report

## Title
Integer Overflow in GetMiningInterval() Enables Consensus Disruption via Malicious Round Submission

## Summary
The `GetMiningInterval()` method performs an unsafe cast from `long` to `int` without overflow protection. A malicious miner can submit a `NextRoundInput` with `ExpectedMiningTime` intervals exceeding `int.MaxValue`, causing integer overflow that disrupts time slot validation and propagates to subsequent rounds, potentially halting consensus progression.

## Finding Description

The vulnerability exists in the interaction between round validation and mining interval retrieval in the AEDPoS consensus mechanism.

**Root Cause:**

The `GetMiningInterval()` method casts a `long` value from `Milliseconds()` to `int` without bounds checking: [1](#0-0) 

The `Milliseconds()` extension method can return values up to `long.MaxValue`: [2](#0-1) 

When the interval exceeds `int.MaxValue` (2,147,483,647 milliseconds ≈ 24.8 days), the cast produces a negative value due to two's complement overflow. Even after `Math.Abs()`, the resulting value is incorrect.

**Insufficient Validation:**

The `CheckRoundTimeSlots()` validation operates on `long` values and only validates that intervals are positive and relatively equal, without checking if they exceed `int` range: [3](#0-2) 

**Attack Execution Path:**

1. A malicious miner submits `NextRound` via the public method: [4](#0-3) 

2. The transaction passes through `ProcessConsensusInformation`: [5](#0-4) 

3. `TimeSlotValidationProvider` validates the new round by calling `CheckRoundTimeSlots()`: [6](#0-5) 

4. The round passes validation and gets stored: [7](#0-6) 

5. Subsequently, `CheckMinerTimeSlot()` calls the vulnerable `GetMiningInterval()` to calculate time slot boundaries: [8](#0-7) 

6. The overflowed interval corrupts the `endOfExpectedTimeSlot` calculation, causing legitimate miners to fail validation.

**Propagation Mechanism:**

The corrupted interval propagates to future rounds because `GenerateNextRoundInformation()` retrieves the mining interval and uses it to calculate `ExpectedMiningTime` for all miners in the next round: [9](#0-8) 

This creates a cascade effect where all subsequent rounds inherit the corrupted timing values.

## Impact Explanation

**Consensus Integrity Violation:**
The attack breaks the fundamental time slot validation mechanism. Legitimate miners fail `CheckMinerTimeSlot()` validation because the time slot window is calculated using the overflowed interval value. For example, if the actual interval should be 3,000,000,000 milliseconds (~35 days) but overflows to -1,294,967,296 (becoming 1,294,967,296 after `Math.Abs()`), the validation window shrinks from ~35 days to ~15 days, causing valid blocks to be rejected as "time slot already passed."

**Network-Wide Availability Impact:**
All honest miners are unable to produce valid blocks once the corrupted round becomes active. The blockchain cannot progress, transactions remain unconfirmed, and the entire network enters a halted state.

**Cascade and Persistence:**
The corrupted interval propagates through `GenerateNextRoundInformation()` to all subsequent rounds, making the issue persistent across multiple rounds. Recovery requires either governance intervention to update the consensus contract or manual chain state manipulation.

**Severity Assessment:**
This represents a high-impact consensus availability attack. While it requires miner privileges (medium barrier), the execution is straightforward, the impact is immediate and network-wide, and recovery is non-trivial.

## Likelihood Explanation

**Attacker Prerequisites:**
The attacker must be an active miner in the current or previous round's miner list, verified by `PreCheck()`: [10](#0-9) 

This is achievable for elected miners or during term transitions when the extra block producer submits the next round.

**Attack Complexity:**
Low. The attacker simply crafts a `NextRoundInput` protobuf message with `ExpectedMiningTime` timestamps spaced more than `int.MaxValue` milliseconds apart (e.g., 3,000,000,000 milliseconds). The message passes all validation logic because `CheckRoundTimeSlots()` validates intervals as `long` values.

**Execution Feasibility:**
- No special blockchain state required
- No timing constraints beyond being the designated next-round producer
- Single transaction execution
- Deterministic outcome

**Detection and Recovery:**
The attack becomes evident when subsequent blocks fail validation, but by then the corrupted round is already in state. There is no built-in recovery mechanism - it requires either a governance proposal to upgrade the consensus contract or manual intervention.

## Recommendation

Add bounds checking to prevent intervals from exceeding `int.MaxValue`:

**Option 1: Validate in CheckRoundTimeSlots()**
```csharp
public ValidationResult CheckRoundTimeSlots()
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

    var baseMiningInterval = (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

    if (baseMiningInterval <= 0)
        return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
    
    // ADD THIS CHECK
    if (baseMiningInterval > int.MaxValue)
        return new ValidationResult { Message = $"Mining interval exceeds maximum allowed value.\n{this}" };

    for (var i = 1; i < miners.Count - 1; i++)
    {
        var miningInterval = (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
        if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
            return new ValidationResult { Message = "Time slots are so different." };
    }

    return new ValidationResult { Success = true };
}
```

**Option 2: Change GetMiningInterval() to return long**
Modify the return type of `GetMiningInterval()` from `int` to `long` and update all call sites to handle `long` values. This is more invasive but eliminates the overflow entirely.

**Option 3: Add overflow checking in GetMiningInterval()**
```csharp
public int GetMiningInterval()
{
    if (RealTimeMinersInformation.Count == 1)
        return 4000;

    var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2).ToList();
    
    var intervalMs = (firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime).Milliseconds();
    
    // ADD OVERFLOW CHECK
    if (intervalMs > int.MaxValue || intervalMs < int.MinValue)
        return 4000; // fallback to default or throw exception
    
    return Math.Abs((int)intervalMs);
}
```

## Proof of Concept

```csharp
[Fact]
public async Task IntegerOverflow_InGetMiningInterval_DisruptsConsensus()
{
    // Setup: Initialize consensus with normal miners
    await InitializeCandidates();
    await InitialAElfConsensusContract();
    
    // Get current round
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Create malicious NextRoundInput with intervals > int.MaxValue
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation = new Dictionary<string, MinerInRound>()
    };
    
    var currentTime = TimestampHelper.GetUtcNow();
    var maliciousInterval = 3_000_000_000L; // 3 billion milliseconds (~35 days) > int.MaxValue
    
    var minerKeys = ValidationDataCenterKeyPairs.Select(k => k.PublicKey.ToHex()).OrderBy(x => x).ToList();
    for (int i = 0; i < minerKeys.Count; i++)
    {
        maliciousRound.RealTimeMinersInformation[minerKeys[i]] = new MinerInRound
        {
            Pubkey = minerKeys[i],
            Order = i + 1,
            ExpectedMiningTime = currentTime.AddMilliseconds((i + 1) * maliciousInterval),
            ProducedBlocks = 0,
            MissedTimeSlots = 0
        };
    }
    
    // Verify validation INCORRECTLY passes (vulnerability)
    var validationResult = maliciousRound.CheckRoundTimeSlots();
    validationResult.Success.ShouldBeTrue(); // This should fail but doesn't!
    
    // Submit malicious round as next-round producer
    var nextRoundInput = new NextRoundInput
    {
        RealTimeMinersInformation = maliciousRound.RealTimeMinersInformation
    };
    
    await BootMinerChangeRoundAsync(nextRoundInput);
    
    // Verify round was stored
    var storedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    storedRound.RoundNumber.ShouldBe(maliciousRound.RoundNumber);
    
    // Demonstrate overflow when retrieving mining interval
    var retrievedInterval = storedRound.GetMiningInterval();
    
    // Expected: 3,000,000,000 ms
    // Actual after overflow: Math.Abs((int)3_000_000_000) = 1,294,967,296 ms
    retrievedInterval.ShouldNotBe((int)maliciousInterval); // Proves overflow occurred
    retrievedInterval.ShouldBeLessThan(int.MaxValue); // Wrapped value is smaller
    
    // This breaks time slot validation for subsequent blocks
    // Legitimate miners will fail CheckMinerTimeSlot() validation
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L37-40)
```csharp
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L20-36)
```csharp
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
