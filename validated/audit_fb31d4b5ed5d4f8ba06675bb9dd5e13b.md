# Audit Report

## Title
Consensus Denial of Service via Missing Order Validation in NextRound Processing

## Summary
The AEDPoS consensus contract lacks validation to ensure miner Order 1 exists when processing `NextRound` inputs. A malicious miner can submit a round with order assignments [2, 3, 4, 5...] that passes all validation checks, causing `NullReferenceException` or `IndexOutOfRangeException` when any miner attempts to obtain consensus commands, permanently halting the blockchain.

## Finding Description

The `FirstMiner()` method returns the result of `FirstOrDefault(m => m.Order == 1)` on `RealTimeMinersInformation`. Since `MinerInRound` is a reference type, this returns `null` when no miner has `Order == 1`. [1](#0-0) 

This null result is dereferenced without checks at multiple critical points:

**Crash Point 1:** The behavior provider's `HandleMinerInNewRound()` method directly accesses `CurrentRound.FirstMiner().OutValue`. [2](#0-1) 

**Crash Point 2:** `IsTimeSlotPassed()` accesses `FirstMiner().ActualMiningTimes` for round 1 checks. [3](#0-2) 

**Crash Point 3:** `GetRoundStartTime()` directly returns `FirstMiner().ExpectedMiningTime`. [4](#0-3) 

**Crash Point 4:** `GetMiningInterval()` filters for Order 1 or 2, then accesses index [1] without bounds checking. [5](#0-4) 

The attack exploits a validation gap. The public `NextRound()` method accepts `NextRoundInput` and processes it through validation. [6](#0-5) 

Authorization only requires the sender to be in the current or previous miner list. [7](#0-6) 

The `ToRound()` conversion simply copies `RealTimeMinersInformation` without validating order integrity. [8](#0-7) 

The validation providers for `NextRound` behavior do not check for Order 1 existence. [9](#0-8) 

The `CheckRoundTimeSlots()` method orders miners by their `Order` field but never verifies that Order 1 exists or that orders are sequential. [10](#0-9) 

When miners have Orders [2, 3, 4, 5], this validation sorts them, checks intervals between consecutive miners, and passes. After the malicious round is saved via `ProcessNextRound()`, any subsequent call to `GetConsensusCommand()` crashes. [11](#0-10) 

The behavior provider is instantiated during consensus command generation, triggering the crash in its constructor when calling `IsTimeSlotPassed()`, which calls `GetMiningInterval()`. [12](#0-11) 

## Impact Explanation

This is a **Critical** severity consensus denial of service vulnerability. When the malicious round becomes the current round, all miners attempting to obtain consensus commands encounter unhandled exceptions. Since consensus command generation is required for all block production, the blockchain halts completely with:

1. **Complete Availability Loss:** No blocks can be produced by any miner
2. **Network-Wide Impact:** All network participants are affected simultaneously
3. **No Automatic Recovery:** The blockchain remains halted until manual intervention (state rollback or hard fork)
4. **Consensus Integrity Violation:** Breaks the fundamental guarantee that valid miners can produce blocks during their time slots

The attack bypasses all existing validation mechanisms and causes permanent consensus failure once executed.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires the attacker to be an active miner (elected through normal consensus), which raises the barrier. However, once this prerequisite is met:

1. **Straightforward Execution:** Craft `NextRoundInput` with Orders [2, 3, 4, 5...] and submit via public `NextRound()` method
2. **No Additional Barriers:** No cryptographic challenges beyond standard miner authentication
3. **Validation Gap Confirmed:** The `CheckRoundTimeSlots()` validation orders by `Order` field but never verifies Order 1 exists
4. **Immediate Success:** Attack succeeds upon round save with no prior warning

While economic incentives are unclear (attacker loses mining rewards), griefing attacks, competitor disruption, or ransom scenarios are plausible. The validation gap makes exploitation trivial for any authorized miner.

## Recommendation

Add explicit validation in `CheckRoundTimeSlots()` to verify Order 1 exists:

```csharp
public ValidationResult CheckRoundTimeSlots()
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    
    if (miners.Count == 1)
        return new ValidationResult { Success = true };
    
    // NEW: Validate Order 1 exists
    if (!miners.Any(m => m.Order == 1))
        return new ValidationResult { Message = "First miner (Order 1) must exist in round." };
    
    // NEW: Validate orders are sequential from 1 to N
    for (int i = 0; i < miners.Count; i++)
    {
        if (miners[i].Order != i + 1)
            return new ValidationResult { Message = $"Miner orders must be sequential from 1 to {miners.Count}." };
    }
    
    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };
    
    // ... rest of validation
}
```

Additionally, add null-safe checks before dereferencing `FirstMiner()` results at all crash points.

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusHalt_MissingOrderOne_Test()
{
    // Setup: Start consensus with valid initial miners
    await InitializeConsensusContract();
    var miners = await GetCurrentMiners();
    var maliciousMiner = miners.First();
    
    // Craft malicious NextRoundInput with orders [2,3,4,5] (missing Order 1)
    var currentRound = await GetCurrentRound();
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation = {}
    };
    
    // Assign orders starting from 2 instead of 1
    int order = 2;
    foreach (var miner in currentRound.RealTimeMinersInformation)
    {
        maliciousRound.RealTimeMinersInformation.Add(miner.Key, new MinerInRound
        {
            Pubkey = miner.Value.Pubkey,
            Order = order++,
            ExpectedMiningTime = Timestamp.FromDateTime(DateTime.UtcNow.AddSeconds(order * 4))
        });
    }
    
    var input = NextRoundInput.Create(maliciousRound, GenerateRandomNumber());
    
    // Execute: Submit malicious round
    var result = await ConsensusStub.NextRound.SendAsync(input);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Passes validation!
    
    // Verify: Any miner trying to get consensus command crashes
    var exception = await Should.ThrowAsync<Exception>(async () =>
    {
        await ConsensusStub.GetConsensusCommand.CallAsync(
            new BytesValue { Value = ByteString.CopyFrom(miners[0].ToByteArray()) }
        );
    });
    
    // Consensus is halted - NullReferenceException or IndexOutOfRangeException
    exception.ShouldNotBeNull();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L105-108)
```csharp
    public Timestamp GetRoundStartTime()
    {
        return FirstMiner().ExpectedMiningTime;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L142-148)
```csharp
    public MinerInRound FirstMiner()
    {
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1)
            // Unlikely.
            : new MinerInRound();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L26-37)
```csharp
        protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;

            _pubkey = pubkey;
            _maximumBlocksCount = maximumBlocksCount;
            _currentBlockTime = currentBlockTime;

            _isTimeSlotPassed = CurrentRound.IsTimeSlotPassed(_pubkey, _currentBlockTime);
            _minerInRound = CurrentRound.RealTimeMinersInformation[_pubkey];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L94-103)
```csharp
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```
