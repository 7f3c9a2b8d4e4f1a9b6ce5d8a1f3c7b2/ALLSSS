# Audit Report

## Title
Mining Interval Manipulation Allows Time Slot Compression via Insufficient Validation

## Summary
The AEDPoS consensus contract's round validation logic only enforces that mining intervals are greater than zero without establishing a minimum bound or verifying correctness against expected values. A malicious miner producing a NextRound or NextTerm block can manipulate Round data to set arbitrarily small mining intervals (e.g., 1ms), which passes validation and becomes stored state, causing all miners to operate under compressed time slots indefinitely.

## Finding Description

The vulnerability exists in the round validation and storage flow where insufficient validation allows mining interval manipulation that persists across future rounds.

The mining interval is calculated from ExpectedMiningTime differences between consecutive miners in a Round. [1](#0-0) 

When a miner produces a NextRound or NextTerm block, they provide Round data via NextRoundInput or NextTermInput, which is directly copied without regeneration through the ToRound() method. [2](#0-1) [3](#0-2) 

The TimeSlotValidationProvider invokes CheckRoundTimeSlots() for validation when a new round is detected. [4](#0-3) 

However, CheckRoundTimeSlots() only validates that the mining interval is strictly greater than zero, with no minimum bound enforced and no verification that the interval matches the expected protocol value. [5](#0-4) 

A malicious miner can set ExpectedMiningTime values 1 millisecond apart. This passes validation (1 > 0) but allows mining at 4000x the intended frequency. The manipulated Round is stored via AddRoundInformation() in ProcessNextRound or ProcessNextTerm. [6](#0-5) [7](#0-6) 

The compromised interval propagates because TinyBlockCommandStrategy and future round generation use the current round's mining interval via GetMiningInterval(). [8](#0-7) [9](#0-8) 

Subsequent rounds generated from the manipulated round inherit the compressed interval because GenerateNextRoundInformation uses GetMiningInterval() to calculate ExpectedMiningTime values for all miners in the next round. [10](#0-9) 

The after-execution validation only compares round hashes and does not regenerate the Round to verify ExpectedMiningTime values match what the contract's GenerateNextRoundInformation would produce. [11](#0-10) 

## Impact Explanation

**Consensus Integrity Violation**: The fundamental consensus timing mechanism is compromised. The intended mining interval (default 4000ms) ensures proper network propagation, block validation time, and prevents resource exhaustion. A manipulated 1ms interval breaks this critical invariant.

**Block Production Rate Manipulation**: With a 1ms interval instead of 4000ms, miners could produce 4000 blocks per intended time slot instead of 1. In extreme cases with multiple miners and tiny blocks, this could reach rates exceeding 100,000 blocks per second, overwhelming network bandwidth and node processing capacity.

**Chain Stability Impact**: Honest nodes may be unable to keep up with block validation at manipulated rates, causing them to fall behind or disconnect. This could lead to increased chain reorganizations, consensus failures, and effective centralization where only high-resource operators can participate. The system would deviate from intended tokenomics for block rewards as production rates become disconnected from time passage.

**Systemic Effect**: Once a manipulated round is accepted, ALL miners in that round are forced to operate under the compressed time slots. The manipulation persists indefinitely because every subsequent round generated via GenerateNextRoundInformation uses GetMiningInterval() from the current round, perpetuating the compressed interval across the entire blockchain until a new term begins with fresh miner elections. Even then, if the attacker is re-elected, they can repeat the attack.

## Likelihood Explanation

**Attacker Requirements**: The attacker must be an active miner in the current round and be designated to produce the round-terminating (NextRound) or term-terminating (NextTerm) block. This designation occurs naturally during normal consensus operation - the last miner in a round produces the NextRound block, and when term change conditions are met, the designated miner produces the NextTerm block. These opportunities occur regularly (every round for NextRound, every term period for NextTerm).

**Attack Complexity**: Low. The attack requires modifying the Round data structure's ExpectedMiningTime values before including it in the block's consensus extra data. No complex cryptographic operations or precise timing attacks are needed. The attacker simply creates a custom NextRoundInput or NextTermInput with manipulated values instead of using the suggested values from GetConsensusExtraData.

**Feasibility**: The validation logic is deterministic and bypassable with any interval > 0. The CheckRoundTimeSlots() method has no minimum bound check, no comparison with State.MiningInterval, and no regeneration to verify correctness. No consensus-level rejection mechanism for suspicious intervals exists. The State.MiningInterval is only set during FirstRound initialization and not referenced during NextRound or NextTerm validation, making it ineffective as a protection.

**Detection**: While off-chain monitoring could detect abnormally high block production rates, the manipulated data passes all on-chain validation checks legitimately at the protocol level. There is no prevention mechanism, only potential post-facto detection after the manipulation has already taken effect.

## Recommendation

Implement proper validation in CheckRoundTimeSlots() to enforce a minimum acceptable mining interval:

1. **Add minimum bound check**: Validate that baseMiningInterval is not only > 0 but also >= a minimum threshold (e.g., State.MiningInterval or a protocol constant like 1000ms).

2. **Regenerate and compare**: In ProcessNextRound and ProcessNextTerm, regenerate the expected Round using GenerateNextRoundInformation and compare key fields (especially ExpectedMiningTime values) with the provided Round. Reject if they don't match within acceptable tolerance.

3. **Use State.MiningInterval for validation**: Reference State.MiningInterval during validation to ensure the provided Round's mining interval aligns with the protocol-defined value.

4. **Enhanced after-execution validation**: In ValidateConsensusAfterExecution, regenerate the expected Round and compare against the stored Round, not just hash comparison.

Example fix for CheckRoundTimeSlots():

```csharp
public ValidationResult CheckRoundTimeSlots(int expectedMiningInterval)
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

    var baseMiningInterval =
        (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

    // Enhanced validation with minimum bound
    const int minimumAllowedInterval = 1000; // 1 second minimum
    if (baseMiningInterval <= 0)
        return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
    
    if (baseMiningInterval < minimumAllowedInterval)
        return new ValidationResult { Message = $"Mining interval {baseMiningInterval}ms is below minimum {minimumAllowedInterval}ms.\n{this}" };
    
    // Validate against expected interval (allow small tolerance for rounding)
    if (Math.Abs(baseMiningInterval - expectedMiningInterval) > expectedMiningInterval / 10)
        return new ValidationResult { Message = $"Mining interval {baseMiningInterval}ms deviates significantly from expected {expectedMiningInterval}ms.\n{this}" };

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

## Proof of Concept

A proof of concept would demonstrate:
1. A miner produces a NextRound block with manipulated ExpectedMiningTime values set 1ms apart
2. The validation passes CheckRoundTimeSlots() because 1 > 0
3. ProcessNextRound stores the manipulated Round via ToRound() and AddRoundInformation()
4. GetMiningInterval() returns 1ms from the stored round
5. Subsequent rounds generated via GenerateNextRoundInformation inherit the 1ms interval
6. TinyBlockCommandStrategy calculates time slot boundaries using the 1ms interval, enabling rapid block production

The test would need to simulate the consensus flow with a malicious miner providing manipulated NextRoundInput, demonstrating that validation passes and the manipulated interval becomes permanently stored state affecting all future rounds.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-47)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
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

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L37-37)
```csharp
        protected int MiningInterval => CurrentRound.GetMiningInterval();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L32-38)
```csharp
            var roundStartTime = CurrentRound.GetRoundStartTime();
            var currentTimeSlotStartTime = CurrentBlockTime < roundStartTime
                ? roundStartTime.AddMilliseconds(-MiningInterval)
                : CurrentRound.RoundNumber == 1
                    ? MinerInRound.ActualMiningTimes.First()
                    : MinerInRound.ExpectedMiningTime;
            var currentTimeSlotEndTime = currentTimeSlotStartTime.AddMilliseconds(MiningInterval);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```
