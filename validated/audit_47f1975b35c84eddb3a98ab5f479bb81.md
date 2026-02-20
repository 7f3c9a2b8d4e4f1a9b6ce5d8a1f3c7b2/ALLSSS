# Audit Report

## Title
Missing ActualMiningTimes Validation in Next Round Allows Consensus Manipulation

## Summary
The `ValidationForNextRound()` method fails to validate the `ActualMiningTimes` field when transitioning to a new consensus round, allowing malicious miners to pre-fill arbitrary timestamps that manipulate term change logic and deny tiny block production permissions to targeted miners.

## Finding Description

The AEDPoS consensus contract validates next round information through the `ValidationForNextRound()` method, which explicitly checks only two aspects: round number increment and InValue nullability. [1](#0-0) 

When legitimate next round information is generated, the `GenerateNextRoundInformation()` method creates fresh `MinerInRound` objects that only initialize specific fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots) without setting `ActualMiningTimes`. [2](#0-1) 

Only the extra block producer legitimately adds their timestamp to `ActualMiningTimes` when producing the round transition block. [3](#0-2) 

However, the `NextRound()` transaction processes input by converting it via `ToRound()`, which copies ALL fields from the protobuf structure including any pre-filled `ActualMiningTimes`. [4](#0-3) 

The manipulated round is then directly stored without additional validation. [5](#0-4) 

A malicious miner producing the extra block can generate legitimate next round information, then modify the `NextRoundInput.RealTimeMinersInformation` map before submission to add fake timestamps to `ActualMiningTimes` for arbitrary miners. The validation passes because it only checks round number and InValue, and the manipulated data is stored in contract state.

## Impact Explanation

Pre-filled `ActualMiningTimes` directly corrupts critical consensus mechanisms:

**1. Term Change Manipulation**: The `NeedToChangeTerm()` method uses the last `ActualMiningTime` of each miner to determine if term transitions should occur. [6](#0-5) [7](#0-6) 

By injecting future timestamps, an attacker can force premature term changes, disrupting the election cycle and miner rotation. Conversely, past timestamps can prevent legitimate term changes, keeping a specific miner set in power longer than intended.

**2. Tiny Block Production Denial**: The consensus behavior logic determines if miners can produce tiny blocks by checking if `ActualMiningTimes.Count < maximumBlocksCount`. [8](#0-7) 

By inflating the count to equal or exceed the limit, an attacker prevents targeted miners from producing tiny blocks, reducing network throughput and potentially causing consensus delays.

**3. First Round Timing Manipulation**: Time slot validation for the first round uses `ActualMiningTimes.First()` to establish timing baselines. [9](#0-8) 

Manipulated initial timestamps can disrupt the entire round's timing calculations.

## Likelihood Explanation

**High Likelihood** - This attack is practical and easily executable:

**Attacker Capabilities**: Any miner producing the extra block (the last block of a round) can execute this attack. The extra block producer role rotates through the miner set, giving each miner periodic opportunities.

**Attack Complexity**: Low - The attacker only needs to:
1. Generate legitimate next round information via the normal consensus flow
2. Modify the `NextRoundInput` structure locally before block production
3. Submit the modified `NextRound` transaction

**Feasibility Factors**:
- The `NextRound()` method is a standard public consensus entry point [10](#0-9) 
- No authorization beyond being the current extra block producer is required
- The validation explicitly omits `ActualMiningTimes` checks (as documented in the code comments)
- The protobuf definition allows the `actual_mining_times` repeated field to be arbitrarily populated [11](#0-10) 

**Detection**: The attack may initially go undetected since the manipulated `ActualMiningTimes` is stored in contract state and treated as legitimate by all subsequent consensus logic.

## Recommendation

Add explicit validation of `ActualMiningTimes` in the `ValidationForNextRound()` method to ensure:

1. For all miners except the extra block producer of the current round: `ActualMiningTimes` must be empty or not initialized
2. For the extra block producer: `ActualMiningTimes` should contain at most one entry matching the current block time

The fix should validate that the `ActualMiningTimes` collection in the next round input matches the expected state based on legitimate consensus flow.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Setup a consensus scenario with multiple miners
2. Have one miner designated as the extra block producer
3. Generate legitimate next round information
4. Modify the `NextRoundInput` to inject additional `ActualMiningTimes` entries for other miners
5. Submit the `NextRound` transaction
6. Verify that the manipulated data passes validation and is stored
7. Verify that subsequent consensus logic (term changes, tiny block logic) is affected by the injected timestamps

The test would prove that malicious ActualMiningTimes entries bypass validation and corrupt consensus state.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L195-196)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L92-96)
```csharp
        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;

        var actualStartTime = actualStartTimes.First();
        var runningTime = currentBlockTime - actualStartTime;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
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

**File:** protobuf/aedpos_contract.proto (L291-292)
```text
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
```
