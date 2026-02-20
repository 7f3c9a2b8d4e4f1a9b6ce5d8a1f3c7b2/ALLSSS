# Audit Report

## Title
Consensus Denial of Service via Malicious FinalOrderOfNextRound Values Due to Incorrect Distinct Validation

## Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` function contains a critical bug where it calls `.Distinct()` on `MinerInRound` objects instead of their `FinalOrderOfNextRound` values, failing to validate uniqueness of mining orders. A malicious validator can exploit this by crafting a `NextRoundInput` with duplicate `FinalOrderOfNextRound` values that pass validation but cause permanent consensus halt when the subsequent round attempts to use these corrupted order values.

## Finding Description

**Root Cause**: The validation incorrectly applies `.Distinct()` to `MinerInRound` object instances rather than to their `FinalOrderOfNextRound` property values. [1](#0-0)  Since `MinerInRound` is a protobuf-generated class [2](#0-1)  where each miner object is distinct by reference, the distinct count will always equal the total number of miner objects regardless of whether their `FinalOrderOfNextRound` values contain duplicates.

**Expected Behavior**: The validation should check `providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0).Select(m => m.FinalOrderOfNextRound).Distinct().Count()` to validate uniqueness of the order VALUES.

**Exploitation Path**:

1. During round N to N+1 transition, a malicious validator crafts a `NextRoundInput` where `Order` and `ExpectedMiningTime` values are correctly set for round N+1 mining, but `FinalOrderOfNextRound` values contain malicious duplicates for round N+2. [3](#0-2) 

2. The validation process runs via `ValidateBeforeExecution()` which instantiates `NextRoundMiningOrderValidationProvider` for NextRound behavior. [4](#0-3) 

3. The buggy `NextRoundMiningOrderValidationProvider` passes because it validates distinct OBJECTS rather than distinct `FinalOrderOfNextRound` VALUES. [5](#0-4) 

4. The `TimeSlotValidationProvider` validates time slots for round N+1's `Order` field (which is correct), not the malicious `FinalOrderOfNextRound` values intended for round N+2. [6](#0-5) 

5. The malicious round data is stored via `ProcessNextRound()` and `AddRoundInformation()`. [7](#0-6) [8](#0-7) 

6. When generating round N+2, `GenerateNextRoundInformation()` uses the corrupted `FinalOrderOfNextRound` values to assign `Order` and calculate `ExpectedMiningTime`. [9](#0-8)  All miners with the same `FinalOrderOfNextRound` receive identical `Order` values and identical `ExpectedMiningTime` values.

7. Any attempt to validate or use round N+2 fails in `CheckRoundTimeSlots()` because the `baseMiningInterval` calculation results in 0 when miners at indices 0 and 1 have identical timestamps. [10](#0-9) 

**Why Existing Protections Fail**: The `RoundTerminateValidationProvider` only validates that `InValue` is null, not `OutValue` or `FinalOrderOfNextRound`. [11](#0-10) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables a single malicious validator to permanently halt the entire blockchain consensus mechanism:

- **Consensus Halt**: No new blocks can be produced after round N+1 completes because round N+2 generation fails validation
- **Network Paralysis**: All validators are unable to progress past the corrupted round
- **Complete Operational Shutdown**: All on-chain operations cease
- **No Automatic Recovery**: The system has no built-in mechanism to recover from corrupted round data; manual intervention and potentially a hard fork would be required
- **Violates Critical Invariant**: Breaks the fundamental guarantee of correct round transitions and time-slot validation, miner schedule integrity

This affects all network participants and all blockchain operations, making it a complete denial of service attack.

## Likelihood Explanation

**Probability: HIGH**

The attack is highly feasible because:

**Attacker Requirements:**
- Must be an active validator in the current round (realistic - validators rotate)
- Must have their turn to propose `NextRound` transition (occurs naturally in rotation)
- Only requires standard validator capabilities to craft custom `NextRoundInput` [12](#0-11) 
- No special privileges beyond validator status needed

**Attack Complexity: LOW**
- Single transaction to `NextRound()` with malicious payload
- No timing constraints or race conditions required
- No collusion with other validators needed
- Straightforward to construct the malicious `NextRoundInput`

**Economic Cost: MINIMAL**
- Only standard transaction fees required
- No tokens at risk
- No staking penalties for this behavior (as it passes validation)

**Detection Difficulty:**
- Malicious `FinalOrderOfNextRound` values appear valid during round N+1 operation
- Attack only manifests when round N+2 generation is attempted
- Difficult to identify the malicious validator retroactively

## Recommendation

Fix the validation logic in `NextRoundMiningOrderValidationProvider` to check uniqueness of the `FinalOrderOfNextRound` VALUES rather than the object instances:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    var distinctCount = providedRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0)
        .Select(m => m.FinalOrderOfNextRound)  // Add this Select() to get the values
        .Distinct()
        .Count();
    if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
    {
        validationResult.Message = "Invalid FinalOrderOfNextRound.";
        return validationResult;
    }

    validationResult.Success = true;
    return validationResult;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousValidator_CanHaltConsensus_WithDuplicateFinalOrderOfNextRound()
{
    // Setup: Initialize consensus with multiple validators
    var initialMiners = GenerateInitialMiners(5);
    await InitializeConsensus(initialMiners);
    
    // Round 1: Normal operation
    await ProduceNormalRound();
    
    // Round 2: Malicious validator crafts NextRoundInput with duplicate FinalOrderOfNextRound
    var maliciousNextRoundInput = new NextRoundInput
    {
        RoundNumber = 3,
        // ... other valid fields for round 2 to 3 transition ...
    };
    
    // Set all miners' FinalOrderOfNextRound to 1 (duplicates!)
    foreach (var miner in maliciousNextRoundInput.RealTimeMinersInformation.Values)
    {
        miner.FinalOrderOfNextRound = 1; // All duplicates!
        miner.Order = /* correct value for round 2 */;
        miner.ExpectedMiningTime = /* correct value for round 2 */;
        miner.OutValue = /* valid hash */;
    }
    
    // Execute the malicious NextRound - should pass validation due to bug
    var result = await ConsensusStub.NextRound.SendAsync(maliciousNextRoundInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Passes!
    
    // Round 3: When generating round 4, all miners get Order=1 and same ExpectedMiningTime
    // Any attempt to validate or mine round 4 will fail with "Mining interval must greater than 0"
    await ProduceBlocksUntilRoundEnd(); // Complete round 3
    
    // Attempt to generate round 4 - should fail validation
    var round4Generation = await TryGenerateNextRound();
    round4Generation.Success.ShouldBe(false);
    round4Generation.Message.ShouldContain("Mining interval must greater than 0");
    
    // Consensus is now permanently halted - no new blocks can be produced
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-26)
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
}
```

**File:** protobuf/aedpos_contract.proto (L266-301)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L1-41)
```csharp
using Google.Protobuf;

namespace AElf.Contracts.Consensus.AEDPoS;

public partial class NextRoundInput
{
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-47)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
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
