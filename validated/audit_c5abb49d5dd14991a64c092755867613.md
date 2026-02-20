# Audit Report

## Title
Insufficient Validation of Next Round Miner Information Allows Consensus Manipulation

## Summary
The `ValidationForNextRound()` function in the AEDPoS consensus contract only validates that `InValue` fields are null and the round number increments correctly, but fails to validate the `Order`, `OutValue`, `Signature`, and `FinalOrderOfNextRound` fields in the proposed next round. This allows a malicious miner to pre-fill these consensus-critical fields with arbitrary values, disrupting the mining sequence and influencing future consensus decisions.

## Finding Description

When a miner triggers a round transition by calling `NextRound()`, the validation performed on the proposed next round data is insufficient. The `ValidationForNextRound()` method only verifies two conditions: [1](#0-0) 

This validation ensures that `InValue` fields are null and the round number increments by exactly 1, but does not validate that `OutValue`, `Signature`, `Order`, `FinalOrderOfNextRound`, and other consensus-critical fields are in their expected initial state.

The `MinerInRound` structure contains multiple consensus-critical fields: [2](#0-1) 

When a legitimate next round is generated via `GenerateNextRoundInformation()`, only specific fields are initialized (`Pubkey`, `Order`, `ExpectedMiningTime`, `ProducedBlocks`, `MissedTimeSlots`), leaving others at their default protobuf values: [3](#0-2) 

The `NextRoundMiningOrderValidationProvider` only performs a count-based check: [4](#0-3) 

This check is satisfied when both counts are zero (legitimate case) but is also satisfied when both counts equal any positive number N (malicious case with consistent pre-filling).

The `ProcessNextRound` method directly converts and stores the input without field sanitization: [5](#0-4) 

The `ToRound()` conversion simply copies all fields without validation: [6](#0-5) 

Finally, `AddRoundInformation()` stores the round directly to state: [7](#0-6) 

**Attack Flow:**
1. Malicious miner generates legitimate next round via `GetConsensusExtraDataForNextRound()`
2. Miner modifies the Round structure to manipulate `Order`, `OutValue`, `Signature`, `FinalOrderOfNextRound` fields (ensuring `OutValue != null` count equals `FinalOrderOfNextRound > 0` count)
3. Miner produces a block containing this manipulated data and calls `NextRound()` with the modified input
4. Validation passes all checks (`InValue` null, round number correct, counts equal)
5. Manipulated round is stored in state and becomes the canonical round used by all nodes

## Impact Explanation

**Mining Sequence Disruption:**
The `Order` field directly determines each miner's position in the mining sequence and their `ExpectedMiningTime`. By manipulating `Order` values, an attacker can disrupt the intended mining schedule, potentially preventing legitimate miners from producing blocks in their assigned time slots or altering the consensus flow.

**Extra Block Producer Manipulation:**
The extra block producer selection for subsequent rounds uses signature values from the current round: [8](#0-7) 

Pre-filled `Signature` values in a manipulated round will influence this calculation when that round is used to generate the next round, affecting which miner becomes the extra block producer and potentially giving the attacker or colluding miners advantageous positions.

**Cryptographic Chain Integrity:**
The `OutValue` field should equal `Hash(InValue)` and is calculated during legitimate mining. Pre-filling these values breaks the intended cryptographic derivation chain that ensures consensus protocol integrity.

**Protocol-Wide Impact:**
All validating nodes accept blocks containing the manipulated consensus data through the insufficient validation checks, making the corrupted round the canonical state used for subsequent consensus decisions.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round
- Must be able to produce a block (typically the extra block producer responsible for `NextRound` transitions)
- No additional privileges beyond standard miner capabilities

**Attack Feasibility:**
The attack is straightforward:
1. Generate legitimate next round data using existing methods
2. Modify the Round structure to pre-fill consensus fields with attacker-chosen values
3. Ensure `OutValue` and `FinalOrderOfNextRound` counts match to satisfy the count-based validation
4. Submit via `NextRound()` transaction in a produced block

The validation logic is deterministic and publicly analyzable. The bypass technique (matching counts while pre-filling fields) requires no complex timing, state races, or cryptographic breaks.

**Probability Assessment:** HIGH - Any miner capable of producing a `NextRound` block can execute this attack with standard miner privileges and no complex preconditions.

## Recommendation

Implement comprehensive validation in `ValidationForNextRound()` to ensure all consensus-critical fields in the proposed next round are in their expected initial state:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // Additional validations for fields that should be in initial state
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.OutValue != null))
        return new ValidationResult { Message = "OutValue must be null in next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.Signature != null))
        return new ValidationResult { Message = "Signature must be null in next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.FinalOrderOfNextRound != 0))
        return new ValidationResult { Message = "FinalOrderOfNextRound must be zero in next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.PreviousInValue != null))
        return new ValidationResult { Message = "PreviousInValue must be null in next round." };
    
    // Validate Order field is correctly assigned (sequential from 1 to miner count)
    var expectedOrders = Enumerable.Range(1, extraData.Round.RealTimeMinersInformation.Count).ToHashSet();
    var actualOrders = extraData.Round.RealTimeMinersInformation.Values.Select(m => m.Order).ToHashSet();
    if (!expectedOrders.SetEquals(actualOrders))
        return new ValidationResult { Message = "Order fields must form a valid sequence." };
    
    return new ValidationResult { Success = true };
}
```

## Proof of Concept

A malicious miner can exploit this vulnerability by crafting a `NextRoundInput` with manipulated consensus fields. The following demonstrates the attack flow:

```csharp
// 1. Attacker is the extra block producer in current round
// 2. Generate legitimate next round
var currentRound = GetCurrentRoundInformation();
GenerateNextRoundInformation(currentRound, currentBlockTime, out var nextRound);

// 3. Manipulate the round data
// Reorder miners to favor attacker
foreach (var miner in nextRound.RealTimeMinersInformation.Values)
{
    // Reverse the mining order
    miner.Order = nextRound.RealTimeMinersInformation.Count - miner.Order + 1;
    
    // Pre-fill consensus fields to satisfy count-based validation
    miner.OutValue = Hash.FromString($"malicious_{miner.Pubkey}");
    miner.Signature = Hash.FromString($"fake_sig_{miner.Pubkey}");
    miner.FinalOrderOfNextRound = miner.Order; // Set to match OutValue != null count
}

// 4. Create malicious NextRoundInput
var maliciousInput = NextRoundInput.Create(nextRound, randomNumber);

// 5. Submit via NextRound() - validation passes because:
//    - InValue is null for all miners ✓
//    - Round number increments correctly ✓
//    - Count(FinalOrderOfNextRound > 0) == Count(OutValue != null) ✓
NextRound(maliciousInput);

// Result: Manipulated round is stored and disrupts consensus
```

The manipulated round will be accepted by all nodes and used as the canonical next round, disrupting the mining sequence and potentially influencing future extra block producer selection.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L25-56)
```csharp
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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L99-124)
```csharp
    /// <summary>
    ///     Will force to generate a `Change` to tx executing result.
    /// </summary>
    /// <param name="round"></param>
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
