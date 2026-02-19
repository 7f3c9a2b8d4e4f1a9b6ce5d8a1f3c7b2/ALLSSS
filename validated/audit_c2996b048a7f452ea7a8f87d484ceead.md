# Audit Report

## Title
Consensus Integrity Bypass via Duplicate Mining Order Validation Failure

## Summary
The `NextRoundMiningOrderValidationProvider` incorrectly validates mining order uniqueness by applying `Distinct()` to entire `MinerInRound` objects instead of checking distinct `FinalOrderOfNextRound` values. This allows a malicious miner to craft a NextRound with duplicate mining orders that passes validation, corrupting the consensus schedule and potentially halting the network.

## Finding Description

The vulnerability exists in the validation logic that verifies mining order uniqueness during NextRound transitions. [1](#0-0) 

The code applies `Distinct()` to a collection of `MinerInRound` objects. Since `MinerInRound` is a protobuf-generated class [2](#0-1) , its equality comparison checks ALL fields (pubkey, OutValue, Signature, InValue, etc.). Because each miner has unique values for these fields, `Distinct()` never filters out any objects even when multiple miners share the same `FinalOrderOfNextRound`.

**Attack Execution Path**:

1. A miner produces a NextRound block and obtains legitimate round data [3](#0-2) 

2. The miner modifies the Round object to set duplicate `FinalOrderOfNextRound` values (e.g., two miners both have FinalOrderOfNextRound = 2)

3. During block validation, `ValidateConsensusBeforeExecution` is called [4](#0-3) 

4. The validation pipeline adds `NextRoundMiningOrderValidationProvider` for NextRound behavior [5](#0-4) 

5. The flawed validation passes because all `MinerInRound` objects are considered "distinct" despite having duplicate `FinalOrderOfNextRound` values

6. The `NextRound` transaction executes [6](#0-5) 

7. The corrupted round is saved to state [7](#0-6) 

8. When generating the next round, the duplicate `FinalOrderOfNextRound` values cause multiple miners to be assigned the same `Order` value [8](#0-7) 

This breaks the consensus schedule integrity invariant that each miner must have a unique mining order position.

## Impact Explanation

**Consensus Schedule Corruption**: When the malicious round is used to generate the next round, multiple miners are assigned the same `Order` value while other order positions remain unassigned. For example, if 5 miners have FinalOrderOfNextRound values of [1,2,2,4,5], then:
- Position 3 is missing from the schedule
- Two miners compete for position 2
- The `BreakContinuousMining` function fails because it uses `First(i => i.Order == X)` [9](#0-8) , which only finds one miner even when multiple share the same order

**Network-Wide Impact**: This corrupts the consensus mechanism for all participants:
- Block production conflicts when multiple miners attempt to mine the same slot
- Missing time slots cause round progression delays
- Incorrect LIB calculations due to corrupted miner scheduling
- Potential consensus halt requiring manual intervention

**Severity**: CRITICAL - This directly violates core consensus invariants and affects the entire network's ability to produce blocks and reach finality.

## Likelihood Explanation

**Attacker Requirements**: Any miner in the active miner set can execute this attack when selected to produce a NextRound block. This is a standard consensus role requiring no special privileges.

**Attack Complexity**: LOW
- The miner obtains legitimate round data from the contract
- Simple modification of `FinalOrderOfNextRound` values in the Round object
- No cryptographic operations or complex timing requirements needed
- Single malicious block execution

**Feasibility**: The validation context obtains the `ProvidedRound` from block extra data [10](#0-9) , which the miner controls. The miner can modify this data before block production, and the flawed validation logic accepts it.

**Detection**: There is no detection mechanism - the malicious round appears valid to all validators because the validation logic is fundamentally broken.

**Probability**: HIGH - Every NextRound block production by a malicious miner presents an exploitation opportunity. NextRound transitions occur regularly in normal network operation.

## Recommendation

Fix the validation to check distinct `FinalOrderOfNextRound` values instead of distinct `MinerInRound` objects:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    
    // Extract FinalOrderOfNextRound values and check for uniqueness
    var ordersOfNextRound = providedRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0)
        .Select(m => m.FinalOrderOfNextRound)
        .ToList();
    
    var distinctOrderCount = ordersOfNextRound.Distinct().Count();
    var minersWhoMinedCount = providedRound.RealTimeMinersInformation.Values
        .Count(m => m.OutValue != null);
    
    if (distinctOrderCount != minersWhoMinedCount || 
        distinctOrderCount != ordersOfNextRound.Count)
    {
        validationResult.Message = "Invalid FinalOrderOfNextRound - duplicates detected.";
        return validationResult;
    }

    validationResult.Success = true;
    return validationResult;
}
```

This fix ensures that:
1. Each `FinalOrderOfNextRound` value is unique (no duplicates)
2. The count of distinct orders matches miners who produced blocks
3. The count of distinct orders matches total orders assigned (catches duplicates)

## Proof of Concept

```csharp
[Fact]
public void NextRoundMiningOrderValidation_ShouldRejectDuplicateOrders()
{
    // Setup: Create a round with 3 miners
    var round = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation =
        {
            ["miner1"] = new MinerInRound
            {
                Pubkey = "miner1",
                OutValue = Hash.FromString("out1"),
                FinalOrderOfNextRound = 1
            },
            ["miner2"] = new MinerInRound
            {
                Pubkey = "miner2",
                OutValue = Hash.FromString("out2"),
                FinalOrderOfNextRound = 2  // DUPLICATE
            },
            ["miner3"] = new MinerInRound
            {
                Pubkey = "miner3",
                OutValue = Hash.FromString("out3"),
                FinalOrderOfNextRound = 2  // DUPLICATE - should be detected
            }
        }
    };

    var validationContext = new ConsensusValidationContext
    {
        ExtraData = new AElfConsensusHeaderInformation
        {
            Round = round,
            Behaviour = AElfConsensusBehaviour.NextRound
        }
    };

    var provider = new NextRoundMiningOrderValidationProvider();
    var result = provider.ValidateHeaderInformation(validationContext);

    // Current implementation FAILS - returns Success = true (VULNERABILITY)
    // Fixed implementation should return Success = false
    Assert.False(result.Success); // This assertion FAILS with current code
    Assert.Contains("duplicate", result.Message.ToLower());
}
```

This test demonstrates that the current validation incorrectly accepts duplicate `FinalOrderOfNextRound` values because `Distinct()` operates on the entire `MinerInRound` objects rather than just the order values.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-90)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```
