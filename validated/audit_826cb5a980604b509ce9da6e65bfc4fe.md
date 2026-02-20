# Audit Report

## Title
Incorrect Distinct() Usage Allows Duplicate FinalOrderOfNextRound Values to Bypass Validation

## Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` method incorrectly calls `Distinct()` on `MinerInRound` objects instead of on their `FinalOrderOfNextRound` values. This allows malicious miners to submit `NextRound` transactions with duplicate mining order assignments, causing consensus disruption through non-deterministic miner selection and mining schedule conflicts.

## Finding Description
The validation logic contains a critical flaw in how it verifies the uniqueness of mining orders for the next round. The code calls `Distinct()` directly on a collection of `MinerInRound` objects: [1](#0-0) 

Since `MinerInRound` is a protobuf-generated message with 17 fields (pubkey, order, in_value, out_value, signature, expected_mining_time, produced_blocks, missed_time_slots, previous_in_value, supposed_order_of_next_round, final_order_of_next_round, actual_mining_times, encrypted_pieces, decrypted_pieces, produced_tiny_blocks, implied_irreversible_block_height, is_extra_block_producer), protobuf C# implements value-based equality comparing ALL fields: [2](#0-1) 

The validation compares the count of distinct `MinerInRound` objects against miners who produced blocks, but fails to validate uniqueness of `FinalOrderOfNextRound` values specifically. Two miners with identical `FinalOrderOfNextRound` but different pubkeys/signatures/OutValues are counted as distinct objects, allowing the validation to pass incorrectly.

The validation is invoked during block validation through the ACS4 interface: [3](#0-2) 

When a malicious miner submits a `NextRound` transaction, the entry point is the public RPC method: [4](#0-3) 

The only privilege check is `PreCheck()`, which merely verifies the sender is in the current or previous miner list: [5](#0-4) 

## Impact Explanation

When `GenerateNextRoundInformation` processes the validated (but malicious) round data, it directly assigns each miner's `Order` from their `FinalOrderOfNextRound` value: [6](#0-5) 

Multiple miners end up with identical `Order` values in the next round, each maintaining their unique dictionary key (pubkey). This breaks the fundamental AEDPoS consensus invariant that each miner must have a unique Order value within a round.

Functions that select miners by order produce unpredictable results. The extra block producer selection uses `FirstOrDefault`: [7](#0-6) 

When multiple miners share the same order, this returns an arbitrary miner based on dictionary iteration order, making extra block producer selection non-deterministic.

Similarly, the continuous mining prevention logic uses `First()` to find miners by specific order values: [8](#0-7) 

With duplicate orders, these lookups become non-deterministic, breaking consensus guarantees that prevent continuous mining by the same miner. Multiple miners with the same `Order` value calculate identical expected mining times, causing simultaneous mining attempts and potential fork scenarios. This violates the fundamental AEDPoS consensus property that each miner has a unique time slot within a round.

All network participants suffer from consensus instability. The chain may experience fork scenarios, block production conflicts, or halt entirely if multiple miners simultaneously claim the same time slot.

## Likelihood Explanation

The `NextRound` method is a public RPC endpoint accessible to any current miner. The attacker must be a current miner, which is a realistic precondition since miners are legitimate network participants who may turn malicious.

A malicious miner can construct a crafted `NextRoundInput` by manually setting duplicate `FinalOrderOfNextRound` values in the `RealTimeMinersInformation` dictionary: [9](#0-8) 

The attacker bypasses the normal `ApplyNormalConsensusData` conflict resolution logic: [10](#0-9) 

The attack costs only transaction fees but can cause significant network disruption, making it attractive for attackers seeking to halt the chain, manipulate mining rewards, or create market instability.

## Recommendation

Fix the validation to check uniqueness of `FinalOrderOfNextRound` values specifically, not entire `MinerInRound` objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

This ensures the validation correctly identifies duplicate mining order assignments regardless of other field differences.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanBypassValidationWithDuplicateOrders()
{
    // Setup: Create a round with 3 miners
    var currentRound = new Round
    {
        RoundNumber = 1,
        RealTimeMinersInformation =
        {
            ["MinerA"] = new MinerInRound { Pubkey = "MinerA", OutValue = Hash.FromString("hashA"), FinalOrderOfNextRound = 1 },
            ["MinerB"] = new MinerInRound { Pubkey = "MinerB", OutValue = Hash.FromString("hashB"), FinalOrderOfNextRound = 1 }, // Duplicate order
            ["MinerC"] = new MinerInRound { Pubkey = "MinerC", OutValue = Hash.FromString("hashC"), FinalOrderOfNextRound = 2 }
        }
    };

    // Malicious NextRoundInput with duplicate FinalOrderOfNextRound values
    var maliciousInput = NextRoundInput.Create(currentRound, ByteString.CopyFromUtf8("random"));

    // Validation provider
    var validator = new NextRoundMiningOrderValidationProvider();
    var context = new ConsensusValidationContext { ProvidedRound = currentRound };

    // Execute validation - should fail but incorrectly passes
    var result = validator.ValidateHeaderInformation(context);

    // The flawed validation passes because it counts distinct MinerInRound objects (3)
    // which equals miners with OutValue != null (3), even though there are only 2 distinct FinalOrderOfNextRound values
    Assert.True(result.Success); // Incorrectly passes validation

    // Verify the duplicate orders exist
    var ordersCount = currentRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0)
        .Select(m => m.FinalOrderOfNextRound)
        .Distinct()
        .Count();
    
    Assert.Equal(2, ordersCount); // Only 2 distinct orders, not 3 - vulnerability confirmed
}
```

## Notes

The vulnerability exists because protobuf-generated C# classes implement `Equals()` and `GetHashCode()` based on all message fields, not just selected properties. The validation should explicitly project to the `FinalOrderOfNextRound` field before applying `Distinct()` to ensure correct uniqueness checking. This flaw allows malicious miners to bypass the intended consensus safety mechanism and create non-deterministic mining schedules.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L264-301)
```text
}

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-165)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L59-65)
```csharp
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L7-23)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-44)
```csharp
        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```
