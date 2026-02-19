# Audit Report

## Title
Incorrect Distinct() Usage Allows Duplicate FinalOrderOfNextRound Values to Bypass Validation

## Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` method incorrectly calls `Distinct()` on `MinerInRound` objects instead of on their `FinalOrderOfNextRound` values. This allows malicious miners to submit `NextRound` transactions with duplicate mining order assignments, causing consensus disruption through non-deterministic miner selection and mining schedule conflicts.

## Finding Description
The validation logic contains a critical flaw in how it verifies the uniqueness of mining orders for the next round. [1](#0-0) 

This code calls `Distinct()` directly on the collection of `MinerInRound` objects. Since `MinerInRound` is a protobuf-generated message [2](#0-1)  that implements value-based equality comparing all fields (pubkey, order, in_value, out_value, signature, etc.), the `Distinct()` operation compares entire objects rather than just the `FinalOrderOfNextRound` field.

**Example Attack Scenario:**
- Miner A: `FinalOrderOfNextRound = 1`, `Pubkey = "A"`, `OutValue = hash1`
- Miner B: `FinalOrderOfNextRound = 1`, `Pubkey = "B"`, `OutValue = hash2`
- Miner C: `FinalOrderOfNextRound = 2`, `Pubkey = "C"`, `OutValue = hash3`

The flawed validation counts 3 distinct `MinerInRound` objects (because pubkeys differ), which equals the count of miners who mined (3 miners with non-null `OutValue`), so validation incorrectly passes. However, there are only 2 distinct `FinalOrderOfNextRound` values, not 3 - miners A and B both claim order 1 for the next round.

The validation is invoked during `NextRound` behavior processing [3](#0-2)  as part of the consensus information update flow [4](#0-3) .

## Impact Explanation

**Consensus Disruption via Duplicate Orders:**
When `GenerateNextRoundInformation` processes the validated (but malicious) round data, it directly assigns each miner's `Order` from their `FinalOrderOfNextRound` value: [5](#0-4) 

Multiple miners end up with identical `Order` values in the next round, each maintaining their unique dictionary key (pubkey).

**Non-Deterministic Behavior:**
Functions that select miners by order produce unpredictable results. The extra block producer selection uses `FirstOrDefault`: [6](#0-5) 

When multiple miners share the same order, this returns an arbitrary miner, making the extra block producer selection non-deterministic.

Similarly, the continuous mining prevention logic uses `First()` to find miners by specific order values: [7](#0-6) 

With duplicate orders, these lookups become non-deterministic, breaking the consensus guarantees that prevent continuous mining by the same miner.

**Mining Schedule Conflicts:**
Multiple miners with the same `Order` value calculate identical expected mining times, causing simultaneous mining attempts. This violates the fundamental AEDPoS consensus property that each miner has a unique time slot within a round.

**Affected Parties:**
All network participants suffer from consensus instability. The chain may experience fork scenarios, block production conflicts, or halt entirely if multiple miners simultaneously claim the same time slot.

## Likelihood Explanation

**Reachable Entry Point:**
The `NextRound` method is a public RPC endpoint [8](#0-7)  that any current miner can invoke [9](#0-8) .

**Feasible Preconditions:**
The attacker must be a current miner, verified by the `PreCheck()` method: [10](#0-9) 

This is a realistic precondition since miners are legitimate network participants who may turn malicious.

**Execution Practicality:**
A malicious miner can construct a crafted `NextRoundInput` [11](#0-10)  by manually setting duplicate `FinalOrderOfNextRound` values in the `RealTimeMinersInformation` dictionary, then submitting it via a standard transaction.

**Economic Rationality:**
The attack costs only transaction fees but can cause significant network disruption, making it attractive for attackers seeking to halt the chain, manipulate mining rewards, or create market instability.

## Recommendation

Fix the validation to check for distinct `FinalOrderOfNextRound` values rather than distinct `MinerInRound` objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Extract just the order value
    .Distinct()
    .Count();
```

This ensures the validation correctly counts unique mining order assignments rather than unique miner objects.

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_WithDuplicateFinalOrderOfNextRound_ShouldFailValidation()
{
    // Setup: Initialize consensus with 3 miners
    await InitializeContracts();
    
    // Get current round
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Craft malicious NextRoundInput with duplicate FinalOrderOfNextRound values
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        BlockchainAge = currentRound.BlockchainAge + 1
    };
    
    var minerKeys = InitialCoreDataCenterKeyPairs.Take(3).ToList();
    
    // Miner 1 and 2 both get FinalOrderOfNextRound = 1 (duplicate!)
    maliciousRound.RealTimeMinersInformation[minerKeys[0].PublicKey.ToHex()] = new MinerInRound
    {
        Pubkey = minerKeys[0].PublicKey.ToHex(),
        FinalOrderOfNextRound = 1,  // Duplicate order
        OutValue = HashHelper.ComputeFrom("out1")
    };
    
    maliciousRound.RealTimeMinersInformation[minerKeys[1].PublicKey.ToHex()] = new MinerInRound
    {
        Pubkey = minerKeys[1].PublicKey.ToHex(),
        FinalOrderOfNextRound = 1,  // Duplicate order
        OutValue = HashHelper.ComputeFrom("out2")
    };
    
    maliciousRound.RealTimeMinersInformation[minerKeys[2].PublicKey.ToHex()] = new MinerInRound
    {
        Pubkey = minerKeys[2].PublicKey.ToHex(),
        FinalOrderOfNextRound = 2,
        OutValue = HashHelper.ComputeFrom("out3")
    };
    
    var nextRoundInput = NextRoundInput.Create(maliciousRound, ByteString.Empty);
    
    // Attempt to submit malicious NextRound
    var result = await AEDPoSContractStub.NextRound.SendAsync(nextRoundInput);
    
    // BUG: This should fail but validation incorrectly passes
    // The next round will have two miners with Order = 1
    var newRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    var minersWithOrder1 = newRound.RealTimeMinersInformation.Values.Count(m => m.Order == 1);
    minersWithOrder1.ShouldBe(2); // Proves the vulnerability - two miners have same order!
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L33-35)
```text
    // Update consensus information, create a new round.
    rpc NextRound (NextRoundInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/aedpos_contract.proto (L266-300)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-86)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L60-65)
```csharp
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-89)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-165)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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
