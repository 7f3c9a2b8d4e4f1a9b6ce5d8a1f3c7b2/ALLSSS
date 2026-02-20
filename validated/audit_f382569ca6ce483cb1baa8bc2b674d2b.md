# Audit Report

## Title
Duplicate Mining Order Validation Bypass Allows Consensus Disruption

## Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` method incorrectly uses `Distinct()` on entire `MinerInRound` objects instead of on `FinalOrderOfNextRound` values, allowing a malicious miner to inject duplicate mining orders that bypass validation and corrupt the consensus state, causing multiple miners to receive identical time slots in subsequent rounds and disrupting blockchain progression.

## Finding Description

The validation logic in `NextRoundMiningOrderValidationProvider` attempts to verify that miners who produced blocks have determined unique next round orders. [1](#0-0) 

However, the implementation uses `Distinct()` on entire `MinerInRound` protobuf objects rather than on the `FinalOrderOfNextRound` values themselves. [2](#0-1) 

The `MinerInRound` protobuf message contains 17 fields including pubkey, order, expected_mining_time, produced_blocks, in_value, out_value, signature, and final_order_of_next_round. [3](#0-2) 

When protobuf generates C# classes, the `Equals()` and `GetHashCode()` methods compare all fields. Therefore, two miners with identical `FinalOrderOfNextRound` values but different `Pubkey` fields are considered distinct by the `Distinct()` operator, allowing the validation to pass incorrectly.

**Evidence of Design Intent:**

The codebase explicitly handles `FinalOrderOfNextRound` conflicts during normal consensus data updates, proving the system requires unique order values. [4](#0-3) 

This conflict resolution mechanism reassigns miners when duplicates are detected, confirming that duplicate `FinalOrderOfNextRound` values violate the consensus invariant.

**Exploitation Path:**

1. The validation provider is registered during NextRound behavior transitions. [5](#0-4) 

2. A malicious miner produces a block with consensus extra data containing duplicate `FinalOrderOfNextRound` values across different miner entries.

3. The flawed validation passes because `Distinct()` sees different MinerInRound objects (different pubkeys).

4. The corrupt round data is persisted to blockchain state. [6](#0-5) 

5. During next round generation, each miner's `FinalOrderOfNextRound` is directly assigned as their `Order` in the new round. [7](#0-6) 

6. Multiple miners receive identical `Order` and `ExpectedMiningTime` values, causing them to attempt mining simultaneously.

7. The logic for calculating available orders uses `Contains()` which only checks membership. [8](#0-7) 

## Impact Explanation

**Critical Consensus Violation:**
- Multiple miners receive identical mining time slots, creating competing blocks at the same height
- Extra block producer selection fails when multiple miners share the designated order
- Round progression halts as the scheduling invariant (unique order per miner) is violated
- Chain experiences persistent forking or complete stall

**Network-Wide Effects:**
- All network participants cannot achieve consensus on block production sequence
- Transaction finality is compromised due to competing blocks
- dApp functionality and user transactions fail
- Manual intervention required to restore consensus state

This breaks the fundamental "Correct round transitions and miner schedule integrity" invariant required for AEDPoS consensus operation.

## Likelihood Explanation

**Attacker Profile:**
- Must be an active miner (obtainable through staking and election)
- No special privileges required beyond normal miner capabilities
- Can execute during any NextRound transition when scheduled

**Attack Simplicity:**
- Single block with crafted consensus extra data containing duplicate `FinalOrderOfNextRound` values
- No timing dependencies or complex state manipulation
- Deterministic success due to validation flaw

**Operational Feasibility:**
- The NextRound method is publicly accessible. [9](#0-8) 
- Permission check only requires being in the miner list. [10](#0-9) 
- No additional duplicate-detection mechanisms exist beyond the flawed validation

**Likelihood: High** - Any miner can execute this attack with trivial effort and guaranteed success.

## Recommendation

Fix the validation logic to check for duplicate `FinalOrderOfNextRound` values rather than duplicate `MinerInRound` objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

This ensures that the validation correctly detects when multiple miners have been assigned the same next round order.

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateFinalOrderOfNextRound_ShouldFailValidation()
{
    // Setup: Get current round with 3 miners
    var currentRound = await GetCurrentRoundInformation();
    
    // Create next round with duplicate FinalOrderOfNextRound values
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        RealTimeMinersInformation =
        {
            {
                "MinerA", new MinerInRound
                {
                    Pubkey = "MinerA",
                    FinalOrderOfNextRound = 1,
                    OutValue = Hash.FromString("outA")
                }
            },
            {
                "MinerB", new MinerInRound
                {
                    Pubkey = "MinerB",
                    FinalOrderOfNextRound = 1, // DUPLICATE!
                    OutValue = Hash.FromString("outB")
                }
            }
        }
    };
    
    // Validate using NextRoundMiningOrderValidationProvider
    var context = new ConsensusValidationContext
    {
        ProvidedRound = maliciousRound
    };
    
    var provider = new NextRoundMiningOrderValidationProvider();
    var result = provider.ValidateHeaderInformation(context);
    
    // Current implementation incorrectly passes
    Assert.True(result.Success); // BUG: Should fail but passes
    
    // After fix, this should fail
    // Assert.False(result.Success);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L11-12)
```csharp
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L23-40)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-156)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
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
