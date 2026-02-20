# Audit Report

## Title
Conflict Resolution Failure in ApplyNormalConsensusData Causes Duplicate Mining Orders and Consensus Breakdown

## Summary
The conflict resolution mechanism in `ApplyNormalConsensusData()` fails to guarantee unique `FinalOrderOfNextRound` values when all mining orders are occupied. This allows duplicate order assignments to persist through normal block production, breaking the fundamental consensus invariant and causing chain halt or permanent fork when the next round is generated.

## Finding Description

The vulnerability exists in the conflict resolution logic that handles `FinalOrderOfNextRound` collisions during consensus data updates. [1](#0-0) 

When a miner produces a block, their new `supposedOrderOfNextRound` is calculated from their signature hash. If this conflicts with another miner's existing `FinalOrderOfNextRound`, the conflict resolution loop attempts to find an available order for the conflicted miner. However, the loop checks if ANY miner currently holds each candidate order, including the current block producer's old order (which will be overwritten later). [2](#0-1) 

When all orders 1 through N are occupied, the loop exhausts all candidates without finding a free slot. The conflicted miner retains their original order, then the current miner is unconditionally assigned the same conflicting order, creating duplicates. [3](#0-2) 

This vulnerability is compounded by multiple protection failures:

**1. TuneOrderInformation Propagation Failure:** The mechanism only broadcasts miners where `FinalOrderOfNextRound != SupposedOrderOfNextRound`. Since unresolved conflicts leave miners with matching values, other nodes never learn about the duplicate. [4](#0-3) 

**2. Validation Bypass:** `NextRoundMiningOrderValidationProvider` only runs for `NextRound` behavior, not for `UpdateValue` behavior where duplicates are created. [5](#0-4) 

**3. Ineffective Duplicate Detection:** Even when the validator runs, `.Distinct()` operates on `MinerInRound` objects (protobuf-generated with full field comparison), not on `FinalOrderOfNextRound` values, failing to detect duplicate orders. [6](#0-5) 

**4. State Persistence:** The duplicate values are persisted to on-chain state via `TryToUpdateRoundInformation`. [7](#0-6) [8](#0-7) 

**5. Signature Variance by Height:** When miners produce multiple blocks without a `PreviousInValue`, a fake value is generated using `pubkey + CurrentHeight`, ensuring each block produces different signatures and different supposed orders. [9](#0-8) 

## Impact Explanation

When `GenerateNextRoundInformation` processes the current round with duplicate `FinalOrderOfNextRound` values, critical failures occur: [10](#0-9) 

**Critical Failures:**

1. **Duplicate Mining Schedules:** Both miners receive `Order = FinalOrderOfNextRound` and identical `ExpectedMiningTime`, scheduling simultaneous block production that violates time-slot consensus rules.

2. **Order Slot Corruption:** The `occupiedOrders` list contains duplicate values, reducing `ableOrders` count. If miners who didn't mine need orders from the reduced pool, `ableOrders[i]` throws `IndexOutOfRangeException`, halting consensus. [11](#0-10) 

3. **Non-deterministic Round Generation:** The `OrderBy(m => m.FinalOrderOfNextRound)` with duplicates relies on dictionary iteration order, which can vary across nodes after serialization/deserialization, causing different nodes to generate different next rounds and permanently forking the chain.

**Severity: HIGH** - Breaks the fundamental consensus invariant that each miner has a unique mining order and time slot. Results in chain halt or permanent fork, affecting all network participants.

## Likelihood Explanation

**Trigger Conditions:**
1. All N miners have produced at least one block (orders 1-N occupied)
2. A miner produces an additional block in the same round (common via tiny blocks)
3. Their new signature-derived order conflicts with existing miner
4. All other orders occupied, so conflict resolution fails

**Attack Complexity: LOW**
- Happens during normal block production (UpdateValue behavior)
- No special permissions required beyond being a miner
- Signature calculation naturally varies per block height
- Standard protocol behavior [12](#0-11) 

**Probability: MEDIUM-HIGH** - In active rounds where all miners participate, preconditions are frequently met. The hash-based order calculation makes conflicts probabilistic but regular as miners produce multiple blocks per round.

## Recommendation

Fix the conflict resolution loop to exclude the current miner's existing order when checking for available orders:

```csharp
foreach (var orderConflictedMiner in conflicts)
    for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
    {
        var maybeNewOrder = i > minersCount ? i % minersCount : i;
        // Exclude current miner's existing order from the check
        if (RealTimeMinersInformation.Values
            .Where(m => m.Pubkey != pubkey)
            .All(m => m.FinalOrderOfNextRound != maybeNewOrder))
        {
            RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound = maybeNewOrder;
            break;
        }
    }
```

Additionally, add validation for duplicate `FinalOrderOfNextRound` values in `UpdateValueValidationProvider` to catch any remaining edge cases.

## Proof of Concept

```csharp
[Fact]
public void ApplyNormalConsensusData_CreatesOrderDuplicates_WhenAllOrdersOccupied()
{
    // Setup: Create round with 3 miners, all orders occupied
    var round = new Round();
    var miner1 = "miner1";
    var miner2 = "miner2";
    var miner3 = "miner3";
    
    round.RealTimeMinersInformation[miner1] = new MinerInRound 
    { 
        Pubkey = miner1, 
        FinalOrderOfNextRound = 1,
        SupposedOrderOfNextRound = 1
    };
    round.RealTimeMinersInformation[miner2] = new MinerInRound 
    { 
        Pubkey = miner2, 
        FinalOrderOfNextRound = 2,
        SupposedOrderOfNextRound = 2
    };
    round.RealTimeMinersInformation[miner3] = new MinerInRound 
    { 
        Pubkey = miner3, 
        FinalOrderOfNextRound = 3,
        SupposedOrderOfNextRound = 3
    };
    
    // Miner1 produces another block with signature that hashes to order 2 (conflict with miner2)
    var signature = Hash.FromString("test_signature_that_maps_to_order_2");
    var outValue = Hash.FromString("out");
    var previousInValue = Hash.FromString("prev");
    
    // Apply consensus data - this should trigger the bug
    var updatedRound = round.ApplyNormalConsensusData(miner1, previousInValue, outValue, signature);
    
    // Verify: Both miner1 and miner2 now have FinalOrderOfNextRound = 2
    Assert.Equal(2, updatedRound.RealTimeMinersInformation[miner1].FinalOrderOfNextRound);
    Assert.Equal(2, updatedRound.RealTimeMinersInformation[miner2].FinalOrderOfNextRound);
    
    // This breaks consensus - duplicate mining orders exist
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-47)
```csharp
    public Round ApplyNormalConsensusData(string pubkey, Hash previousInValue, Hash outValue, Hash signature)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return this;

        RealTimeMinersInformation[pubkey].OutValue = outValue;
        RealTimeMinersInformation[pubkey].Signature = signature;
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;

        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

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

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-88)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L126-132)
```csharp
    private bool TryToUpdateRoundInformation(Round round)
    {
        var ri = State.Rounds[round.RoundNumber];
        if (ri == null) return false;
        State.Rounds[round.RoundNumber] = round;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L55-134)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataToPublishOutValue(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.

        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
            if (triggerInformation.PreviousInValue != null &&
                triggerInformation.PreviousInValue != Hash.Empty)
            {
                Context.LogDebug(
                    () => $"Previous in value in trigger information: {triggerInformation.PreviousInValue}");
                // Self check.
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
                else
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
            }
            else
            {
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
            }
        }

        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);

        Context.LogDebug(
            () => "Previous in value after ApplyNormalConsensusData: " +
                  $"{updatedRound.RealTimeMinersInformation[pubkey].PreviousInValue}");

        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;

        // Update secret pieces of latest in value.
        
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }

        // To publish Out Value.
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

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

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```
