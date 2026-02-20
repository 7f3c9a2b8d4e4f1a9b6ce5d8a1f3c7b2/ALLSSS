# Audit Report

## Title
Conflict Resolution Failure in ApplyNormalConsensusData Causes Duplicate Mining Orders and Consensus Breakdown

## Summary
The conflict resolution mechanism in `ApplyNormalConsensusData()` fails to guarantee unique `FinalOrderOfNextRound` values when all mining orders are occupied. This allows duplicate order assignments to persist through normal block production, breaking the fundamental consensus invariant and causing chain halt or permanent fork when the next round is generated.

## Finding Description

The vulnerability exists in the conflict resolution logic that handles `FinalOrderOfNextRound` collisions during consensus data updates. [1](#0-0) 

When a miner produces a block, their new `supposedOrderOfNextRound` is calculated from their signature hash. If this conflicts with another miner's existing `FinalOrderOfNextRound`, the conflict resolution loop attempts to find an available order for the conflicted miner. However, the loop checks if ANY miner currently holds each candidate order, including the conflicted miner's own current order and the current block producer's old order (which will be overwritten). When all orders 1 through N are occupied, the loop exhausts all candidates without finding a free slot. The conflicted miner retains their original order, then the current miner is unconditionally assigned the same conflicting order, creating duplicates.

This vulnerability is compounded by multiple protection failures:

**1. TuneOrderInformation Propagation Failure:** [2](#0-1) 

The mechanism only broadcasts miners where `FinalOrderOfNextRound != SupposedOrderOfNextRound`. Since unresolved conflicts leave miners with matching values, other nodes never learn about the duplicate.

**2. Validation Bypass:** [3](#0-2) 

`NextRoundMiningOrderValidationProvider` only runs for `NextRound` behavior, not for `UpdateValue` behavior where duplicates are created.

**3. Ineffective Duplicate Detection:** [4](#0-3) 

Even when the validator runs, `.Distinct()` operates on `MinerInRound` objects (protobuf-generated with full field comparison), not on `FinalOrderOfNextRound` values, failing to detect duplicate orders.

**4. State Persistence:** [5](#0-4) 

The duplicate values are persisted to on-chain state via `ProcessUpdateValue`, where they remain until next round generation.

**5. Signature Variance by Height:** [6](#0-5) 

When miners produce multiple blocks without a `PreviousInValue`, a fake value is generated using `pubkey + CurrentHeight`, ensuring each block produces different signatures and different supposed orders, making conflicts probabilistic but regular.

## Impact Explanation

When `GenerateNextRoundInformation` processes the current round with duplicate `FinalOrderOfNextRound` values: [7](#0-6) 

**Critical Failures:**

1. **Duplicate Mining Schedules:** Both miners receive `Order = FinalOrderOfNextRound` and identical `ExpectedMiningTime`, scheduling simultaneous block production that violates time-slot consensus rules.

2. **Order Slot Corruption:** [8](#0-7) 

The `occupiedOrders` list contains duplicate values, reducing `ableOrders` count. If miners who didn't mine need orders from the reduced pool, `ableOrders[i]` throws `IndexOutOfRangeException`, halting consensus.

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
- Tiny block production is standard protocol behavior [9](#0-8) 

**Probability: MEDIUM-HIGH** - In active rounds where all miners participate, preconditions are frequently met. The hash-based order calculation makes conflicts probabilistic but regular as miners produce multiple blocks per round.

## Recommendation

Fix the conflict resolution logic in `ApplyNormalConsensusData` to properly handle the case when all orders are occupied:

1. **Improve conflict resolution**: When searching for available orders, exclude the current miner's order from the check since it will be overwritten.

2. **Fix duplicate detection**: Change `NextRoundMiningOrderValidationProvider` to check distinct `FinalOrderOfNextRound` values:
```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Select(m => m.FinalOrderOfNextRound)
    .Where(o => o > 0)
    .Distinct()
    .Count();
```

3. **Add validation for UpdateValue**: Include `NextRoundMiningOrderValidationProvider` in the UpdateValue behavior validation chain.

4. **Deterministic ordering**: Use stable sort with secondary key (e.g., pubkey) when ordering by `FinalOrderOfNextRound`.

## Proof of Concept

The vulnerability can be triggered in a consensus test scenario where:
1. Setup a round with N miners (e.g., 5 miners)
2. Have all N miners produce their first block (occupying orders 1-N)
3. Have one miner produce a second tiny block whose signature hash maps to an already-occupied order
4. Observe that conflict resolution fails and both miners retain the same `FinalOrderOfNextRound`
5. Trigger `NextRound` generation
6. Observe either `IndexOutOfRangeException` or non-deterministic round generation

The test would validate that duplicate `FinalOrderOfNextRound` values exist in the round state after step 3, and demonstrate consensus failure in step 5.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
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
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L94-108)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-44)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L25-52)
```csharp
        public override ConsensusCommand GetAEDPoSConsensusCommand()
        {
            // Provided pubkey can mine a block after TinyBlockMinimumInterval ms.
            var arrangedMiningTime =
                MiningTimeArrangingService.ArrangeMiningTimeWithOffset(CurrentBlockTime,
                    TinyBlockMinimumInterval);

            var roundStartTime = CurrentRound.GetRoundStartTime();
            var currentTimeSlotStartTime = CurrentBlockTime < roundStartTime
                ? roundStartTime.AddMilliseconds(-MiningInterval)
                : CurrentRound.RoundNumber == 1
                    ? MinerInRound.ActualMiningTimes.First()
                    : MinerInRound.ExpectedMiningTime;
            var currentTimeSlotEndTime = currentTimeSlotStartTime.AddMilliseconds(MiningInterval);

            return arrangedMiningTime > currentTimeSlotEndTime
                ? new TerminateRoundCommandStrategy(CurrentRound, Pubkey, CurrentBlockTime, false)
                    .GetAEDPoSConsensusCommand() // The arranged mining time already beyond the time slot.
                : new ConsensusCommand
                {
                    Hint = new AElfConsensusHint { Behaviour = AElfConsensusBehaviour.TinyBlock }.ToByteString(),
                    ArrangedMiningTime = arrangedMiningTime,
                    MiningDueTime = currentTimeSlotEndTime,
                    LimitMillisecondsOfMiningBlock = IsLastTinyBlockOfCurrentSlot()
                        ? LastTinyBlockMiningLimit
                        : DefaultBlockMiningLimit
                };
        }
```
