# Audit Report

## Title
Late UpdateValue Transaction Can Corrupt Next Round Mining Schedule

## Summary
The `ProcessUpdateValue` method fails to validate the `round_id` field in `UpdateValueInput`, allowing stale transactions from previous rounds to corrupt mining schedules in subsequent rounds. This enables manipulation of miner positions and false mining participation records.

## Finding Description

The `UpdateValueInput` message includes a `round_id` field explicitly documented to "ensure the values to update will be apply to correct round by comparing round id." [1](#0-0) 

However, `ProcessUpdateValue` retrieves the current round from storage and directly applies the update without validating that `updateValueInput.RoundId` matches the current round. [2](#0-1) 

The current round is retrieved via `TryToGetCurrentRoundInformation`, which returns whatever `State.CurrentRoundNumber` points to. [3](#0-2) 

**Attack Scenario:**

When a miner produces a block with `UpdateValue` behavior, `ApplyNormalConsensusData` calculates `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` based on the miner's signature hash. [4](#0-3) 

These values are packaged into `UpdateValueInput` with the current round's `RoundIdForValidation`. [5](#0-4) 

If the extra block producer executes `NextRound` before the `UpdateValue` transaction processes, the round advances to N+1. When the late `UpdateValue` transaction executes, `ProcessUpdateValue` applies its data to Round N+1 instead of Round N.

The critical impact occurs during next round generation. `GenerateNextRoundInformation` identifies miners who participated by checking `SupposedOrderOfNextRound != 0`, and their `FinalOrderOfNextRound` determines their position in the next round. [6](#0-5) [7](#0-6) 

**Why Existing Protections Fail:**

`UpdateValueValidationProvider` only validates that consensus information (OutValue, Signature) is properly filled and that previous in values are correct - it does NOT check `round_id`. [8](#0-7) 

`PreCheck` only verifies the miner is in the current or previous round's miner list, not that the transaction data belongs to the current round. [9](#0-8) 

`EnsureTransactionOnlyExecutedOnceInOneBlock` prevents duplicate consensus transactions within one block but cannot prevent stale transactions from previous rounds. [10](#0-9) 

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant of correct round transitions and miner schedule integrity. Specific harms include:

1. **False Mining Records**: Miners can appear to have mined in rounds where they didn't participate, corrupting the historical mining record used for reward calculations and reputation tracking.

2. **Mining Schedule Manipulation**: Attackers can influence their position in future rounds by injecting their `FinalOrderOfNextRound` value into incorrect rounds, potentially securing more favorable time slots.

3. **Schedule Disruption**: Legitimate miners' expected positions can be displaced by the corrupted order calculations, affecting network predictability and fairness.

4. **Compounding Effect**: Since `GenerateNextRoundInformation` carries forward `ProducedBlocks` and `MissedTimeSlots` counts, repeated exploitation can lead to sustained manipulation across multiple rounds.

The consensus protocol's fairness guarantee is violated, as mining positions should be determined by cryptographic signatures from actual block production, not by stale transactions applied to wrong rounds.

## Likelihood Explanation

This vulnerability is highly exploitable due to natural timing conditions in distributed blockchain systems:

1. **Public Entry Point**: `UpdateValue` is a public RPC method that any authorized miner can call. [11](#0-10) 

2. **Natural Race Conditions**: The timing window occurs when a miner produces a block near round boundaries and network latency delays transaction inclusion, allowing the extra block producer's `NextRound` to execute first.

3. **Minimal Attack Requirements**: Only requires being an authorized miner - no special privileges beyond normal mining participation.

4. **Difficult Detection**: The transaction passes all existing validation checks and executes successfully, making malicious exploitation hard to distinguish from natural timing issues.

5. **Deliberate Exploitation**: A malicious miner can intentionally delay broadcasting their `UpdateValue` transaction, wait for the round to advance, then submit it to manipulate their position in the next round.

## Recommendation

Add round_id validation in `ProcessUpdateValue` method:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // Add this validation
    Assert(updateValueInput.RoundId == currentRound.RoundId, 
        "Round id mismatch - UpdateValue transaction is stale.");
    
    // Rest of the existing logic...
}
```

This ensures that `UpdateValue` transactions can only be applied to the round they were created for, preventing stale transactions from corrupting subsequent rounds.

## Proof of Concept

A test would demonstrate:
1. Miner produces block in Round N, generating `UpdateValueInput` with Round N's `RoundId`
2. Extra block producer executes `NextRound`, advancing to Round N+1
3. Miner's `UpdateValue` transaction executes, incorrectly updating Round N+1
4. Next round generation includes miner as having participated in Round N+1
5. Miner's position in Round N+2 is determined by their injected `FinalOrderOfNextRound` value

The test would verify that without the validation, the miner appears in Round N+1's participation records despite not actually mining in that round, and their position in Round N+2 is influenced by stale data from Round N.

### Citations

**File:** protobuf/aedpos_contract.proto (L29-31)
```text
    // Update consensus information.
    rpc UpdateValue (UpdateValueInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/aedpos_contract.proto (L199-200)
```text
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L35-50)
```csharp
        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
            PreviousInValue = minerInRound.PreviousInValue ?? Hash.Empty,
            RoundId = RoundIdForValidation,
            ProducedBlocks = minerInRound.ProducedBlocks,
            ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
            TuneOrderInformation = { tuneOrderInformation },
            EncryptedPieces = { minerInRound.EncryptedPieces },
            DecryptedPieces = { decryptedPreviousInValues },
            MinersPreviousInValues = { minersPreviousInValues },
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
            RandomNumber = randomNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-135)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }

    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```
