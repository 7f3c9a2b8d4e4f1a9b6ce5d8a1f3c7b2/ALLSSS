# Audit Report

## Title
Term Change Bypassed When Miners with Null OutValue Use UpdateValue Behavior

## Summary
The AEDPoS consensus command generation logic contains a critical flaw where miners who haven't produced blocks in the current round (OutValue == null) incorrectly return `UpdateValue` behavior even when term change conditions are met. This bypasses term transition logic, causing delayed treasury releases, stale election snapshots, incorrect miner statistics, and outdated miner lists.

## Finding Description

The vulnerability exists in the consensus behavior selection flow. When determining which consensus behavior a miner should use, the system follows this path: [1](#0-0) 

When a miner's `OutValue == null` (hasn't mined in current round), the code calls `HandleMinerInNewRound()`. This method returns `UpdateValue` if the time slot hasn't passed: [2](#0-1) 

The critical issue is the early return at line 55. When `HandleMinerInNewRound()` returns `UpdateValue`, execution never reaches line 82 where `GetConsensusBehaviourToTerminateCurrentRound()` checks if term change is needed: [3](#0-2) 

This method performs the term change check via `NeedToChangeTerm()`: [4](#0-3) 

The `NeedToChangeTerm()` logic determines when term transitions should occur based on miner timestamps: [5](#0-4) 

**Why Existing Protections Fail:**

The validation system only validates that the chosen behavior is internally consistent, not whether the correct behavior was selected. When `UpdateValue` is provided, the validator checks UpdateValue-specific constraints: [6](#0-5) [7](#0-6) 

The validator does NOT check whether `NextTerm` should have been used instead of `UpdateValue`.

## Impact Explanation

When a miner with `OutValue == null` produces a block using `UpdateValue` instead of `NextTerm`, the wrong processing function executes:

**Actual Execution - ProcessUpdateValue():** [8](#0-7) 

This only updates the current round information without triggering term transition.

**Expected Execution - ProcessNextTerm():** [9](#0-8) 

**Specific Harms:**

1. **Term Number Not Incremented:** [10](#0-9) 

2. **Miner Statistics Not Reset:** [11](#0-10) 

3. **Miner List Not Updated:** [12](#0-11) 

4. **Treasury Release Delayed:** [13](#0-12) 

5. **Election Snapshot Not Taken:** [14](#0-13) 

This breaks core protocol invariants: voters/stakeholders don't receive expected treasury distributions, election state becomes inconsistent with blockchain state, miner performance tracking becomes incorrect, and the wrong miner set persists.

## Likelihood Explanation

This vulnerability triggers automatically during normal consensus operation with no attacker involvement.

**Trigger Conditions:**
1. Two-thirds of miners have `ActualMiningTimes` meeting the term change threshold (checked by `NeedToChangeTerm()`)
2. A miner who hasn't produced blocks in the current round (`OutValue == null`) is next in the mining rotation  
3. Current block time is within that miner's time slot (`!_isTimeSlotPassed`)

**Probability:** HIGH

In typical AEDPoS operation with multiple miners:
- At the start of each round, all miners have `OutValue == null` until they produce their first block
- If term change conditions are met when the round starts, the first miner(s) to produce blocks will use incorrect `UpdateValue` behavior
- With 21 production nodes (standard in AElf), multiple blocks may be produced with wrong behavior before a miner with `OutValue != null` triggers the term change

**Entry Point:** Public `GetConsensusCommand()` method accessible during normal block production: [15](#0-14) 

No special permissions required - occurs naturally during consensus flow.

## Recommendation

Modify `HandleMinerInNewRound()` to check term change conditions before returning `UpdateValue`. The method should return `Nothing` when term change is needed, allowing execution to reach line 82 where `GetConsensusBehaviourToTerminateCurrentRound()` can properly handle the term transition.

Alternatively, perform the term change check earlier in `GetConsensusBehaviour()` before calling `HandleMinerInNewRound()`, ensuring term transitions take precedence over normal block production.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize consensus with miners and set up conditions where `NeedToChangeTerm()` returns true (2/3+ miners with ActualMiningTimes past term threshold)
2. Call `GetConsensusCommand()` for a miner with `OutValue == null` whose time slot hasn't passed
3. Verify the returned behavior is `UpdateValue` instead of `NextTerm`
4. Execute the consensus command and verify `ProcessUpdateValue()` is called
5. Confirm term number is not incremented, treasury is not released, and election snapshot is not taken

The vulnerability is demonstrated by showing that under term change conditions, miners with `OutValue == null` generate `UpdateValue` commands, bypassing all term transition logic.

---

**Notes:**

This is a design flaw in the behavior selection logic where the order of checks causes term change conditions to be ignored when they should take precedence. The vulnerability has high impact on protocol integrity (delayed treasury releases, stale election state, incorrect miner management) and high likelihood (occurs naturally during normal consensus operation when term changes are due).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L49-56)
```csharp
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-82)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L114-114)
```csharp
            return !_isTimeSlotPassed ? AElfConsensusBehaviour.UpdateValue : AElfConsensusBehaviour.Nothing;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L30-35)
```csharp
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-223)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-54)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();

        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();

        Context.LogDebug(() =>
            $"{currentRound.ToString(_processingBlockMinerPubkey)}\nArranged behaviour: {behaviour.ToString()}");

        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
    }
```
