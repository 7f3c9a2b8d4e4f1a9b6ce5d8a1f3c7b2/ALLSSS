# Audit Report

## Title
Term Change Suppression via Block Timestamp Manipulation

## Summary
Malicious miners controlling 2/3 of the miner set can prevent legitimate term changes indefinitely by setting arbitrarily old block timestamps. The consensus system's term change mechanism relies on `ActualMiningTime` values without validating that block timestamps have a reasonable lower bound, allowing colluding miners to suppress term transitions and maintain permanent control over the blockchain.

## Finding Description

The vulnerability exists in the AEDPoS consensus term change decision logic. The entry point is `GetConsensusBehaviourToTerminateCurrentRound()` which determines whether to trigger a term change by calling `NeedToChangeTerm`: [1](#0-0) 

The `NeedToChangeTerm` function counts how many miners have `ActualMiningTimes` that meet the term change threshold, requiring `MinersCountOfConsent` (2/3 + 1 of total miners) to return true: [2](#0-1) 

The threshold calculation in `IsTimeToChangeTerm` determines if a timestamp indicates a new term period: [3](#0-2) 

**Root Cause**: `ActualMiningTime` values are directly set from `Context.CurrentBlockTime` (the block header timestamp) without any lower-bound validation: [4](#0-3) [5](#0-4) [6](#0-5) 

These timestamps are then stored in the round state: [7](#0-6) [8](#0-7) 

**Why Protections Fail**:

1. Block timestamp validation only prevents timestamps too far in the **future**, not timestamps that are too old: [9](#0-8) 

2. The `TimeSlotValidationProvider` validates the **previous** `ActualMiningTime` from the base round state, not the current block's timestamp being added. When checking if `latestActualMiningTime < expectedMiningTime`, arbitrarily old timestamps pass the validation since they are less than the current round's expected mining time: [10](#0-9) 

3. The client-side check in `MiningRequestService` can be bypassed by malicious node operators: [11](#0-10) 

4. `MinersCountOfConsent` requires 2/3 + 1 consensus: [12](#0-11) 

## Impact Explanation

**Critical Consensus/Governance Integrity Compromise**: This vulnerability breaks a fundamental invariant of the consensus system - that term changes should occur at regular intervals based on elapsed time. The impact is severe:

1. **Election Bypass**: New candidates voted in through the election system cannot take office because term changes never occur. The `ProcessNextTerm` function that updates miner lists, releases treasury funds, and records election snapshots is never called: [13](#0-12) 

2. **Permanent Centralization**: The same 2/3 colluding miners remain in power indefinitely, creating a permanent oligarchy that nullifies the democratic election mechanism.

3. **Treasury Control**: Term changes trigger treasury releases. Suppressing term changes gives malicious miners control over when treasury funds are released: [14](#0-13) 

4. **Reward System Manipulation**: Block production rewards and profit distributions tied to term cycles can be manipulated.

## Likelihood Explanation

**Attacker Capabilities**: Requires controlling 2/3 of the current miner set (typically 7 out of 10 miners).

**Attack Complexity**: Low - Miners simply modify their node software to set block timestamps below the term change boundary. The calculation `(blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds)` will return an old term number when timestamps are artificially low.

**Feasibility**: 
- Attackers must control 2/3 of miner positions (realistic if they won elections legitimately or exploited other vulnerabilities)
- No special privileges required beyond being block producers
- Timestamps must stay within `AllowedFutureBlockTimeSpan` (4 seconds) but can be arbitrarily old
- Attack is deterministic and sustainable indefinitely once initiated

**Detection Difficulty**: High - Block timestamps appear valid (not in the far future), making the suppression difficult to attribute to malicious behavior versus other system issues.

## Recommendation

Implement lower-bound validation for block timestamps to ensure they cannot be set arbitrarily in the past:

1. **Add validation in `TimeSlotValidationProvider`** to check that the current block's timestamp (`Context.CurrentBlockTime`) is within a reasonable range of the expected mining time, not just validating previous timestamps.

2. **Enforce monotonic timestamp progression** by validating that `Context.CurrentBlockTime > previousBlockTime` during block validation.

3. **Add consensus-level timestamp checks** to ensure `Context.CurrentBlockTime >= ExpectedMiningTime - toleranceWindow` where `toleranceWindow` accounts for reasonable clock skew.

4. **Implement detection mechanisms** to alert when ActualMiningTimes consistently lag behind expected times, indicating potential timestamp manipulation.

Example fix in `TimeSlotValidationProvider`:

```csharp
// Add validation of current block timestamp
private bool ValidateCurrentBlockTimestamp(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var expectedMiningTime = minerInRound.ExpectedMiningTime;
    
    // Ensure current block time is not too far before expected mining time
    var minAllowedTime = expectedMiningTime.AddMilliseconds(-validationContext.BaseRound.GetMiningInterval());
    if (validationContext.CurrentBlockTime < minAllowedTime)
    {
        return false; // Block timestamp too old
    }
    
    return true;
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test chain with 10 miners where 7 are controlled by the attacker
2. Having the 7 malicious miners set their block timestamps to values before the term change boundary
3. Observing that `NeedToChangeTerm` returns false because only 3 honest miners have timestamps past the boundary (below the required threshold of 7)
4. Verifying that `ProcessNextTerm` is never called, preventing miner list updates, treasury releases, and election snapshot recording

The attack succeeds because:
- `BlockValidationProvider` only checks timestamps aren't too far in the future
- `TimeSlotValidationProvider` validates the previous `ActualMiningTime` from base round state, allowing the current old timestamp to be added
- `NeedToChangeTerm` uses these old timestamps and fails to detect that sufficient time has elapsed for a term change

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L162-163)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L195-196)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L304-304)
```csharp
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L133-139)
```csharp
        if (block.Header.Height != AElfConstants.GenesisBlockHeight &&
            block.Header.Time.ToDateTime() - TimestampHelper.GetUtcNow().ToDateTime() >
            KernelConstants.AllowedFutureBlockTimeSpan.ToTimeSpan())
        {
            Logger.LogDebug("Future block received {Block}, {BlockTime}", block, block.Header.Time.ToDateTime());
            return Task.FromResult(false);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** src/AElf.Kernel/Miner/Application/IMiningRequestService.cs (L47-64)
```csharp
    private bool ValidateBlockMiningTime(Timestamp blockTime, Timestamp miningDueTime,
        Duration blockExecutionDuration)
    {
        if (miningDueTime - Duration.FromTimeSpan(TimeSpan.FromMilliseconds(250)) <
            blockTime + blockExecutionDuration)
        {
            Logger.LogDebug(
                "Mining canceled because mining time slot expired. MiningDueTime: {MiningDueTime}, BlockTime: {BlockTime}, Duration: {BlockExecutionDuration}",
                miningDueTime, blockTime, blockExecutionDuration);
            return false;
        }

        if (blockTime + blockExecutionDuration >= TimestampHelper.GetUtcNow()) return true;
        Logger.LogDebug(
            "Will cancel mining due to timeout: Actual mining time: {BlockTime}, execution limit: {BlockExecutionDuration} ms",
            blockTime, blockExecutionDuration.Milliseconds());
        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```
