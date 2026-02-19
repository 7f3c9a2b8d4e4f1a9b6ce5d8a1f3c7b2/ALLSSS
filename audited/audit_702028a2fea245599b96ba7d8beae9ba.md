### Title
Term Change Suppression via Block Timestamp Manipulation

### Summary
Malicious miners controlling 2/3 of the miner set can prevent legitimate term changes indefinitely by manipulating block timestamps. The `NeedToChangeTerm` function relies on miners' `ActualMiningTime` values to determine when a term should change, but there is no validation ensuring these timestamps cannot be set artificially low. This allows colluding miners to maintain permanent control over the consensus system, bypassing elections and governance mechanisms.

### Finding Description

The vulnerability exists in the term change decision logic within the AEDPoS consensus system. The entry point is `GetConsensusBehaviourToTerminateCurrentRound()` which calls `NeedToChangeTerm` to determine whether to trigger a term change: [1](#0-0) 

The `NeedToChangeTerm` function counts how many miners have `ActualMiningTimes` that meet the term change threshold and requires `MinersCountOfConsent` (2/3 + 1 of total miners) to return true: [2](#0-1) 

The term change threshold is calculated by `IsTimeToChangeTerm`: [3](#0-2) 

**Root Cause**: `ActualMiningTime` values are directly set from `Context.CurrentBlockTime` without lower-bound validation: [4](#0-3) [5](#0-4) 

These timestamps are then used when `ProcessUpdateValue` and `ProcessTinyBlock` store them: [6](#0-5) [7](#0-6) 

**Why Protections Fail**:

1. Block timestamp validation only prevents timestamps too far in the **future**, not timestamps that are too old: [8](#0-7) 

2. The `TimeSlotValidationProvider` checks the **previous** `ActualMiningTime` from the base round, not the current block's timestamp being added: [9](#0-8) 

3. There is no validation requiring `Context.CurrentBlockTime >= ExpectedMiningTime` or `Context.CurrentBlockTime >= PreviousBlockTime`.

4. The client-side check in `MiningRequestService` can be bypassed by malicious node operators: [10](#0-9) 

### Impact Explanation

**Consensus/Governance Integrity Compromise**: Malicious miners can maintain permanent control over the blockchain by preventing term changes. This has severe consequences:

1. **Election Bypass**: New candidates voted in through the election system cannot take office because term changes never occur. The `ProcessNextTerm` function that updates miner lists is never called: [11](#0-10) 

2. **Centralization**: The same 2/3 colluding miners remain in power indefinitely, effectively creating a permanent oligarchy despite the democratic election mechanism.

3. **Treasury Control**: Term changes trigger treasury releases. Suppressing term changes allows malicious miners to control when treasury funds are released: [12](#0-11) 

4. **Reward Manipulation**: Block production rewards and profit distributions tied to term cycles can be manipulated.

**Severity**: Critical - This breaks a fundamental invariant of the consensus system (correct round transitions and miner schedule integrity) and allows unauthorized control over governance.

### Likelihood Explanation

**Attacker Capabilities**: Requires controlling 2/3 of the current miner set (7 out of 10 miners in typical configuration).

**Attack Complexity**: Low - Miners simply need to modify their node software to set block timestamps below the term change boundary `blockchainStartTimestamp + (termNumber * periodSeconds)`. Since `MinersCountOfConsent` is calculated as: [13](#0-12) 

For 10 miners: (10 * 2 / 3) + 1 = 7 miners must have timestamps past the boundary. If 7 miners collude to keep timestamps low, only 3 honest miners will have correct timestamps, failing to meet the threshold.

**Feasibility Conditions**:
- Attackers must already control 2/3 of miner positions (realistic if they won elections or exploited other issues)
- No additional privileges beyond being block producers required
- Timestamps must stay within `AllowedFutureBlockTimeSpan` constraint but can be arbitrarily old

**Detection**: Difficult - Block timestamps appear valid (within allowed future range), and the suppression manifests as "term changes not happening" which could be misattributed to other causes.

**Probability**: High likelihood once preconditions are met. The attack is deterministic and sustainable indefinitely once initiated.

### Recommendation

**Immediate Mitigation**:

1. Add lower-bound validation for block timestamps in `ValidateBeforeExecution`:
   - Enforce `Context.CurrentBlockTime >= ExpectedMiningTime` for the current miner
   - Enforce `Context.CurrentBlockTime >= PreviousBlockTime + MinimumBlockInterval`

2. Modify `GetConsensusExtraDataToPublishOutValue` and `GetConsensusExtraDataForTinyBlock` to validate the timestamp being added:

```
Assert(Context.CurrentBlockTime >= minerInRound.ExpectedMiningTime, 
    "Block timestamp cannot be before expected mining time");
```

3. Add an invariant check in `NeedToChangeTerm`: if the current real time (from a trusted time source or median of recent blocks) is significantly past the term boundary, force the term change regardless of miner timestamps.

4. Implement timestamp median validation: require block timestamp to be close to the median of recent block timestamps to prevent large deviations.

**Test Cases**:
- Verify term change occurs even when 2/3 miners set low timestamps
- Test that blocks with `timestamp < ExpectedMiningTime` are rejected
- Verify forced term change after timeout period expires

### Proof of Concept

**Initial State**:
- 10 miners in current term (term 5)
- `blockchainStartTimestamp = T0`
- `periodSeconds = 604800` (7 days)
- Term change should occur at: `T0 + (5 * 604800) = T_boundary`
- 7 miners collude, 3 are honest

**Attack Sequence**:

1. **Setup**: Colluding miners modify their node code to set block timestamps to `T_boundary - 60` (60 seconds before the boundary) regardless of actual time.

2. **Block Production**: As blocks are produced in rounds approaching and past `T_boundary`:
   - 7 malicious miners set `Context.CurrentBlockTime = T_boundary - 60`
   - 3 honest miners set `Context.CurrentBlockTime = actual_time` (past T_boundary)

3. **Term Change Check**: When `GetConsensusBehaviourToTerminateCurrentRound` is called:
   - `NeedToChangeTerm` counts miners with timestamps meeting threshold
   - Only 3 miners have `ActualMiningTime >= T_boundary`
   - Requires 7 miners to meet threshold (MinersCountOfConsent)
   - Returns **false** instead of **true**

4. **Behaviour Selection**:
   - `GetConsensusBehaviourToTerminateCurrentRound` returns `AElfConsensusBehaviour.NextRound` instead of `AElfConsensusBehaviour.NextTerm`
   - `ProcessNextRound` is called instead of `ProcessNextTerm`
   - Miner list is NOT updated, term remains 5

**Expected Result**: Term changes to 6, new miner list from elections takes effect

**Actual Result**: Term remains 5, original miners maintain control indefinitely

**Success Condition**: After multiple rounds past `T_boundary`, term number remains unchanged and election winners cannot become miners.

### Notes

This vulnerability demonstrates a critical timestamp manipulation attack enabled by insufficient validation of block timestamps. The attack is particularly severe because it subverts the democratic election mechanism that is fundamental to the AEDPoS consensus model, allowing a minority coalition (2/3 of miners) to maintain permanent control over the network despite elections indicating different validator preferences from the community.

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
