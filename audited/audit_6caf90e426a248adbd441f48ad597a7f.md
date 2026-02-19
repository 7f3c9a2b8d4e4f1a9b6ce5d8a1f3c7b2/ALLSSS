### Title
Incomplete Block Finalization During Term Transition Due to Mismatch Between Term Change Criteria and LIB Calculation

### Summary
The `NextTerm` consensus command can be generated and executed before sufficient miners have produced `UpdateValue` blocks, causing incomplete Last Irreversible Block (LIB) finalization for the previous round. This occurs because `NeedToChangeTerm` counts all miners with `ActualMiningTimes` (including TinyBlock producers), while LIB calculation only uses miners who produced `UpdateValue` blocks, creating a critical mismatch that can leave consensus data from the terminated round unfinalised.

### Finding Description

The vulnerability exists in the consensus command generation and term transition logic across multiple components:

**Root Cause**: The term change decision uses different criteria than the LIB calculation mechanism, creating a window where term transitions can occur without proper block finalization. [1](#0-0) 

The `NeedToChangeTerm` method checks if at least `MinersCountOfConsent` (2/3+1) miners have `ActualMiningTimes` past the term boundary. However, `ActualMiningTimes` is updated by BOTH `UpdateValue` and `TinyBlock` transactions. [2](#0-1) 

TinyBlock processing adds to `ActualMiningTimes` but does NOT update `ImpliedIrreversibleBlockHeight` or `SupposedOrderOfNextRound`. [3](#0-2) 

Only `UpdateValue` processing sets `SupposedOrderOfNextRound` and updates `ImpliedIrreversibleBlockHeight`. [4](#0-3) 

The `GetMinedMiners` method used for LIB calculation only returns miners where `SupposedOrderOfNextRound != 0`, excluding TinyBlock-only producers. [5](#0-4) 

When LIB is calculated, if `impliedIrreversibleHeights.Count < MinersCountOfConsent`, the calculation returns `libHeight = 0`, failing to finalize blocks. [6](#0-5) 

During `ProcessNextTerm`, NO new LIB calculation occurs. The stale `ConfirmedIrreversibleBlockHeight` from the current round is carried forward to the next term. [7](#0-6) 

### Impact Explanation

**Consensus Integrity Violation**: Blocks from the terminated round may remain unfinalised indefinitely, violating the fundamental consensus guarantee that blocks should reach irreversible status after 2/3+1 confirmation.

**Cross-Chain Security**: If cross-chain contracts rely on LIB heights for verification (common in cross-chain indexing), unfinalised blocks could:
- Prevent valid cross-chain transactions from being verified
- Create inconsistencies in parent/side-chain state synchronization
- Block cross-chain token transfers or message passing

**Block Finality Guarantees**: Applications and users relying on block finality may experience:
- Transactions remaining in unconfirmed state longer than expected
- Potential reorganization of blocks that should be irreversible
- Inconsistent chain state across nodes if some nodes calculate LIB differently

**Severity Justification**: This is a Critical severity issue because it directly undermines the consensus layer's core guarantee of block finality, affecting the entire blockchain's security model and potentially all dependent systems.

### Likelihood Explanation

**Realistic Attack Scenario**: In a network with 7 miners (MinersCountOfConsent = 5):
1. During Round N, 3 miners produce `UpdateValue` blocks
2. 2 additional miners produce only `TinyBlock` blocks (e.g., as extra block producers)
3. All 5 miners have `ActualMiningTimes` past the term period boundary
4. `NeedToChangeTerm` returns true (5 >= 5)
5. One miner generates and executes `NextTerm` command
6. Last LIB calculation used only 3 miners' heights (3 < 5)
7. LIB returns 0 or stale value, leaving Round N-1 blocks unfinalised

**Attacker Capabilities**: No special attacker privileges needed. This can occur naturally during normal consensus operation when:
- Some miners are designated as extra block producers (producing TinyBlocks)
- Network conditions cause some miners to miss their UpdateValue time slots
- Term boundary timing aligns with early round progression

**Feasibility**: HIGH - This is not an attack but a design flaw that can occur during routine operation, especially during the transition period between terms when miner participation may vary.

**Detection Difficulty**: The issue may go undetected because:
- Term transitions appear successful
- Consensus data IS sent to Election contract (no obvious data loss)
- Only the LIB height remains stale, which may not trigger immediate alerts

### Recommendation

**Immediate Fix**: Modify `NeedToChangeTerm` to use the same criteria as LIB calculation.

Replace the current implementation: [1](#0-0) 

With a version that checks miners who have produced UpdateValue blocks (those with `SupposedOrderOfNextRound != 0` or `OutValue != null`), ensuring term transitions only occur when sufficient miners have contributed to LIB consensus.

**Alternative Fix**: Force LIB recalculation during `ProcessNextTerm` before carrying forward the height: [8](#0-7) 

Add LIB calculation logic similar to `ProcessUpdateValue` after line 168, ensuring the LIB reflects maximum possible consensus before term transition.

**Validation Check**: Add assertion in `ProcessNextTerm` that verifies `ConfirmedIrreversibleBlockHeight` meets minimum finalization requirements before allowing term transition.

**Test Cases**:
1. Simulate term transition with mixed UpdateValue/TinyBlock producers
2. Verify LIB includes all eligible blocks from previous round
3. Test cross-chain verification still works after term transitions
4. Ensure no blocks remain unfinalised across term boundaries

### Proof of Concept

**Initial State**:
- Current round: Round N, Term T
- 7 miners in network (MinersCountOfConsent = 5)
- Term period: 604800 seconds (1 week)
- Blockchain start timestamp: T0

**Exploitation Steps**:

1. **Round N begins**: Term period has elapsed, time is now T0 + 604800 seconds

2. **Miner 1 produces UpdateValue block** at time T0 + 604801
   - Sets `ActualMiningTimes`, `SupposedOrderOfNextRound`, `ImpliedIrreversibleBlockHeight`
   - LIB calculated: 1 miner in GetMinedMiners (1 < 5), LIB returns 0

3. **Miner 2 produces UpdateValue block** at time T0 + 604802
   - LIB calculated: 2 miners in GetMinedMiners (2 < 5), LIB returns 0

4. **Miner 3 produces UpdateValue block** at time T0 + 604803
   - LIB calculated: 3 miners in GetMinedMiners (3 < 5), LIB returns 0
   - Current round's `ConfirmedIrreversibleBlockHeight` = 0 (or old stale value)

5. **Miners 4 and 5 produce TinyBlock blocks** at times T0 + 604804, T0 + 604805
   - Only `ActualMiningTimes` updated, NO update to `SupposedOrderOfNextRound` or `ImpliedIrreversibleBlockHeight`
   - No LIB calculation occurs during TinyBlock processing

6. **Miner 6 checks `NeedToChangeTerm`**:
   - 5 miners have `ActualMiningTimes` > T0 + 604800 (term boundary)
   - Returns TRUE (5 >= 5)
   - Generates `NextTerm` command

7. **NextTerm executed**:
   - `ProcessNextTerm` does NOT recalculate LIB
   - Carries forward `ConfirmedIrreversibleBlockHeight = 0` (or stale value) to Term T+1
   
**Expected Result**: All blocks from Round N-1 should be marked as irreversible with proper 2/3+1 consensus.

**Actual Result**: Blocks from Round N-1 remain unfinalised because:
- Only 3 miners contributed to LIB calculation (< MinersCountOfConsent)
- LIB returned 0, leaving `ConfirmedIrreversibleBlockHeight` stale
- Term transition proceeded anyway because `NeedToChangeTerm` counted all 5 miners including TinyBlock producers

**Success Condition**: After term transition, query `ConfirmedIrreversibleBlockHeight` and observe it is significantly lower than expected, demonstrating unfinalised blocks from the previous round.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```
