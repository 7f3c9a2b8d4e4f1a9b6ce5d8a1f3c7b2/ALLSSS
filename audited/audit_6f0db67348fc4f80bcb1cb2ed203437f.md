### Title
Term Transition Race Condition: Election Results Not Finalized Before Miner List Update

### Summary
The consensus command generation for term transitions does not account for election snapshot timing, allowing election results to be manipulated at the exact moment of term change. The miner list for the next term is determined by calling `GetVictories` at block production time without any freeze period, enabling attackers to front-run term transitions with vote changes and potentially gain unauthorized miner status for an entire term period (typically 7 days).

### Finding Description

**Root Cause:**
The term transition flow lacks an election finalization mechanism. When `isNewTerm` is true in `TerminateRoundCommandStrategy.GetAEDPoSConsensusCommand()`, the system sets the consensus behaviour to `NextTerm` [1](#0-0)  but provides no protection against concurrent election changes.

**Execution Path:**

1. **Term Change Decision:** When `NeedToChangeTerm` returns true (checking if 2/3 of miners mined past the period threshold) [2](#0-1) , the behaviour provider returns `AElfConsensusBehaviour.NextTerm` [3](#0-2) 

2. **Miner List Retrieval:** During NextTerm block production, `GetConsensusExtraDataForNextTerm` calls `GenerateFirstRoundOfNextTerm` [4](#0-3)  which invokes `TryToGetVictories` to obtain the current election winners [5](#0-4) 

3. **Election State Query:** `TryToGetVictories` calls the Election contract's `GetVictories` method at that exact moment [6](#0-5) , which returns candidates ranked by their current `ObtainedActiveVotedVotesAmount` [7](#0-6) 

4. **Vote Mutability:** Throughout this process, users can:
   - Change their votes via `ChangeVotingOption` at any time before lock expiration [8](#0-7) , which immediately updates `ObtainedActiveVotedVotesAmount` [9](#0-8) 
   - Cast new votes that instantly affect candidate vote totals [10](#0-9) 
   - Withdraw votes after lock expiry [11](#0-10) 

5. **Snapshot Timing:** The `TakeSnapshot` call in `ProcessNextTerm` occurs AFTER the miner list has already been updated [12](#0-11)  and only records the previous term's state, providing no validation of the new election results.

**Why Existing Protections Fail:**
- No freeze period prevents voting operations near term boundaries
- No "election finalization" step validates result stability before use
- The snapshot mechanism only archives historical data, not election validation
- Lock times constrain withdrawal but not vote changes before expiry

### Impact Explanation

**Direct Harm:**
1. **Unauthorized Miner Selection:** Attackers can manipulate their ranking to become block producers for an entire term (default: 604800 seconds / 7 days) [13](#0-12) 
2. **Revenue Theft:** Illegitimate miners capture block rewards, transaction fees, and Treasury profit distributions intended for legitimate elected miners
3. **Consensus Integrity Compromise:** The miner list no longer reflects the true election outcome, violating the core invariant of miner schedule integrity

**Who is Affected:**
- Legitimate candidates at ranking boundaries who lose miner status
- Token holders whose votes are effectively nullified by last-second manipulation
- The network through reduced consensus integrity

**Severity Justification:**
- **Critical Impact:** Entire term's governance compromised (~7 days of blocks)
- **Financial Damage:** Block rewards + fees + profit share for full term period
- **Consensus Invariant Violation:** Miner list integrity requirement explicitly breached

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Sufficient voting tokens (either owned or delegated) to shift boundary rankings
2. Ability to submit vote transactions at term boundaries
3. For maximum impact: existing votes not yet locked or capital for new votes

**Attack Complexity:**
- **Low-Medium:** Attack requires monitoring for `NeedToChangeTerm` conditions and timing transactions appropriately
- **Observable Trigger:** The 2/3 miner threshold check provides a predictable signal
- **Transaction Ordering:** Standard transaction submission can be timed to execute before NextTerm block

**Feasibility Conditions:**
- Attacker is near ranking boundary (#N or #N+1 position) OR can influence boundary candidate
- Has votes with remaining lock time allowing changes OR capital for new votes
- Can detect approaching term transition (publicly observable blockchain state)

**Economic Rationality:**
- **High ROI:** Term-long miner status provides significant rewards justifying vote lock capital
- **Temporary Lock:** Attack only requires capital locked during manipulation window
- **Repeatable:** Can be executed at every term boundary

**Detection Constraints:**
- Vote changes are publicly visible but by the time detected, miner list is already locked
- No automated defense mechanism exists to prevent or rollback such manipulation

### Recommendation

**Code-Level Mitigation:**

1. **Implement Election Freeze Period:**
   In `GetConsensusExtraDataForNextTerm`, add validation that election snapshot was captured at least N blocks (e.g., 100 blocks) before term transition:
   ```csharp
   // Capture election snapshot at fixed block before term end
   var snapshotBlockHeight = CalculateElectionSnapshotHeight(nextTermNumber);
   var frozenElectionResults = GetFrozenElectionSnapshot(snapshotBlockHeight);
   ```

2. **Add Snapshot-Based Miner Selection:**
   Modify `TryToGetVictories` to accept a snapshot block height parameter instead of using current state:
   ```csharp
   private bool TryToGetVictories(long snapshotTermNumber, out MinerList victories)
   ```

3. **Enforce Vote Lock During Freeze:**
   Add term-boundary checks in `ChangeVotingOption` and `Vote`:
   ```csharp
   var nextTermThreshold = GetNextTermTransitionTimestamp();
   Assert(Context.CurrentBlockTime.AddSeconds(FREEZE_PERIOD) < nextTermThreshold, 
          "Voting operations locked during term transition freeze period");
   ```

**Invariant Checks:**
- Assert that miner list in `ProcessNextTerm` matches pre-captured snapshot
- Verify no vote changes occurred during freeze window
- Log discrepancies between real-time and frozen election results

**Test Cases:**
1. Attempt to change vote during freeze period (should fail)
2. Submit vote transaction before NextTerm block (verify doesn't affect result if after snapshot)
3. Verify term transition uses frozen snapshot even if real-time votes differ
4. Confirm legitimate vote changes before freeze window are properly included

### Proof of Concept

**Initial State:**
- Current term number: 5
- Miner count: 17
- Attacker's current ranking: #18 (just below threshold)
- Attacker controls voting power (either direct tokens or influence over voters)
- Term period: 604800 seconds (7 days)

**Attack Steps:**

1. **Monitor Chain State:**
   - Observe `GetCurrentRoundInformation` to detect when miners are approaching term threshold
   - Calculate when `NeedToChangeTerm` will return true based on period seconds

2. **Prepare Vote Transaction:**
   - If attacker has existing vote: prepare `ChangeVotingOption` to vote for self (if lock not expired)
   - OR prepare new `Vote` transaction with sufficient amount to push into top 17

3. **Execute Front-Run:**
   - Submit vote transaction with high gas to prioritize execution
   - Transaction executes in block N

4. **NextTerm Block Produced:**
   - Block N+1: NextTerm block calls `GetConsensusExtraDataForNextTerm`
   - `TryToGetVictories` calls `GetVictories` which now sees attacker in position #17
   - Miner list generated includes attacker

5. **Term Transition:**
   - `ProcessNextTerm` updates miner list with attacker included
   - Miner list locked for next 604800 seconds

**Expected vs Actual Result:**
- **Expected:** Miner list reflects stable election results from before manipulation window
- **Actual:** Miner list includes attacker who manipulated votes at last moment

**Success Condition:**
- Attacker's public key appears in `State.MinerList[termNumber+1]` despite not having legitimate long-term support
- Attacker mines blocks and receives rewards during term 6
- Original #17 miner loses position despite having more sustained voter support

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L31-31)
```csharp
                        Behaviour = _isNewTerm ? AElfConsensusBehaviour.NextTerm : AElfConsensusBehaviour.NextRound
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-242)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-35)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L209-209)
```csharp
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-81)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L23-31)
```csharp
    public override Empty ChangeVotingOption(ChangeVotingOptionInput input)
    {
        var targetInformation = State.CandidateInformationMap[input.CandidatePubkey];
        AssertValidCandidateInformation(targetInformation);
        var votingRecord = State.VoteContract.GetVotingRecord.Call(input.VoteId);
        Assert(Context.Sender == votingRecord.Voter, "No permission to change current vote's option.");
        var actualLockedSeconds = Context.CurrentBlockTime.Seconds.Sub(votingRecord.VoteTimestamp.Seconds);
        var claimedLockingSeconds = State.LockTimeMap[input.VoteId];
        Assert(actualLockedSeconds < claimedLockingSeconds, "This vote already expired.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L66-67)
```csharp
        oldCandidateVotes.ObtainedActiveVotedVotesAmount =
            oldCandidateVotes.ObtainedActiveVotedVotesAmount.Sub(votingRecord.Amount);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L562-563)
```csharp
            candidateVotes.ObtainedActiveVotedVotesAmount =
                candidateVotes.ObtainedActiveVotedVotesAmount.Add(amount);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L658-659)
```csharp
        candidateVotes.ObtainedActiveVotedVotesAmount =
            candidateVotes.ObtainedActiveVotedVotesAmount.Sub(votingRecord.Amount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-218)
```csharp
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
```
