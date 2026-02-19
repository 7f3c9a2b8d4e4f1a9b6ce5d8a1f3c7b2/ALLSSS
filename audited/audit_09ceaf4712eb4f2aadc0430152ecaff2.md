### Title
Withdrawal Function Corrupts Historical Snapshots and Current Aggregate Vote Counts

### Summary
The `Withdraw()` function modifies VotingResult data for the snapshot number stored in the original voting record, even after that snapshot has been finalized by `TakeSnapshot()`. This retroactively corrupts historical snapshot data and causes current snapshots to have incorrect aggregate counts (VotesAmount, VotersCount), leading to flawed governance decisions and reward calculations that depend on these values.

### Finding Description

The vulnerability exists in the `Withdraw()` function's snapshot handling logic. [1](#0-0) 

When a user votes, the voting record captures the current snapshot number: [2](#0-1) 

When `TakeSnapshot()` is called to advance snapshots, it finalizes the previous snapshot and creates a new VotingResult for the next snapshot, **copying forward the aggregate counts** from the previous snapshot: [3](#0-2) 

However, when `Withdraw()` is executed, it retrieves the VotingResult using the snapshot number from the voting record and modifies **only that snapshot's data**, without updating any subsequent snapshots: [4](#0-3) 

**Root Cause**: The withdrawal logic assumes votes exist only in their original snapshot, but the TakeSnapshot mechanism copies aggregate counts forward to new snapshots. When a withdrawal modifies the original snapshot, subsequent snapshots retain stale copied counts that no longer reflect reality.

**Why Existing Protections Fail**: There is no check preventing withdrawals after snapshot advancement, and no mechanism to propagate withdrawal effects to subsequent snapshots that inherited the vote counts.

### Impact Explanation

**Direct Impacts**:

1. **Historical Data Corruption**: Finalized snapshot results are retroactively modified after `SnapshotEndTimestamp` is set, violating snapshot immutability guarantees.

2. **Incorrect Current Snapshot Counts**: The current snapshot's `VotesAmount` and `VotersCount` become inflated because they include withdrawn votes that were copied forward but never decremented when withdrawn.

3. **Governance Decision Corruption**: The Election contract queries these values for critical operations: [5](#0-4) 

These functions return incorrect data when called after withdrawals occur from historical snapshots.

4. **Token Double-Use**: Users can withdraw tokens locked in previous snapshots, unlock them for other uses, while the current snapshot still counts those votes in its aggregate totals.

**Quantified Impact**: For a voting item with N snapshots, if users withdraw votes after snapshot advancement:
- Historical snapshots 1 to N-1 get modified post-finalization
- Current snapshot N shows VotesAmount = (actual votes in N) + (withdrawn votes from 1 to N-1)
- Election governance decisions based on these inflated counts will be incorrect

**Affected Parties**: All users relying on snapshot results for governance, reward distribution, or consensus decisions.

**Severity Justification**: HIGH - This violates core data integrity invariants, corrupts governance decision inputs, and enables token double-counting in critical consensus mechanisms.

### Likelihood Explanation

**Attacker Capabilities**: Any user who can vote and withdraw (standard user operations, no special privileges required).

**Attack Complexity**: LOW
1. Vote with significant amount in snapshot N
2. Wait for TakeSnapshot(N) to be called, advancing to snapshot N+1
3. Call Withdraw() to remove vote from snapshot N
4. Snapshot N+1 retains inflated counts, snapshot N is corrupted

**Feasibility Conditions**: 
- Voting items with multiple snapshots (common in governance scenarios)
- Standard vote and withdraw operations are public methods
- No time locks or restrictions prevent this sequence

**Detection Constraints**: The issue manifests in state data inconsistencies that may not be immediately visible to observers. The test suite actually demonstrates this behavior without recognizing it as problematic: [6](#0-5) 

This test takes a snapshot BEFORE withdrawing, then verifies the historical snapshot is modified - confirming the vulnerability exists in the current implementation.

**Probability**: HIGH - This occurs naturally whenever users withdraw votes after snapshot advancement, which is a normal operational flow in multi-snapshot voting scenarios.

### Recommendation

**Code-Level Mitigation**:

Option 1 (Prevent Historical Withdrawals):
Add a check in `Withdraw()` to prevent withdrawals from finalized snapshots:
```csharp
var votingItem = State.VotingItems[votingRecord.VotingItemId];
Assert(votingRecord.SnapshotNumber == votingItem.CurrentSnapshotNumber,
    "Cannot withdraw votes from finalized snapshots.");
```

Option 2 (Update All Subsequent Snapshots):
When withdrawing, iterate through all snapshots from the original to current and update their aggregate counts:
```csharp
for (long i = votingRecord.SnapshotNumber + 1; i <= votingItem.CurrentSnapshotNumber; i++)
{
    var subsequentHash = GetVotingResultHash(votingRecord.VotingItemId, i);
    var subsequentResult = State.VotingResults[subsequentHash];
    if (subsequentResult != null)
    {
        subsequentResult.VotesAmount = subsequentResult.VotesAmount.Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            subsequentResult.VotersCount = subsequentResult.VotersCount.Sub(1);
        State.VotingResults[subsequentHash] = subsequentResult;
    }
}
```

**Invariant Checks to Add**:
- After TakeSnapshot: previous snapshot's SnapshotEndTimestamp must be set and immutable
- Before Withdraw: validate snapshot number against current snapshot
- After any state change: VotesAmount must equal sum of active voting records for that snapshot

**Test Cases to Prevent Regression**:
1. Test withdrawal after snapshot advancement - should either fail or update all subsequent snapshots
2. Verify historical snapshot data remains unchanged after being finalized
3. Verify current snapshot aggregate counts match actual active votes after withdrawals

### Proof of Concept

**Initial State**:
- Register voting item with `total_snapshot_number = 2`
- VotingItem: `CurrentSnapshotNumber = 1`

**Step 1 - Alice Votes in Snapshot 1**:
```
Vote(votingItemId, voter=Alice, amount=1000, option="A")
```
- VotingRecord[voteId]: `{voter: Alice, amount: 1000, snapshotNumber: 1, option: "A"}`
- VotingResult[snapshot 1]: `{Results["A"]: 1000, VotesAmount: 1000, VotersCount: 1}`

**Step 2 - Advance to Snapshot 2**:
```
TakeSnapshot(votingItemId, snapshotNumber=1)
```
- VotingResult[snapshot 1]: `{Results["A"]: 1000, VotesAmount: 1000, VotersCount: 1, SnapshotEndTimestamp: T1}`
- VotingResult[snapshot 2]: `{Results: {}, VotesAmount: 1000, VotersCount: 1}` ← Copied from snapshot 1
- VotingItem: `CurrentSnapshotNumber = 2`

**Step 3 - Bob Votes in Snapshot 2**:
```
Vote(votingItemId, voter=Bob, amount=500, option="B")
```
- VotingResult[snapshot 2]: `{Results["B"]: 500, VotesAmount: 1500, VotersCount: 2}`

**Step 4 - Alice Withdraws (Exploit)**:
```
Withdraw(voteId=Alice's vote)
```
- Line 207 uses `votingRecord.SnapshotNumber = 1`
- VotingResult[snapshot 1]: `{Results["A"]: 0, VotesAmount: 0, VotersCount: 0}` ← Historical data corrupted
- VotingResult[snapshot 2]: `{Results["B"]: 500, VotesAmount: 1500, VotersCount: 2}` ← **UNCHANGED, INCORRECT**
- Alice's 1000 tokens unlocked

**Expected vs Actual Result**:

Expected:
- Snapshot 2 VotesAmount should be 500 (only Bob's vote)
- Snapshot 2 VotersCount should be 1 (only Bob)
- Snapshot 1 should remain immutable at 1000 votes

Actual:
- Snapshot 2 VotesAmount is 1500 (includes withdrawn vote)
- Snapshot 2 VotersCount is 2 (includes withdrawn voter)
- Snapshot 1 was modified to 0 votes (corrupted historical data)

**Success Condition**: Call `GetVotingResult(votingItemId, snapshotNumber=2)` and observe `VotesAmount=1500` despite only 500 tokens actually being locked, proving the aggregate count is incorrect.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L105-117)
```csharp
        var votingRecord = new VotingRecord
        {
            VotingItemId = input.VotingItemId,
            Amount = amount,
            SnapshotNumber = votingItem.CurrentSnapshotNumber,
            Option = input.Option,
            IsWithdrawn = false,
            VoteTimestamp = Context.CurrentBlockTime,
            Voter = input.Voter,
            IsChangeTarget = input.IsChangeTarget
        };

        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L207-207)
```csharp
        var votingResultHash = GetVotingResultHash(votingRecord.VotingItemId, votingRecord.SnapshotNumber);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-222)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L241-273)
```csharp
    public override Empty TakeSnapshot(TakeSnapshotInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);

        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can take snapshot.");

        Assert(votingItem.CurrentSnapshotNumber - 1 < votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");

        // Update previous voting going information.
        var previousVotingResultHash = GetVotingResultHash(input.VotingItemId, votingItem.CurrentSnapshotNumber);
        var previousVotingResult = State.VotingResults[previousVotingResultHash];
        previousVotingResult.SnapshotEndTimestamp = Context.CurrentBlockTime;
        State.VotingResults[previousVotingResultHash] = previousVotingResult;

        Assert(votingItem.CurrentSnapshotNumber == input.SnapshotNumber,
            $"Can only take snapshot of current snapshot number: {votingItem.CurrentSnapshotNumber}, but {input.SnapshotNumber}");
        var nextSnapshotNumber = input.SnapshotNumber.Add(1);
        votingItem.CurrentSnapshotNumber = nextSnapshotNumber;
        State.VotingItems[votingItem.VotingItemId] = votingItem;

        // Initial next voting going information.
        var currentVotingGoingHash = GetVotingResultHash(input.VotingItemId, nextSnapshotNumber);
        State.VotingResults[currentVotingGoingHash] = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = nextSnapshotNumber,
            SnapshotStartTimestamp = Context.CurrentBlockTime,
            VotersCount = previousVotingResult.VotersCount,
            VotesAmount = previousVotingResult.VotesAmount
        };
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L224-238)
```csharp
    public override Int64Value GetVotersCount(Empty input)
    {
        return new Int64Value
        {
            Value = State.VoteContract.GetLatestVotingResult.Call(State.MinerElectionVotingItemId.Value).VotersCount
        };
    }

    public override Int64Value GetVotesAmount(Empty input)
    {
        return new Int64Value
        {
            Value = State.VoteContract.GetLatestVotingResult.Call(State.MinerElectionVotingItemId.Value).VotesAmount
        };
    }
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L259-277)
```csharp
        await TakeSnapshot(voteItemId, 1);


        var beforeBalance = GetUserBalance(voteAddress);
        var transactionResult = await Withdraw(voteUser, currentVoteId);
        transactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        voteItems = await VoteContractStub.GetVotedItems.CallAsync(voteAddress);
        voteItems.VotedItemVoteIds[voteItemId.ToHex()].ActiveVotes.Count.ShouldBe(0);
        voteItems.VotedItemVoteIds[voteItemId.ToHex()].WithdrawnVotes.Count.ShouldBe(1);
        var voteRecordAfterWithdraw = await VoteContractStub.GetVotingRecord.CallAsync(currentVoteId);
        voteRecordAfterWithdraw.IsWithdrawn.ShouldBe(true);
        var voteResultAfterWithdraw = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
        {
            SnapshotNumber = 1,
            VotingItemId = voteItemId
        });
        voteResultBeforeWithdraw.VotesAmount.Sub(voteResultAfterWithdraw.VotesAmount).ShouldBe(voteAmount);
        voteResultBeforeWithdraw.Results[registerItem.Options[1]]
            .Sub(voteResultAfterWithdraw.Results[registerItem.Options[1]]).ShouldBe(voteAmount);
```
