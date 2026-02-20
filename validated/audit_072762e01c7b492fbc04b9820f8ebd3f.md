# Audit Report

## Title
Cross-Snapshot Withdrawal Leaves Stale Vote Counts in Subsequent Snapshots

## Summary
The `Withdraw()` function in the Vote contract only updates the voting result for the snapshot where the vote was originally cast, but fails to update subsequent snapshots that have inherited cumulative `VotersCount` and `VotesAmount` metrics. This causes withdrawn votes to persist in later snapshots' aggregate statistics, leading to inflated governance metrics.

## Finding Description

The vulnerability stems from a fundamental mismatch between how snapshots inherit cumulative data and how withdrawals update that data.

When `TakeSnapshot()` creates a new snapshot, it copies the previous snapshot's `VotersCount` and `VotesAmount` as starting cumulative metrics: [1](#0-0) 

However, when a voter withdraws their vote via `Withdraw()`, the function retrieves the voting result using only the snapshot number stored in the original voting record: [2](#0-1) 

This means `Withdraw()` only updates the voting result of the original snapshot: [3](#0-2) 

**Root Cause:** The withdrawal logic does not iterate through or update any subsequent snapshots that have already carried over the vote counts. Once `TakeSnapshot()` copies the cumulative counts forward, those copies remain immutable with respect to withdrawals from earlier snapshots.

**Attack Scenario:**
1. Attacker votes with 10,000 tokens in snapshot 1
2. Sponsor calls `TakeSnapshot()` creating snapshot 2 (inherits VotesAmount=10,000, VotersCount=1)
3. Attacker withdraws the vote
4. Snapshot 1 correctly shows VotesAmount=0, VotersCount=0
5. Snapshot 2 incorrectly retains VotesAmount=10,000, VotersCount=1

## Impact Explanation

The inflated metrics compromise systems that rely on accurate voting statistics:

1. **Governance Integrity:** The Election contract's `GetVotersCount()` and `GetVotesAmount()` methods query the latest voting result and will return inflated values: [4](#0-3) 

2. **Quorum Manipulation:** If governance decisions or reward distributions rely on voter participation thresholds, attackers can artificially inflate these metrics by voting in early snapshots, waiting for snapshot inheritance, then withdrawing while leaving later snapshots with inflated counts.

3. **Multi-Snapshot Amplification:** With multiple snapshots, a single vote can be counted multiple times across snapshots even after withdrawal, creating a multiplier effect on aggregate statistics.

While this does not cause direct fund loss, it compromises the integrity of governance metrics that external contracts, dApps, or governance mechanisms rely upon for decision-making.

## Likelihood Explanation

**Attacker Capabilities:** Any voter can execute this - no special permissions required beyond standard voting operations.

**Attack Complexity:** Very low - the sequence is straightforward:
- Vote in snapshot N
- Wait for `TakeSnapshot()` to create snapshot N+1
- Call `Withdraw()` to remove the vote
- Snapshot N+1 retains inflated counts

**Feasibility:** Always feasible when:
- Voting item has multiple snapshots (`TotalSnapshotNumber > 1`)
- Either token locking is enabled (voter can withdraw after snapshot) OR token locking is disabled (sponsor can withdraw on behalf)

**Detection Difficulty:** The discrepancy is not easily detectable without comparing snapshot results and tracing vote histories, as inflated values appear as normal aggregate statistics.

The existing test suite demonstrates this scenario without detecting the issue: [5](#0-4) 

The test votes in snapshot 1 (line 246), takes snapshot 2 (line 259), then withdraws (line 263). It only verifies snapshot 1's state after withdrawal (lines 270-278) but never checks that snapshot 2 retains the inflated counts.

## Recommendation

The `Withdraw()` function should update all subsequent snapshots that have inherited the withdrawn vote's counts. Implement one of these solutions:

**Solution 1: Update subsequent snapshots on withdrawal**
```csharp
public override Empty Withdraw(WithdrawInput input)
{
    // ... existing code ...
    
    // Update original snapshot
    var votingResultHash = GetVotingResultHash(votingRecord.VotingItemId, votingRecord.SnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    votingResult.Results[votingRecord.Option] = votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
    votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);
    if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
        votingResult.VotersCount = votingResult.VotersCount.Sub(1);
    State.VotingResults[votingResultHash] = votingResult;
    
    // NEW: Update all subsequent snapshots
    var votingItem = State.VotingItems[votingRecord.VotingItemId];
    for (var i = votingRecord.SnapshotNumber + 1; i <= votingItem.CurrentSnapshotNumber; i++)
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
    
    // ... rest of existing code ...
}
```

**Solution 2: Don't copy cumulative counts in TakeSnapshot**
Only copy counts that should truly carry over (like Results for specific options), but recalculate VotersCount and VotesAmount dynamically based on active votes.

## Proof of Concept

```csharp
[Fact]
public async Task CrossSnapshot_Withdrawal_Inflates_Subsequent_Snapshots()
{
    // Register voting item with 2 snapshots
    var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 2);
    var voteUser = Accounts[1].KeyPair;
    var voteItemId = registerItem.VotingItemId;
    var voteAmount = 10000;
    
    // Vote in snapshot 1
    await Vote(voteUser, voteItemId, registerItem.Options[0], voteAmount);
    
    // Verify snapshot 1 has correct counts
    var snapshot1Before = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        SnapshotNumber = 1,
        VotingItemId = voteItemId
    });
    snapshot1Before.VotersCount.ShouldBe(1);
    snapshot1Before.VotesAmount.ShouldBe(voteAmount);
    
    // Take snapshot 2 (inherits counts from snapshot 1)
    await TakeSnapshot(voteItemId, 1);
    
    // Verify snapshot 2 inherited counts
    var snapshot2Before = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        SnapshotNumber = 2,
        VotingItemId = voteItemId
    });
    snapshot2Before.VotersCount.ShouldBe(1);
    snapshot2Before.VotesAmount.ShouldBe(voteAmount);
    
    // Withdraw the vote
    var voteIds = await GetVoteIds(voteUser, voteItemId);
    await Withdraw(voteUser, voteIds.ActiveVotes.First());
    
    // Verify snapshot 1 correctly updated to zero
    var snapshot1After = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        SnapshotNumber = 1,
        VotingItemId = voteItemId
    });
    snapshot1After.VotersCount.ShouldBe(0);
    snapshot1After.VotesAmount.ShouldBe(0);
    
    // BUG: Snapshot 2 still has inflated counts!
    var snapshot2After = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        SnapshotNumber = 2,
        VotingItemId = voteItemId
    });
    
    // This assertion will FAIL, proving the vulnerability
    snapshot2After.VotersCount.ShouldBe(0); // Actually still 1!
    snapshot2After.VotesAmount.ShouldBe(0); // Actually still 10000!
}
```

## Notes

This vulnerability represents a critical governance integrity issue. While it doesn't directly result in fund loss, it fundamentally undermines the accuracy of voting metrics that are exposed through the Election contract and potentially used by other governance mechanisms. The ability to artificially inflate participation metrics across multiple snapshots could enable attackers to manipulate quorum calculations, reward distributions, or any external systems that rely on these metrics for decision-making. The fix should ensure that withdrawals properly cascade to all affected snapshots to maintain data consistency.

### Citations

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L264-271)
```csharp
        State.VotingResults[currentVotingGoingHash] = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = nextSnapshotNumber,
            SnapshotStartTimestamp = Context.CurrentBlockTime,
            VotersCount = previousVotingResult.VotersCount,
            VotesAmount = previousVotingResult.VotesAmount
        };
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

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L238-280)
```csharp
    public async Task VoteContract_Withdraw_Success_Test()
    {
        var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);

        var voteUser = Accounts[1].KeyPair;
        var voteAddress = Accounts[1].Address;
        var voteItemId = registerItem.VotingItemId;
        var voteAmount = 100;
        await Vote(voteUser, voteItemId, registerItem.Options[1], voteAmount);
        var voteIds = await GetVoteIds(voteUser, voteItemId);
        var currentVoteId = voteIds.ActiveVotes.First();
        var voteRecordBeforeWithdraw = await VoteContractStub.GetVotingRecord.CallAsync(currentVoteId);
        voteRecordBeforeWithdraw.IsWithdrawn.ShouldBe(false);
        var voteItems = await VoteContractStub.GetVotedItems.CallAsync(voteAddress);
        voteItems.VotedItemVoteIds[voteItemId.ToHex()].ActiveVotes.Count.ShouldBe(1);
        voteItems.VotedItemVoteIds[voteItemId.ToHex()].WithdrawnVotes.Count.ShouldBe(0);
        var voteResultBeforeWithdraw = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
        {
            SnapshotNumber = 1,
            VotingItemId = voteItemId
        });
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
        voteResultBeforeWithdraw.VotersCount.Sub(1).ShouldBe(voteResultAfterWithdraw.VotersCount);
        var afterBalance = GetUserBalance(voteAddress);
        beforeBalance.ShouldBe(afterBalance - 100);
```
