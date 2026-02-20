# Audit Report

## Title
Cross-Snapshot Withdrawal Leaves Stale Vote Counts in Subsequent Snapshots

## Summary
The `Withdraw()` function in the Vote contract only updates the voting result for the snapshot where the vote was originally cast, but fails to update subsequent snapshots that have inherited cumulative `VotersCount` and `VotesAmount` metrics. This causes withdrawn votes to persist in later snapshots' aggregate statistics, compromising governance metric integrity.

## Finding Description

The vulnerability occurs due to a mismatch between how snapshots inherit cumulative data and how withdrawals update that data.

When `TakeSnapshot()` creates a new snapshot, it copies the previous snapshot's `VotersCount` and `VotesAmount` as inherited cumulative metrics: [1](#0-0) 

However, when a voter withdraws their vote via `Withdraw()`, the function retrieves the voting result using only the snapshot number stored in the original voting record: [2](#0-1) 

This means `Withdraw()` only updates the voting result of the original snapshot, subtracting the withdrawn vote from `VotesAmount`, `Results`, and potentially `VotersCount`: [3](#0-2) 

**Root Cause:** The withdrawal logic does not iterate through or update any subsequent snapshots that have already inherited the vote counts. Once `TakeSnapshot()` copies the cumulative counts forward, those copies remain immutable with respect to withdrawals from earlier snapshots.

**Attack Scenario:**
1. Voter casts vote with 10,000 tokens in snapshot N
2. Sponsor calls `TakeSnapshot()` creating snapshot N+1 (inherits VotesAmount=10,000, VotersCount=1)
3. Voter withdraws the vote
4. Snapshot N correctly shows VotesAmount=0, VotersCount=0
5. Snapshot N+1 incorrectly retains VotesAmount=10,000, VotersCount=1

## Impact Explanation

The inflated metrics compromise systems that rely on accurate voting statistics:

1. **Governance Metric Integrity:** The Election contract exposes `GetVotersCount()` and `GetVotesAmount()` methods that retrieve these values via `GetLatestVotingResult`: [4](#0-3) 

These methods return inflated values for any snapshot following withdrawals from earlier snapshots.

2. **External Contract Dependency:** Any external contracts, dApps, or governance mechanisms relying on voter participation metrics will receive incorrect data, potentially affecting:
   - Quorum calculations
   - Participation rate tracking
   - Governance decision metrics

3. **Multi-Snapshot Amplification:** With multiple snapshots, a single vote can be counted multiple times across snapshots even after withdrawal, creating a multiplier effect on aggregate statistics.

While this does not cause direct fund loss, it violates the fundamental invariant that voting statistics should accurately reflect active votes, compromising governance transparency and metric reliability.

## Likelihood Explanation

**Attacker Capabilities:** Any voter can execute this exploit - no special permissions required beyond standard voting operations.

**Attack Complexity:** Very low:
- Vote in snapshot N
- Wait for `TakeSnapshot()` to create snapshot N+1  
- Call `Withdraw()` to remove the vote
- Snapshot N+1 retains inflated counts

**Feasibility:** Always feasible when:
- Voting item has multiple snapshots (`TotalSnapshotNumber > 1`)
- Either token locking is enabled (voter can withdraw) OR token locking is disabled (sponsor can withdraw on behalf)

**Detection Difficulty:** The discrepancy is not easily detectable without comparing all snapshot results and tracing vote histories, as inflated values appear as normal aggregate statistics.

The existing test suite demonstrates this scenario without detecting the issue: [5](#0-4) 

The test verifies snapshot 1's state after withdrawal but doesn't check that snapshot 2 would retain inflated counts if it existed.

## Recommendation

Modify the `Withdraw()` function to update all subsequent snapshots when a vote is withdrawn. The fix should:

1. After updating the original snapshot's voting result, iterate through all subsequent snapshots up to `CurrentSnapshotNumber`
2. For each subsequent snapshot, decrement the `VotersCount` and `VotesAmount` by the withdrawn amounts
3. Ensure the iteration only affects snapshots that have already been created via `TakeSnapshot()`

Pseudo-code fix:
```
// After updating the original snapshot (line 222)
// Update all subsequent snapshots that inherited these counts
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

## Proof of Concept

```csharp
[Fact]
public async Task CrossSnapshot_Withdrawal_Leaves_Stale_Counts_Test()
{
    // Register voting item with 2 snapshots
    var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 2);
    var voteUser = Accounts[1].KeyPair;
    var voteAddress = Accounts[1].Address;
    var voteAmount = 10000;
    
    // Phase 1: Vote in snapshot 1
    await Vote(voteUser, registerItem.VotingItemId, registerItem.Options[0], voteAmount);
    
    // Verify snapshot 1 has the vote
    var snapshot1Before = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = registerItem.VotingItemId,
        SnapshotNumber = 1
    });
    snapshot1Before.VotesAmount.ShouldBe(voteAmount);
    snapshot1Before.VotersCount.ShouldBe(1);
    
    // Phase 2: Take snapshot to create snapshot 2 (inherits counts)
    await TakeSnapshot(registerItem.VotingItemId, 1);
    
    // Verify snapshot 2 inherited the counts
    var snapshot2Before = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = registerItem.VotingItemId,
        SnapshotNumber = 2
    });
    snapshot2Before.VotesAmount.ShouldBe(voteAmount); // Inherited from snapshot 1
    snapshot2Before.VotersCount.ShouldBe(1); // Inherited from snapshot 1
    
    // Phase 3: Withdraw the vote
    var voteIds = await GetVoteIds(voteUser, registerItem.VotingItemId);
    await Withdraw(voteUser, voteIds.ActiveVotes.First());
    
    // Verify snapshot 1 was updated correctly
    var snapshot1After = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = registerItem.VotingItemId,
        SnapshotNumber = 1
    });
    snapshot1After.VotesAmount.ShouldBe(0); // Correctly updated
    snapshot1After.VotersCount.ShouldBe(0); // Correctly updated
    
    // BUG: Verify snapshot 2 was NOT updated (stale counts remain)
    var snapshot2After = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = registerItem.VotingItemId,
        SnapshotNumber = 2
    });
    
    // This assertion will PASS, proving the vulnerability
    snapshot2After.VotesAmount.ShouldBe(voteAmount); // Still has inflated count!
    snapshot2After.VotersCount.ShouldBe(1); // Still has inflated count!
    
    // Expected behavior: Both should be 0 after withdrawal
    // Actual behavior: Snapshot 2 retains the withdrawn vote counts
}
```

## Notes

This vulnerability affects the **integrity of governance metrics** rather than causing direct financial loss. The key concern is that external systems querying `GetVotersCount()` and `GetVotesAmount()` via the Election contract will receive inflated participation statistics that do not reflect the actual state of active votes. This compromises transparency and could affect any governance decisions or reward distributions that rely on accurate voter participation data.

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

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L238-281)
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
    }
```
