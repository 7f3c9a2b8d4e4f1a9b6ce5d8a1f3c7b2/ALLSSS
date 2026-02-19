# Audit Report

## Title
VotersCount Accounting Error Due to Asymmetric Increment/Decrement Logic in Multiple-Vote Withdrawal Scenarios

## Summary
The Vote contract's `VotersCount` field uses asymmetric accounting logic that increments by 1 for every vote cast but only decrements by 1 when a voter withdraws their last vote. This causes permanent inflation of `VotersCount` when voters cast multiple votes and withdraw them, corrupting a fundamental governance metric documented as representing "the total number of voters."

## Finding Description
The vulnerability stems from a mismatch between increment and decrement logic for the `VotersCount` field:

**Increment Logic**: When any user calls `Vote()`, it invokes `UpdateVotingResult()` which unconditionally increments `VotersCount` by 1 for every vote cast, regardless of whether the voter already has active votes for that voting item. [1](#0-0) 

**Decrement Logic**: When a user calls `Withdraw()`, it only decrements `VotersCount` by 1 if the voter has no remaining active votes after the withdrawal. If the voter still has other active votes for that voting item, `VotersCount` remains unchanged. [2](#0-1) 

**No Validation**: The `GetVotingResult()` view method directly returns the stored `VotingResult` without any validation or consistency checks. [3](#0-2) 

**Execution Path Demonstrating the Bug**:
1. Voter A calls `Vote()` → `VotersCount` increments to 1, A has 1 active vote
2. Voter A calls `Vote()` again → `VotersCount` increments to 2, A has 2 active votes
3. Voter A calls `Withdraw()` on first vote → A still has 1 active vote, so `VotersCount` stays at 2
4. Voter A calls `Withdraw()` on second vote → A now has 0 active votes, so `VotersCount` decrements to 1
5. Final state: `VotersCount` = 1 but actual active voters = 0

This behavior is confirmed in the existing test suite where user3 casts two votes in phase 2, resulting in `VotersCount` = 7 despite only 3 unique voters participating. [4](#0-3) 

The protobuf documentation explicitly describes `voters_count` as "The total number of voters," but the implementation fails to track unique voters correctly. [5](#0-4) 

## Impact Explanation
**Data Integrity Corruption - Medium Severity**:

The vulnerability corrupts a fundamental voting metric that governance systems rely upon:

1. **Permanent Misrepresentation**: Once a voter casts multiple votes and withdraws them, `VotersCount` becomes permanently inflated for that voting item. The magnitude of inflation equals the number of "extra" votes cast by all voters who later fully withdraw.

2. **Governance Metrics Corruption**: Any governance dashboard, analytics tool, or decision-making system relying on `VotersCount` receives inflated participation data. This could influence governance decisions by misrepresenting voter engagement.

3. **Election Contract Exposure**: The Election contract exposes a `GetVotersCount()` method that directly returns this corrupted value for consensus participation tracking. [6](#0-5) 

The severity is **Medium** rather than High because:
- No direct fund loss or theft occurs
- No unauthorized state changes to critical protocol parameters
- No privilege escalation or authorization bypass
- Impact limited to data integrity of governance metrics

However, the bug is deterministic and affects every voting item where voters exercise the normal behavior of casting multiple votes.

## Likelihood Explanation
**High Likelihood**:

This vulnerability manifests through normal, legitimate voting operations:

1. **Public Entry Points**: Both `Vote()` and `Withdraw()` are public methods accessible to any user without special permissions. [7](#0-6) [8](#0-7) 

2. **No Special Preconditions**: The bug requires only that a voting item exists and allows multiple votes per voter, which is standard behavior in the Vote contract.

3. **Inevitable Occurrence**: The accounting error accumulates automatically whenever users follow the pattern of voting multiple times and then withdrawing votes. This happens as a side effect of legitimate voting behavior, not malicious exploitation.

4. **Reproducible**: The test suite contains a case demonstrating this exact behavior, confirming it occurs under normal AElf runtime conditions.

5. **No Economic Barriers**: Only requires normal voting transaction fees, no special setup or expensive operations.

The bug manifests through everyday governance participation patterns, making it highly likely to occur frequently across the protocol's voting items.

## Recommendation
Modify the accounting logic to track unique voters rather than vote operations. The fix requires maintaining a per-voter, per-voting-item flag to track whether a voter currently has any active votes:

**Option 1 - Track First Vote Flag**: 
- In `UpdateVotingResult()`: Only increment `VotersCount` if this is the voter's first active vote for this voting item
- In `Withdraw()`: Only decrement `VotersCount` if the voter is removing their last active vote (existing logic is correct)

**Option 2 - Recompute on Demand**:
- Remove `VotersCount` from stored state
- Compute it dynamically in `GetVotingResult()` by counting unique voters from the `VotedItemsMap`

**Option 3 - Add Voter Set**:
- Maintain a set of addresses that have active votes for each voting item
- Update `VotersCount` to reflect the size of this set

The simplest fix is Option 1, which requires checking if the voter already has active votes before incrementing:

```csharp
private void UpdateVotingResult(VotingItem votingItem, string option, long amount, Address voter)
{
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    if (!votingResult.Results.ContainsKey(option)) votingResult.Results.Add(option, 0);

    var currentVotes = votingResult.Results[option];
    votingResult.Results[option] = currentVotes.Add(amount);
    
    // Only increment VotersCount if this is the voter's first active vote
    var votedItems = State.VotedItemsMap[voter];
    if (votedItems?.VotedItemVoteIds[votingItem.VotingItemId.ToHex()]?.ActiveVotes.Count == 0)
    {
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
    }
    
    votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
    State.VotingResults[votingResultHash] = votingResult;
}
```

Note: The `UpdateVotingResult` method signature would need to accept the voter address parameter.

## Proof of Concept
The existing test case in `VoteForBestLanguageTests.cs` demonstrates this vulnerability. The test shows that when user3 votes twice (lines 88-91), the `VotersCount` reaches 7 (line 94) despite only 3 unique voters existing (user1, user2, user3).

To create a minimal proof of concept focusing on a single voter:

```csharp
[Fact]
public async Task Single_Voter_Multiple_Votes_Inflates_VotersCount()
{
    // Register a voting item
    var registerItem = await RegisterVotingItemAsync(100, 1, true, DefaultSender, 2);
    var votingItemId = registerItem.VotingItemId;
    var user = Accounts[1];
    
    // User votes once - VotersCount should be 1
    await Vote(user.KeyPair, votingItemId, registerItem.Options[0], 100);
    var result1 = await GetVotingResult(votingItemId, 1);
    result1.VotersCount.ShouldBe(1); // Correct
    
    // Same user votes again - VotersCount should still be 1 (same voter)
    await Vote(user.KeyPair, votingItemId, registerItem.Options[1], 100);
    var result2 = await GetVotingResult(votingItemId, 1);
    result2.VotersCount.ShouldBe(1); // FAILS: Actually returns 2
    
    // Get user's vote IDs
    var voteIds = await GetVoteIds(user.KeyPair, votingItemId);
    voteIds.ActiveVotes.Count.ShouldBe(2);
    
    // User withdraws first vote - VotersCount should still be 1 (still has active vote)
    await Withdraw(user.KeyPair, voteIds.ActiveVotes[0]);
    var result3 = await GetVotingResult(votingItemId, 1);
    result3.VotersCount.ShouldBe(1); // FAILS: Actually returns 2
    
    // User withdraws second vote - VotersCount should be 0 (no more voters)
    await Withdraw(user.KeyPair, voteIds.ActiveVotes[1]);
    var result4 = await GetVotingResult(votingItemId, 1);
    result4.VotersCount.ShouldBe(0); // FAILS: Actually returns 1
    
    // Demonstrates: VotersCount = 1 but no active voters remain
}
```

This test demonstrates the core issue: a single voter casting multiple votes and withdrawing them leaves `VotersCount` inflated by 1, misrepresenting the actual number of active voters.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-90)
```csharp
    public override Empty Vote(VoteInput input)
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L178-178)
```csharp
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L191-191)
```csharp
    public override Empty Withdraw(WithdrawInput input)
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L217-218)
```csharp
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);
```

**File:** contract/AElf.Contracts.Vote/ViewMethods.cs (L34-42)
```csharp
    public override VotingResult GetVotingResult(GetVotingResultInput input)
    {
        var votingResultHash = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = input.SnapshotNumber
        }.GetHash();
        return State.VotingResults[votingResultHash];
    }
```

**File:** test/AElf.Contracts.Vote.Tests/Full/VoteForBestLanguageTests.cs (L87-94)
```csharp
            //user3 vote new option 3 twice
            var transactionResult3 = await Vote(user3.KeyPair, registerItem.VotingItemId, options[2], 100);
            transactionResult3.Status.ShouldBe(TransactionResultStatus.Mined);
            transactionResult3 = await Vote(user3.KeyPair, registerItem.VotingItemId, options[2], 100);
            transactionResult3.Status.ShouldBe(TransactionResultStatus.Mined);

            var votingResult = await GetVotingResult(registerItem.VotingItemId, 2);
            votingResult.VotersCount.ShouldBe(7);
```

**File:** protobuf/vote_contract.proto (L169-170)
```text
    // The total number of voters.
    int64 voters_count = 4;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L224-229)
```csharp
    public override Int64Value GetVotersCount(Empty input)
    {
        return new Int64Value
        {
            Value = State.VoteContract.GetLatestVotingResult.Call(State.MinerElectionVotingItemId.Value).VotersCount
        };
```
