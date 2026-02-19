# Audit Report

## Title
Quadratic Voting Results Corruption Due to Inconsistent Amount Tracking

## Summary
The Vote contract contains a critical accounting mismatch in quadratic voting. During voting, it increments `Results[option]` by 1 (vote count), but during withdrawal, it decrements by the full token amount. This causes voting tallies to become negative and completely corrupts quadratic voting results.

## Finding Description

The vulnerability exists in how the Vote contract tracks quadratic voting results across two operations:

**During Voting:** When `IsQuadratic` is true, the contract calculates the token amount to lock as `ticketCost * currentVotesCount`. [1](#0-0) 

This token amount is stored in the voting record. [2](#0-1) 

However, when updating voting results, the contract passes `1` (vote count) instead of `amount` (token amount) for quadratic voting. [3](#0-2) 

The `UpdateVotingResult` function then increments both `Results[option]` and `VotesAmount` by this passed value (which is `1` for quadratic voting). [4](#0-3) 

**During Withdrawal:** The withdrawal logic decrements both `Results[option]` and `VotesAmount` by `votingRecord.Amount`, which contains the full token amount, not 1. [5](#0-4) 

**The Mismatch:** For quadratic voting, `Results[option]` is incremented by 1 during voting but decremented by potentially large token amounts during withdrawal, causing the results to become negative and completely corrupted.

## Impact Explanation

This vulnerability has critical impact on voting integrity:

1. **Negative Vote Counts**: After withdrawals, `Results[option]` becomes negative (e.g., 2 - 200 = -198)
2. **Corrupted Tallies**: Vote results no longer represent actual voting outcomes
3. **Broken Governance**: Any decisions based on these vote results will use corrupted data
4. **Feature Unusable**: Quadratic voting is completely non-functional

**Concrete Example:**
- First vote: `Results["OptionA"]` increments by 1, locks 100 tokens
- Second vote: `Results["OptionA"]` increments by 1 (total: 2), locks 200 tokens
- Withdraw second vote: `Results["OptionA"]` decrements by 200 → **Results = -198**

This affects all participants in quadratic voting items, voting sponsors who rely on accurate counts, and any downstream systems depending on vote results.

## Likelihood Explanation

The likelihood of this issue is **Very High**:

1. **No Special Privileges Required**: Any regular user can trigger this by participating in a quadratic voting item
2. **Trivial to Trigger**: Occurs during normal vote and withdrawal operations
3. **No Complex Setup**: Simply requires voting with `IsQuadratic = true` and later withdrawing
4. **Immediate Observable**: Bug manifests on first withdrawal, easily detectable through negative vote counts

The vulnerability is automatically triggered in any quadratic voting scenario where users exercise their legitimate right to withdraw votes.

## Recommendation

Fix the inconsistency by ensuring the same value is used for both incrementing and decrementing voting results. For quadratic voting, the `Results` map should track vote counts (increments of 1), not token amounts.

**Recommended Fix:**
In the `Withdraw` function, when decrementing voting results for quadratic voting, use `1` instead of `votingRecord.Amount`:

```csharp
public override Empty Withdraw(WithdrawInput input)
{
    var votingRecord = State.VotingRecords[input.VoteId];
    var votingItem = State.VotingItems[votingRecord.VotingItemId];
    
    // ... existing validation code ...
    
    var votingResult = State.VotingResults[votingResultHash];
    
    // Determine the amount to decrement based on voting type
    var decrementAmount = votingItem.IsQuadratic ? 1 : votingRecord.Amount;
    
    votingResult.Results[votingRecord.Option] =
        votingResult.Results[votingRecord.Option].Sub(decrementAmount);
    
    // ... rest of withdrawal logic ...
}
```

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public void QuadraticVoting_Withdrawal_CorruptsResults()
{
    // Setup: Register quadratic voting item with ticketCost = 100
    var votingItemId = RegisterQuadraticVotingItem(ticketCost: 100);
    
    // User votes twice on same option
    Vote(votingItemId, "OptionA"); // Locks 100 tokens, Results["OptionA"] = 1
    Vote(votingItemId, "OptionA"); // Locks 200 tokens, Results["OptionA"] = 2
    
    // Check results before withdrawal
    var resultBefore = GetVotingResult(votingItemId);
    Assert.Equal(2, resultBefore.Results["OptionA"]); // Correct: 2 votes
    
    // Withdraw second vote (200 tokens)
    Withdraw(secondVoteId);
    
    // Check results after withdrawal
    var resultAfter = GetVotingResult(votingItemId);
    
    // BUG: Results becomes negative!
    // Expected: 2 - 1 = 1
    // Actual: 2 - 200 = -198
    Assert.True(resultAfter.Results["OptionA"] < 0); // NEGATIVE! Vulnerability confirmed
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L98-103)
```csharp
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L105-115)
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
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L169-181)
```csharp
    private void UpdateVotingResult(VotingItem votingItem, string option, long amount)
    {
        // Update VotingResult based on this voting behaviour.
        var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
        var votingResult = State.VotingResults[votingResultHash];
        if (!votingResult.Results.ContainsKey(option)) votingResult.Results.Add(option, 0);

        var currentVotes = votingResult.Results[option];
        votingResult.Results[option] = currentVotes.Add(amount);
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
        votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
        State.VotingResults[votingResultHash] = votingResult;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-220)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);
```
