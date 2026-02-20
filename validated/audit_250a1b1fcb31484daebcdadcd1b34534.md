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

Fix the accounting mismatch by ensuring consistent tracking across voting and withdrawal operations. The issue is in line 119 where the contract conditionally passes different values to `UpdateVotingResult`.

**Option 1 (Recommended):** Always pass the token amount to `UpdateVotingResult`, regardless of voting type:

Change line 119 from:
```csharp
UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
```

To:
```csharp
UpdateVotingResult(votingItem, input.Option, amount);
```

**Option 2:** If the intent is to track vote counts separately from token amounts, create separate tracking for quadratic votes and update the withdrawal logic accordingly to decrement the correct value.

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_Withdrawal_Corrupts_Results()
{
    // Register a quadratic voting item
    var startTime = TimestampHelper.GetUtcNow();
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(10),
        StartTimestamp = startTime,
        Options = { "OptionA" },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true,
        IsQuadratic = true,
        TicketCost = 100
    };
    
    await VoteContractStub.Register.SendAsync(input);
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(new VotingRegisterInput
        {
            TotalSnapshotNumber = 1,
            EndTimestamp = startTime.AddDays(10),
            StartTimestamp = startTime,
            AcceptedCurrency = TestTokenSymbol,
            IsLockToken = true,
            IsQuadratic = true,
            TicketCost = 100
        }),
        HashHelper.ComputeFrom(DefaultSender)
    );
    
    // Vote twice
    var voter = Accounts[1].KeyPair;
    var voterStub = GetVoteContractTester(voter);
    
    await voterStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "OptionA",
        Amount = 0 // Amount ignored for quadratic
    });
    
    var voteId2 = await voterStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "OptionA",
        Amount = 0
    });
    
    // Check results after voting
    var resultAfterVoting = await VoteContractStub.GetVotingResult.CallAsync(
        new GetVotingResultInput
        {
            VotingItemId = votingItemId,
            SnapshotNumber = 1
        }
    );
    
    resultAfterVoting.Results["OptionA"].ShouldBe(2); // Two votes = 2
    resultAfterVoting.VotesAmount.ShouldBe(2);
    
    // Withdraw second vote
    var voteId = voteId2.Output;
    await voterStub.Withdraw.SendAsync(new WithdrawInput { VoteId = voteId });
    
    // Check results after withdrawal - SHOULD BE 1 BUT WILL BE NEGATIVE
    var resultAfterWithdrawal = await VoteContractStub.GetVotingResult.CallAsync(
        new GetVotingResultInput
        {
            VotingItemId = votingItemId,
            SnapshotNumber = 1
        }
    );
    
    // BUG: Results become negative!
    // Expected: 1 (one vote remaining)
    // Actual: 2 - 200 = -198 (because withdrawal subtracts token amount, not vote count)
    resultAfterWithdrawal.Results["OptionA"].ShouldBeLessThan(0); // Proves corruption
    resultAfterWithdrawal.VotesAmount.ShouldBeLessThan(0); // Also corrupted
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L100-102)
```csharp
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
```

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L177-179)
```csharp
        votingResult.Results[option] = currentVotes.Add(amount);
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
        votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L215-220)
```csharp
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);
```
