### Title
Quadratic Voting Mechanism Fundamentally Broken Due to Per-VoteId Count Tracking

### Summary
The quadratic voting implementation fails to impose increasing costs for multiple votes because `QuadraticVotesCountMap` is keyed by unique `VoteId` instead of by voter or (voter, voting item) pair. Each vote transaction generates a new `VoteId`, causing the count to always start at zero, effectively charging only the base `TicketCost` for every vote regardless of how many times a user has voted. This completely defeats the purpose of quadratic voting as a mechanism to prevent vote concentration and manipulation.

### Finding Description

The quadratic voting feature is implemented in the `Vote` method where it increments `QuadraticVotesCountMap[input.VoteId]` and calculates the cost as `ticketCost * count`. [1](#0-0) 

The critical flaw is that `QuadraticVotesCountMap` uses `VoteId` as the key: [2](#0-1) 

Each vote transaction generates a **unique** `VoteId` in `AssertValidVoteInput`: [3](#0-2) 

Since `Context.GenerateId()` produces a unique hash based on `votingResult.VotesAmount` (which changes with each vote), every vote gets a fresh `VoteId`. When accessing `State.QuadraticVotesCountMap[newUniqueVoteId]`, the default value is 0, so `currentVotesCount` becomes 1 for every single vote, making each vote cost exactly `1 * ticketCost`.

The `Withdraw` method does not decrement `QuadraticVotesCountMap`, but this is **irrelevant** because the user's next vote will use a completely different `VoteId` anyway, starting the count at 0 again: [4](#0-3) 

### Impact Explanation

**Governance Manipulation Impact**: The quadratic voting mechanism is designed to prevent wealthy voters from dominating decisions by making it exponentially more expensive to accumulate votes (1st vote costs 1x, 2nd costs 2x, 3rd costs 3x, etc., totaling 1+2+3+... = N(N+1)/2 for N votes). With this implementation, a user can cast N votes for only N * ticketCost instead of the intended N(N+1)/2 * ticketCost.

For example, to cast 10 votes:
- **Intended cost**: 1+2+3+...+10 = 55 * ticketCost
- **Actual cost**: 10 * ticketCost
- **Exploit savings**: 45 * ticketCost (82% discount)

This allows wealthy voters to buy voting power at **linear cost** instead of quadratic cost, completely undermining the fairness mechanism. Any voting item using `IsQuadratic = true` is vulnerable to plutocratic manipulation, as users can cheaply accumulate dominant voting power.

The withdrawal issue is a secondary concern - the primary vulnerability is that multiple votes never incur quadratic costs at all.

### Likelihood Explanation

**Certainty: 100%** - This is not a conditional exploit but a fundamental implementation flaw that affects every quadratic voting item.

**Attacker Requirements**:
- Any user with sufficient token balance
- Access to the public `Vote` method
- A voting item registered with `IsQuadratic = true`

**Execution**:
1. Call `Vote` multiple times on the same voting item
2. Each call generates a unique `VoteId`
3. Each vote costs only `1 * ticketCost` instead of increasing quadratically
4. User accumulates N votes for N * ticketCost instead of N(N+1)/2 * ticketCost

**Detection**: The flaw is structural and present in every vote transaction. There are no test cases validating quadratic cost progression across multiple votes from the same user.

### Recommendation

**Immediate Fix**: Change `QuadraticVotesCountMap` to track vote counts per **(Voter, VotingItemId)** pair instead of per `VoteId`:

1. Modify the state structure:
```csharp
// In VoteContractState.cs
public MappedState<Address, Hash, long> QuadraticVotesCountMap { get; set; } // Address -> VotingItemId -> Count
```

2. Update the `Vote` method to use the voter-item pair as key and increment properly

3. **Decrement the count in `Withdraw`** when a vote is withdrawn:
```csharp
if (votingItem.IsQuadratic)
{
    var currentCount = State.QuadraticVotesCountMap[votingRecord.Voter][votingRecord.VotingItemId];
    State.QuadraticVotesCountMap[votingRecord.Voter][votingRecord.VotingItemId] = currentCount.Sub(1);
}
```

This ensures that when a user withdraws their vote and votes again, they pay the correct cost based on their **current active vote count**, not their historical cumulative votes.

4. Add comprehensive test cases validating:
   - First vote costs 1x ticketCost
   - Second vote from same user costs 2x ticketCost (cumulative 3x)
   - After withdrawing one vote and revoting, cost reflects updated active count
   - Multiple votes from different users are tracked independently

### Proof of Concept

**Initial State**:
- Voting item registered with `IsQuadratic = true`, `TicketCost = 100 ELF`
- User has 10,000 ELF balance

**Exploitation Steps**:
1. User calls `Vote(votingItemId, option, amount=ignored)` 
   - VoteId1 generated, count = 1, **charged 100 ELF**
2. User calls `Vote(votingItemId, option, amount=ignored)` again
   - VoteId2 generated (different from VoteId1), count = 1 again, **charged 100 ELF** (should be 200)
3. User calls `Vote` 8 more times
   - Each charges **100 ELF** (should be 300, 400, 500, 600, 700, 800, 900, 1000)

**Expected Result** (proper quadratic): Total cost = 1+2+3+...+10 = **5,500 ELF**

**Actual Result** (broken implementation): Total cost = 10 * 100 = **1,000 ELF**

**Success Condition**: User obtains 10 votes for 1,000 ELF instead of the intended 5,500 ELF, achieving an 82% discount and undermining the quadratic voting fairness mechanism.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L191-239)
```csharp
    public override Empty Withdraw(WithdrawInput input)
    {
        var votingRecord = State.VotingRecords[input.VoteId];
        if (votingRecord == null) throw new AssertionException("Voting record not found.");
        var votingItem = State.VotingItems[votingRecord.VotingItemId];

        if (votingItem.IsLockToken)
            Assert(votingRecord.Voter == Context.Sender, "No permission to withdraw votes of others.");
        else
            Assert(votingItem.Sponsor == Context.Sender, "No permission to withdraw votes of others.");

        // Update VotingRecord.
        votingRecord.IsWithdrawn = true;
        votingRecord.WithdrawTimestamp = Context.CurrentBlockTime;
        State.VotingRecords[input.VoteId] = votingRecord;

        var votingResultHash = GetVotingResultHash(votingRecord.VotingItemId, votingRecord.SnapshotNumber);

        var votedItems = State.VotedItemsMap[votingRecord.Voter];
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].ActiveVotes.Remove(input.VoteId);
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].WithdrawnVotes.Add(input.VoteId);
        State.VotedItemsMap[votingRecord.Voter] = votedItems;

        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;

        if (votingItem.IsLockToken)
            State.TokenContract.Unlock.Send(new UnlockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                Amount = votingRecord.Amount,
                LockId = input.VoteId
            });

        Context.Fire(new Withdrawn
        {
            VoteId = input.VoteId
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L394-398)
```csharp
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }
```

**File:** contract/AElf.Contracts.Vote/VoteContractState.cs (L30-33)
```csharp
    /// <summary>
    ///     Vote Id -> Votes Count
    /// </summary>
    public MappedState<Hash, long> QuadraticVotesCountMap { get; set; }
```
