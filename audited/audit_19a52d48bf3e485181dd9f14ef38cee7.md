### Title
QuadraticVotesCountMap Never Decremented Causing Inflated Costs on VoteId Reuse

### Summary
The `QuadraticVotesCountMap` state variable is incremented on each vote but never decremented or cleared during withdrawal, causing permanently inflated voting costs if a VoteId is reused. Combined with the lack of validation preventing VoteId reuse in the `Vote` method, this leads to users being required to lock more tokens than intended for subsequent votes with the same VoteId.

### Finding Description

The vulnerability exists in the quadratic voting implementation within the Vote contract: [1](#0-0) 

When a vote is cast with quadratic voting enabled, the `QuadraticVotesCountMap[input.VoteId]` is incremented and the cost is calculated as `TicketCost * currentVotesCount`. However, the Withdraw method never decrements or clears this counter: [2](#0-1) 

The Withdraw method only marks the record as withdrawn and updates voting results, but leaves `QuadraticVotesCountMap` unchanged. Additionally, the Vote method lacks validation to prevent VoteId reuse: [3](#0-2) 

The VotingRecord is simply overwritten without checking if the VoteId already exists or if a previous record exists and was withdrawn. This contrasts with the Election contract which explicitly validates VoteId uniqueness: [4](#0-3) 

### Impact Explanation

When a VoteId is reused in quadratic voting (particularly in delegated voting where sponsors provide VoteIds), the cost escalates incorrectly:

1. First vote with VoteId "X": `QuadraticVotesCountMap["X"] = 1`, amount = `TicketCost * 1`
2. Withdrawal: `QuadraticVotesCountMap["X"]` remains 1 (not cleared)
3. Second vote with VoteId "X": `QuadraticVotesCountMap["X"] = 2`, amount = `TicketCost * 2`

For `IsLockToken = true` voting, this inflated amount is locked via the Token contract: [5](#0-4) 

The voter must lock double the intended tokens (or more for additional reuses), reducing their liquidity and effectively charging them incorrectly for the voting action. For a TicketCost of 100, the voter would lock 200 tokens instead of 100 on the second use of the same VoteId.

### Likelihood Explanation

The likelihood varies by usage scenario:

**Regular Voting (IsLockToken=true):** Low likelihood - VoteId is auto-generated using `Context.GenerateId()` with `votingResult.VotesAmount` as seed: [6](#0-5) 

Since VotesAmount increases with each vote, collisions are extremely rare under normal sequential execution.

**Delegated Voting (IsLockToken=false):** Medium likelihood - The sponsor provides VoteIds explicitly: [7](#0-6) 

A sponsor could accidentally or intentionally reuse a VoteId after withdrawal. However, the primary delegated voting user (Election contract) implements its own VoteId uniqueness check, mitigating this issue in that context.

The vulnerability primarily affects custom implementations using delegated quadratic voting without proper VoteId validation.

### Recommendation

**Option 1 (Preferred):** Add explicit VoteId uniqueness validation in the Vote method:

```csharp
// In Vote method after line 92
var existingRecord = State.VotingRecords[input.VoteId];
Assert(existingRecord == null, "Vote ID already exists.");
```

This prevents any VoteId reuse, making the permanent nature of QuadraticVotesCountMap acceptable.

**Option 2:** Clear QuadraticVotesCountMap on withdrawal and allow VoteId reuse:

```csharp
// In Withdraw method after line 222
if (votingItem.IsQuadratic)
{
    State.QuadraticVotesCountMap[input.VoteId] = 0;
}
```

And modify the reuse check to allow reuse of withdrawn VoteIds:

```csharp
// In Vote method
var existingRecord = State.VotingRecords[input.VoteId];
Assert(existingRecord == null || existingRecord.IsWithdrawn, 
    "Vote ID already in use.");
```

**Test Cases:** Add tests covering:
- Attempting to reuse a VoteId before withdrawal (should fail)
- Attempting to reuse a VoteId after withdrawal in quadratic voting
- Verifying QuadraticVotesCountMap behavior across vote-withdraw-vote cycles

### Proof of Concept

**Initial State:**
- Register a voting item with `IsQuadratic = true`, `IsLockToken = false`, `TicketCost = 100`
- Sponsor has authorization to vote on behalf of voters

**Transaction Sequence:**

1. **First Vote:**
   - Sponsor calls `Vote(VotingItemId, Voter=AddressA, VoteId="0x123...", Option="A", Amount=ignored)`
   - `QuadraticVotesCountMap["0x123..."]` increments to 1
   - `amount = 100 * 1 = 100`
   - VotingRecord created with amount=100

2. **Withdraw:**
   - Sponsor calls `Withdraw(VoteId="0x123...")`
   - VotingRecord marked as `IsWithdrawn = true`
   - `QuadraticVotesCountMap["0x123..."]` remains 1 (NOT cleared)

3. **Second Vote (Reuse):**
   - Sponsor calls `Vote(VotingItemId, Voter=AddressA, VoteId="0x123...", Option="B", Amount=ignored)`
   - `QuadraticVotesCountMap["0x123..."]` increments to 2
   - `amount = 100 * 2 = 200`
   - VotingRecord overwritten with amount=200

**Expected Result:** Second vote should cost 100 (same as first, since previous was withdrawn)

**Actual Result:** Second vote costs 200 (doubled due to non-cleared counter)

**Success Condition:** If `IsLockToken = true`, the voter would need to lock 200 tokens instead of 100, demonstrating the inflated cost vulnerability.

### Notes

While the Election contract (the primary real-world user of delegated voting) implements its own protection against VoteId reuse, the Vote contract should not rely on callers to implement critical validations. The lack of built-in protection makes the contract unsafe for custom delegated voting implementations and represents a violation of defensive programming principles. The vulnerability is real but has limited current exploitability due to the Election contract's mitigations.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L117-117)
```csharp
        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L122-130)
```csharp
        if (votingItem.IsLockToken)
            // Lock voted token.
            State.TokenContract.Lock.Send(new LockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                LockId = input.VoteId,
                Amount = amount
            });
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-388)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L397-397)
```csharp
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L433-433)
```csharp
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
```
