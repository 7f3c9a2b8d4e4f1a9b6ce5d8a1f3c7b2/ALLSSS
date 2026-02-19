### Title
Vote Count Inflation via Duplicate VoteId in Delegated Voting

### Summary
In delegated voting scenarios (IsLockToken = false), the Vote contract allows sponsors to submit multiple votes with the same VoteId. This results in vote count inflation, duplicate entries in the ActiveVotes list, and phantom votes that become unwithdrawable. Each duplicate vote inflates the total vote count without corresponding token backing, violating vote integrity.

### Finding Description

The vulnerability exists in the `Vote()` function's interaction with `UpdateVotedItems()` and `UpdateVotingResult()`. [1](#0-0) 

When processing a vote, the contract:
1. Stores the voting record without checking for existence
2. Updates voting results (incrementing vote counts)
3. Adds voteId to ActiveVotes list without duplicate checking [2](#0-1) 

At line 151, `ActiveVotes.Add(voteId)` is called without verifying if the voteId already exists in the list. Additionally, line 117 overwrites any existing VotingRecord with the same VoteId without validation.

For delegated voting (IsLockToken = false), the sponsor provides the VoteId: [3](#0-2) 

At lines 386-388, the contract only requires that the sponsor is the sender and that VoteId is non-null, but never checks if the VoteId has already been used in `State.VotingRecords`.

### Impact Explanation

**Direct Impact:**
- **Vote Count Inflation**: Each duplicate vote increments vote totals in `UpdateVotingResult()` without actual token backing
- **Permanent State Corruption**: When a VoteId is reused, the first vote's data is overwritten, making it permanently unwithdrawable while its vote count remains inflated
- **votersCount Manipulation**: The votersCount metric is artificially inflated, misrepresenting actual voter participation

**Attack Sequence:**
1. Sponsor creates delegated voting item (IsLockToken = false)
2. Sponsor calls Vote(voteId="X", voter=Alice, amount=100, option="A")
   - Results: VotingResult has 100 votes for "A", votersCount=1
3. Sponsor calls Vote(voteId="X", voter=Alice, amount=200, option="B")
   - VotingRecord["X"] is overwritten with new data
   - VotingResult now has 100 for "A" + 200 for "B", votersCount=2
   - Alice's ActiveVotes = ["X", "X"] (duplicate)
4. Upon withdrawal of "X", only the last vote (200 for "B") is subtracted
   - Final state: 100 phantom votes for "A" remain, votersCount still inflated
   - One "X" remains in ActiveVotes but references a withdrawn record

This violates the critical invariant that vote counts must accurately represent actual voting activity and token commitments.

### Likelihood Explanation

**High Likelihood** - The exploit is straightforward and requires only sponsor privileges in delegated voting:

**Attacker Capabilities:**
- Must be the sponsor of a delegated voting item (IsLockToken = false)
- Can provide arbitrary VoteIds in Vote() calls
- No economic cost beyond transaction fees

**Execution Practicality:**
- The Vote() function is publicly callable by the sponsor
- No rate limiting or duplicate detection exists
- Attack succeeds with simple repeated calls using the same VoteId

**Feasibility Conditions:**
- Delegated voting is a documented feature used by the Election contract
- Sponsors have legitimate reasons to create voting items
- The vulnerability requires no special timing or race conditions

**Detection Constraints:**
- The vulnerability creates valid-looking transactions
- No alerts or checks exist to detect duplicate VoteIds
- State corruption persists indefinitely

### Recommendation

**1. Add VoteId Uniqueness Check in Vote() Function:**

Before line 117, add:
```csharp
Assert(State.VotingRecords[input.VoteId] == null, "Vote ID already exists.");
```

**2. Add Duplicate Check in UpdateVotedItems():**

Before line 151, add:
```csharp
Assert(!votedItems.VotedItemVoteIds[voterItemIndex].ActiveVotes.Contains(voteId), 
       "Vote ID already in active votes.");
```

**3. Add Regression Test:**

Create test cases that:
- Attempt to vote twice with the same VoteId in delegated voting
- Verify that the second vote is rejected
- Verify that vote counts remain accurate after attempted duplicate votes

**4. Add State Validation:**

Implement a view function to detect inconsistencies between VotingRecords and ActiveVotes to identify any existing corrupted state.

### Proof of Concept

**Initial State:**
- Sponsor creates delegated voting item: VotingItemId="Item1", IsLockToken=false, Options=["A", "B"]
- VotingResult: results={}, votersCount=0, votesAmount=0

**Step 1: First Vote**
```
Sponsor calls Vote(
  votingItemId="Item1",
  voteId="DUPLICATE_ID",
  voter=Alice,
  amount=100,
  option="A"
)
```
**Result:** VotingRecord["DUPLICATE_ID"] = {voter: Alice, amount: 100, option: "A"}
VotingResult: results["A"]=100, votersCount=1, votesAmount=100
Alice's ActiveVotes = ["DUPLICATE_ID"]

**Step 2: Second Vote with Same VoteId**
```
Sponsor calls Vote(
  votingItemId="Item1",
  voteId="DUPLICATE_ID",  // SAME ID
  voter=Alice,
  amount=200,
  option="B"
)
```
**Result:** VotingRecord["DUPLICATE_ID"] = {voter: Alice, amount: 200, option: "B"} (overwritten)
VotingResult: results["A"]=100, results["B"]=200, votersCount=2, votesAmount=300 (INFLATED)
Alice's ActiveVotes = ["DUPLICATE_ID", "DUPLICATE_ID"] (DUPLICATE)

**Step 3: Withdraw**
```
Sponsor calls Withdraw(voteId="DUPLICATE_ID")
```
**Result:** VotingResult: results["A"]=100 (PHANTOM), results["B"]=0, votersCount=2 (INFLATED), votesAmount=100 (INFLATED)
Alice's ActiveVotes = ["DUPLICATE_ID"] (one removed, one remains as dangling reference)

**Success Condition:** 
- Expected: All vote counts should be 0 after withdrawal
- Actual: 100 phantom votes for option "A" remain, votersCount and votesAmount are permanently inflated

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-144)
```csharp
    public override Empty Vote(VoteInput input)
    {
        var votingItem = AssertValidVoteInput(input);
        var amount = 0L;
        if (!votingItem.IsQuadratic)
        {
            amount = input.Amount;
        }
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }

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

        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
        UpdateVotedItems(input.VoteId, votingRecord.Voter, votingItem);

        if (votingItem.IsLockToken)
            // Lock voted token.
            State.TokenContract.Lock.Send(new LockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                LockId = input.VoteId,
                Amount = amount
            });

        Context.Fire(new Voted
        {
            VoteId = input.VoteId,
            VotingItemId = votingRecord.VotingItemId,
            Voter = votingRecord.Voter,
            Amount = votingRecord.Amount,
            Option = votingRecord.Option,
            SnapshotNumber = votingRecord.SnapshotNumber,
            VoteTimestamp = votingRecord.VoteTimestamp
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L146-161)
```csharp
    private void UpdateVotedItems(Hash voteId, Address voter, VotingItem votingItem)
    {
        var votedItems = State.VotedItemsMap[voter] ?? new VotedItems();
        var voterItemIndex = votingItem.VotingItemId.ToHex();
        if (votedItems.VotedItemVoteIds.ContainsKey(voterItemIndex))
            votedItems.VotedItemVoteIds[voterItemIndex].ActiveVotes.Add(voteId);
        else
            votedItems.VotedItemVoteIds[voterItemIndex] =
                new VotedIds
                {
                    ActiveVotes = { voteId }
                };

        votedItems.VotedItemVoteIds[voterItemIndex].WithdrawnVotes.Remove(voteId);
        State.VotedItemsMap[voter] = votedItems;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-401)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
        else
        {
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }

        return votingItem;
    }
```
