### Title
Vote Orphaning Vulnerability in RemoveOption Allows Result Manipulation

### Summary
The `RemoveOption` function removes options from the voting item's option list but fails to clean up existing votes for that option in the voting results state. This creates an exploitable inconsistency where removed options retain all their accumulated votes in results while preventing new voters from voting for them, enabling sponsors to manipulate voting outcomes.

### Finding Description

The vulnerability exists in the `RemoveOption` function which only removes the option from `VotingItem.Options` without cleaning up associated voting data: [1](#0-0) 

When users vote, the system validates that the option exists in `VotingItem.Options`: [2](#0-1) 

Votes are then recorded in `VotingResult.Results` via `UpdateVotingResult`: [3](#0-2) 

The `VotingResult` structure stores votes as a map from option strings to vote counts: [4](#0-3) 

When results are queried, the system returns the entire `VotingResults` state directly, including votes for removed options: [5](#0-4) 

The `Withdraw` function still allows users to withdraw votes for removed options because it uses the option stored in the `VotingRecord`, not the current `VotingItem.Options` list: [6](#0-5) 

**Why protections fail:** There is no validation in `RemoveOption` to check if votes exist for the option being removed, and no cleanup mechanism to handle orphaned votes. The existing test only verifies option removal from the Options list, not vote cleanup: [7](#0-6) 

### Impact Explanation

This vulnerability enables **governance manipulation** through unfair voting:

1. **Result Manipulation**: A sponsor can remove competing options after they accumulate votes, preserving those votes in results while preventing new votes, artificially inflating the removed option's standing.

2. **Unfair Advantage**: Removed options retain their vote count in `VotingResult.Results` and contribute to `votes_amount` totals, but new users cannot vote for them (validation at line 381 fails). This creates asymmetric voting power.

3. **State Inconsistency**: `VotingItem.Options` becomes out of sync with keys in `VotingResult.Results`, violating the invariant that only listed options should have votes.

4. **Election Impact**: In the Election contract which uses the Vote contract, this allows manipulation of candidate elections by removing candidates while preserving their votes.

**Severity: HIGH** - Directly compromises voting integrity and enables governance manipulation without requiring any attack cost beyond sponsor privileges.

### Likelihood Explanation

**Likelihood: HIGH** - The exploit is straightforward and practical:

- **Reachable Entry Point**: `RemoveOption` is a public method callable by the voting sponsor, a legitimate role.

- **Feasible Preconditions**: Only requires sponsor role (obtained during voting registration) and an active voting period. No special state setup needed.

- **Execution Practicality**: Single transaction to call `RemoveOption` after observing vote distributions. No complex state manipulation required.

- **Economic Rationality**: Extremely low cost (one transaction fee) with high impact (control voting outcomes). No economic barriers.

- **Detection Difficulty**: Off-chain monitoring would see option removal but may not realize votes remain counted. On-chain queries show the orphaned votes, but users may not notice the inconsistency.

The sponsor legitimately owns this capability, making it a design flaw rather than an access control issue. The vulnerability occurs in normal contract operation whenever a sponsor removes an option after votes are cast.

### Recommendation

**Immediate Fix**: Modify `RemoveOption` and `RemoveOptions` to either:

1. **Option A - Prevent Removal**: Reject removal if votes exist for the option:
```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    
    // NEW: Check if votes exist for this option
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    Assert(!votingResult.Results.ContainsKey(input.Option) || votingResult.Results[input.Option] == 0, 
           "Cannot remove option with existing votes.");
    
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

2. **Option B - Clean Up Votes**: Remove votes when removing the option:
```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    
    votingItem.Options.Remove(input.Option);
    
    // NEW: Clean up votes for removed option
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    if (votingResult.Results.ContainsKey(input.Option))
    {
        var removedVotes = votingResult.Results[input.Option];
        votingResult.VotesAmount = votingResult.VotesAmount.Sub(removedVotes);
        votingResult.Results.Remove(input.Option);
        State.VotingResults[votingResultHash] = votingResult;
    }
    
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

**Recommended Approach**: Option A is safer as it prevents potential issues with vote withdrawal for removed options and maintains voting integrity. Option B requires additional logic to handle voter counts and withdrawal scenarios.

**Test Cases to Add**:
1. Test that attempts to remove an option with existing votes (should fail with Option A or succeed with cleanup in Option B)
2. Test that GetVotingResult does not include votes for removed options after proper cleanup
3. Test that VotingResult.votes_amount accurately reflects removal

### Proof of Concept

**Initial State**:
- Sponsor registers voting item with options ["A", "B", "C"]
- Token locks enabled, 10-day duration, snapshot number 1

**Exploitation Steps**:

1. **Users Vote** (Block N):
   - User1 votes 100 tokens for option "A"
   - User2 votes 200 tokens for option "B" 
   - User3 votes 150 tokens for option "C"
   - `GetVotingResult`: Results = {A: 100, B: 200, C: 150}, VotesAmount = 450

2. **Sponsor Removes Leading Option** (Block N+100):
   - Sponsor calls `RemoveOption` with option "B"
   - Transaction succeeds
   - `GetVotingItem`: Options = ["A", "C"] (B removed)

3. **Check Results** (Block N+101):
   - `GetVotingResult`: Results = {A: 100, B: 200, C: 150}, VotesAmount = 450
   - **Expected**: Results = {A: 100, C: 150}, VotesAmount = 250
   - **Actual**: B's 200 votes remain counted despite removal

4. **New User Attempts Vote** (Block N+102):
   - User4 tries to vote for option "B" with 300 tokens
   - Transaction fails: "Option B not found" (line 381 validation)
   - Users cannot vote for removed option

5. **Original Voter Can Withdraw** (Block N+103):
   - User2 calls `Withdraw` with their vote ID
   - Transaction succeeds (line 215 uses stored option from VotingRecord)
   - Results updated: {A: 100, B: 0, C: 150}, VotesAmount = 250

**Success Condition**: Steps 3-4 demonstrate the vulnerability - removed option "B" retains its votes in results while preventing new votes, creating an unfair and manipulable voting state.

### Citations

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L303-312)
```csharp
    public override Empty RemoveOption(RemoveOptionInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
        votingItem.Options.Remove(input.Option);
        State.VotingItems[votingItem.VotingItemId] = votingItem;
        return new Empty();
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

**File:** protobuf/vote_contract.proto (L162-177)
```text
message VotingResult {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The voting result, option -> amount of votes,
    map<string, int64> results = 2;
    // The snapshot number.
    int64 snapshot_number = 3;
    // The total number of voters.
    int64 voters_count = 4;
    // The start time of this snapshot.
    google.protobuf.Timestamp snapshot_start_timestamp = 5;
    // The end time of this snapshot.
    google.protobuf.Timestamp snapshot_end_timestamp = 6;
    // Total votes received during the process of this snapshot.
    int64 votes_amount = 7;
}
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

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L435-450)
```csharp
    public async Task VoteContract_RemoveOption_Success_Test()
    {
        var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);
        var removeOption = registerItem.Options[0];
        var transactionResult = (await VoteContractStub.RemoveOption.SendAsync(new RemoveOptionInput
        {
            Option = removeOption,
            VotingItemId = registerItem.VotingItemId
        })).TransactionResult;

        transactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        var votingItem = await GetVoteItem(registerItem.VotingItemId);
        votingItem.Options.Count.ShouldBe(2);
        votingItem.Options.Contains(removeOption).ShouldBeFalse();
    }
```
