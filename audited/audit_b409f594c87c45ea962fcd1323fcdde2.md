# Audit Report

## Title
Sponsor Can Remove Voted Options During Active Voting, Causing DOS and Vote Manipulation

## Summary
The `RemoveOption()` function in the Vote contract lacks critical validation checks, allowing sponsors to remove options during active voting periods even when votes have been cast. This creates a denial-of-service condition for new voters and enables vote manipulation through selective option removal and re-addition, fundamentally breaking voting integrity.

## Finding Description

The `RemoveOption()` function only validates sponsor permission, option existence, and option length before removing an option from a voting item. [1](#0-0) 

The function performs no validation against the voting item's `StartTimestamp` or `EndTimestamp` fields, which are stored in the VotingItem structure. [2](#0-1) 

When voters call the `Vote()` function, it validates that the option exists in `votingItem.Options` list through `AssertValidVoteInput()`. [3](#0-2) 

However, votes are stored separately in the `VotingResult.Results[option]` mapping through `UpdateVotingResult()`. [4](#0-3) 

**Attack Path**:
1. Sponsor registers voting item with options A, B, C
2. Voting period becomes active (CurrentBlockTime >= StartTimestamp)
3. Multiple voters cast votes for option A via `Vote()` → stored in `VotingResult.Results["A"]`
4. Sponsor calls `RemoveOption()` to remove option A from `VotingItem.Options`
5. New voters attempting to vote for A fail at line 381 assertion: `Assert(votingItem.Options.Contains(input.Option))`
6. Existing votes for A remain in `VotingResult.Results["A"]` but option is unavailable
7. Sponsor can later re-add option A via `AddOption()`, creating inconsistent voting states

This creates a fundamental inconsistency where votes exist for options that are not available, and new voters are denied the ability to vote on options that already have votes.

## Impact Explanation

**Voting Integrity Violation**: The core invariant of fair voting - that all eligible voters have equal opportunity to vote on the same set of options - is broken. The system creates two classes of voters: those who voted before option removal and those who cannot vote after removal.

**Denial of Service**: New voters are completely blocked from voting on removed options despite existing votes, creating an availability issue for a critical governance function.

**Vote Manipulation**: Sponsors can strategically remove losing options during voting, wait for sentiment to change, then re-add them. This enables timing-based manipulation of voting outcomes.

**Governance Impact**: The Vote contract is used by the Election contract for candidate selection and other governance processes. This vulnerability undermines the integrity of AElf's governance mechanisms, potentially affecting fund allocations and protocol decisions.

**Data Inconsistency**: Voting results contain orphaned votes for non-existent options, breaking result integrity and making accurate tallying impossible.

The severity is **Medium-High** because while no funds are directly stolen, the governance manipulation capability can indirectly affect fund distributions and protocol security decisions.

## Likelihood Explanation

**Attacker Profile**: Any user can be a voting sponsor by calling `Register()`. The attacker doesn't need special privileges beyond creating their own voting item.

**Execution Complexity**: **Low** - Single transaction calling `RemoveOption()` with voting item ID and option name. No complex state setup, timing windows, or race conditions required.

**Prerequisites**: 
- Voting item must exist (trivial - attacker creates it)
- Attacker must be sponsor (trivial - attacker sponsors their own voting)
- Option must exist (trivial - attacker knows their voting options)

**Detection**: Difficult - No events are emitted when options are removed, creating no on-chain audit trail. Off-chain systems would need to continuously poll voting item state to detect modifications.

**Reproducibility**: **High** - Can be executed repeatedly during any voting period with no rate limits or cooldowns.

The likelihood is **High** due to low technical barriers and easy executability by any sponsor.

## Recommendation

Add temporal and state validation to `RemoveOption()` and `AddOption()` functions:

```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // NEW: Prevent modification during active voting period
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp || 
           Context.CurrentBlockTime > votingItem.EndTimestamp, 
           "Cannot modify options during active voting period.");
    
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    
    // NEW: Verify no votes exist for this option
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    Assert(!votingResult.Results.ContainsKey(input.Option) || 
           votingResult.Results[input.Option] == 0, 
           "Cannot remove option with existing votes.");
    
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Apply similar checks to `AddOption()` to prevent option addition during active voting.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveOption_During_Active_Voting_With_Existing_Votes_Test()
{
    // Register voting item with options A, B, C
    var registerItem = await RegisterVotingItemAsync(
        totalSnapshot: 1,
        options: new[] { "A", "B", "C" },
        startTimestamp: Timestamp.FromDateTime(DateTime.UtcNow),
        endTimestamp: Timestamp.FromDateTime(DateTime.UtcNow.AddDays(7))
    );
    
    // Vote for option A
    var voteResult = await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = registerItem.VotingItemId,
        Amount = 100,
        Option = "A"
    });
    voteResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Sponsor removes option A during active voting
    var removeResult = await VoteContractStub.RemoveOption.SendAsync(new RemoveOptionInput
    {
        VotingItemId = registerItem.VotingItemId,
        Option = "A"
    });
    removeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // New voter attempts to vote for A - FAILS with "Option A not found"
    var secondVoter = GetVoteContractTester(Accounts[2].KeyPair);
    var failedVote = await secondVoter.Vote.SendWithExceptionAsync(new VoteInput
    {
        VotingItemId = registerItem.VotingItemId,
        Amount = 100,
        Option = "A"
    });
    failedVote.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    failedVote.TransactionResult.Error.ShouldContain("Option A not found");
    
    // Verify: Option A is removed from voting item but votes still exist in results
    var votingItem = await VoteContractStub.GetVotingItem.CallAsync(registerItem.VotingItemId);
    votingItem.Options.Contains("A").ShouldBeFalse(); // Option removed
    
    var votingResult = await VoteContractStub.GetLatestVotingResult.CallAsync(registerItem.VotingItemId);
    votingResult.Results["A"].ShouldBe(100); // But votes remain orphaned
}
```

## Notes

This vulnerability demonstrates a critical design flaw where option management is decoupled from vote state validation. The VotingItem options list and VotingResult vote mappings are not kept in sync when options are modified, creating inconsistent state that breaks voting integrity. The lack of temporal validation (checking timestamps) and state validation (checking existing votes) in option modification functions enables this exploit.

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

**File:** protobuf/vote_contract.proto (L106-133)
```text
message VotingItem {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The token symbol which will be accepted.
    string accepted_currency = 2;
    // Whether the vote will lock token.
    bool is_lock_token = 3;
    // The current snapshot number.
    int64 current_snapshot_number = 4;
    // The total snapshot number.
    int64 total_snapshot_number = 5;
    // The list of options.
    repeated string options = 6;
    // The register time of the voting activity.
    google.protobuf.Timestamp register_timestamp = 7;
    // The start time of the voting.
    google.protobuf.Timestamp start_timestamp = 8;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 9;
    // The start time of current round of the voting.
    google.protobuf.Timestamp current_snapshot_start_timestamp = 10;
    // The sponsor address of the voting activity.
    aelf.Address sponsor = 11;
    // Is quadratic voting.
    bool is_quadratic = 12;
    // Quadratic voting item ticket cost.
    int64 ticket_cost = 13;
}
```
