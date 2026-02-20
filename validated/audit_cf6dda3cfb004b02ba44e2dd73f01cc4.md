# Audit Report

## Title
Vote Contract Allows Unrestricted Post-Registration Option Manipulation Enabling Vote Outcome Manipulation

## Summary
The Vote contract's `AddOption` and `RemoveOption` methods lack timestamp or voting status validation, allowing sponsors to manipulate vote outcomes by removing leading options or adding new options during active voting periods, compromising voting integrity for time-bound governance votes.

## Finding Description

The Vote contract generates voting item IDs by hashing registration inputs WITHOUT including options, enabling stable IDs despite option changes. [1](#0-0) 

The `AddOption` method only validates sponsor authorization, option length/uniqueness, and maximum count - with no checks against the voting period's start/end timestamps or current voting status. [2](#0-1) 

Similarly, `RemoveOption` only verifies sponsor authorization and option existence, without any temporal validation. [3](#0-2) 

The `Vote` method enforces that voters can only vote for currently-existing options, meaning removed options cannot receive new votes while their existing vote counts remain frozen in the `VotingResult.Results` map. [4](#0-3) 

Registration validation only checks that `EndTimestamp > StartTimestamp`, establishing no expectation of option immutability. [5](#0-4) 

Test cases confirm this behavior is operational, demonstrating options being added during active voting in phase 2 after votes were cast in phase 1, with no time restrictions. [6](#0-5) 

The VotingItem structure includes `start_timestamp` and `end_timestamp` fields, indicating intent for time-bounded voting periods where option stability would be expected. [7](#0-6) 

## Impact Explanation

**For Generic Voting Items (High Severity):**
- **Vote Outcome Manipulation**: Sponsors can remove options with high vote counts, freezing those votes while competing options continue accumulating votes unrestricted
- **Democratic Fairness Violation**: Late-added options weren't available to early voters, creating unfair advantage  
- **Governance Integrity Breach**: For time-bound governance/funding votes, this violates the fundamental principle that ballot options should be fixed once voting begins

**Concrete Attack Scenario:**
1. DAO creates treasury allocation vote with options ["Project A", "Project B", "Project C"], 10-day voting period
2. Days 1-6: Community participates, Project A receives 10,000 votes, B receives 5,000, C receives 3,000
3. Day 7: Sponsor calls `RemoveOption("Project A")` (no timestamp check prevents this)
4. Days 7-10: Only Project B and C can receive new votes; Project B reaches 11,000 votes
5. Outcome: Project B declared winner despite Project A legitimately leading with 10,000 votes

**For Election Contract (Medium Severity):**
The Election contract uses these methods for candidate management [8](#0-7)  and `QuitElection` removes candidates without replacement. [9](#0-8) 

## Likelihood Explanation

**Reachable Entry Points**: Both `AddOption` and `RemoveOption` are public RPC methods defined in the contract interface. [10](#0-9) 

**Feasible Preconditions:**
- Attacker must be the voting item sponsor OR compromise sponsor account
- Sponsor role is easily obtainable - anyone can register voting items and become sponsor
- Many governance scenarios have sponsors with conflicts of interest (e.g., competing project proposers)
- Multi-sig sponsors increase compromise surface area

**Execution Practicality:**
- Single transaction call with minimal gas fees
- No complex state manipulation required
- The Election contract actively demonstrates this functionality is operational and in production use

**Detection Constraints:**
- Option modifications are recorded on-chain but no events are emitted for option changes
- Users typically don't monitor option lists continuously during voting
- Removed options remain in `VotingResult.Results` making manipulation subtle
- By the time manipulation is discovered, voting period may have ended

**Probability Assessment**: Medium-High. While requiring sponsor privileges, the ease of obtaining sponsor role combined with inherent conflicts of interest in governance scenarios makes this realistically exploitable.

## Recommendation

Add timestamp validation to both `AddOption` and `RemoveOption` methods to prevent option manipulation during active voting periods:

```csharp
public override Empty AddOption(AddOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // ADD: Prevent option changes during active voting period
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp || 
           Context.CurrentBlockTime > votingItem.EndTimestamp,
           "Cannot modify options during active voting period.");
    
    AssertOption(votingItem, input.Option);
    Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    votingItem.Options.Add(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Apply the same validation to `RemoveOption`. For the Election contract's unlimited-duration use case, consider a separate flag (e.g., `AllowDynamicOptions`) in the registration to explicitly permit option modifications during voting.

## Proof of Concept

The existing test demonstrates the vulnerability: [11](#0-10) 

This test shows that after votes are cast in phase 1, new options are successfully added in phase 2 during the active voting period, and those new options can receive votes - proving that option manipulation during active voting is possible and operational.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteExtensions.cs (L7-12)
```csharp
    public static Hash GetHash(this VotingRegisterInput votingItemInput, Address sponsorAddress)
    {
        var input = votingItemInput.Clone();
        input.Options.Clear();
        return HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(input), HashHelper.ComputeFrom(sponsorAddress));
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L280-290)
```csharp
    public override Empty AddOption(AddOptionInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        AssertOption(votingItem, input.Option);
        Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
        votingItem.Options.Add(input.Option);
        State.VotingItems[votingItem.VotingItemId] = votingItem;
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L351-366)
```csharp
    private Hash AssertValidNewVotingItem(VotingRegisterInput input)
    {
        // Use input without options and sender's address to calculate voting item id.
        var votingItemId = input.GetHash(Context.Sender);

        Assert(State.VotingItems[votingItemId] == null, "Voting item already exists.");

        // total snapshot number can't be 0. At least one epoch is required.
        if (input.TotalSnapshotNumber == 0) input.TotalSnapshotNumber = 1;

        Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");

        Context.LogDebug(() => $"Voting item created by {Context.Sender}: {votingItemId.ToHex()}");

        return votingItemId;
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

**File:** test/AElf.Contracts.Vote.Tests/Full/VoteForBestLanguageTests.cs (L12-129)
```csharp
    public async Task MultipleUsers_Vote_Scenario_Test()
    {
        var registerItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 3);

        var user1 = Accounts[1];
        var user2 = Accounts[2];
        var user3 = Accounts[3];

        //phase 1
        {
            //user1 vote 100
            var transactionResult1 = await Vote(user1.KeyPair, registerItem.VotingItemId, registerItem.Options[0], 100);
            transactionResult1.Status.ShouldBe(TransactionResultStatus.Mined);

            //user2 vote 150
            var transactionResult2 = await Vote(user2.KeyPair, registerItem.VotingItemId, registerItem.Options[0], 150);
            transactionResult2.Status.ShouldBe(TransactionResultStatus.Mined);

            //user3 vote 200
            var transactionResult3 = await Vote(user3.KeyPair, registerItem.VotingItemId, registerItem.Options[1], 200);
            transactionResult3.Status.ShouldBe(TransactionResultStatus.Mined);

            var votingResult = await GetVotingResult(registerItem.VotingItemId, 1);
            votingResult.VotersCount.ShouldBe(3);
            votingResult.Results.Count.ShouldBe(2);
            votingResult.Results[registerItem.Options[0]].ShouldBe(250);
            votingResult.Results[registerItem.Options[1]].ShouldBe(200);

            //take snapshot
            var snapshotResult = await TakeSnapshot(registerItem.VotingItemId, 1);
            snapshotResult.Status.ShouldBe(TransactionResultStatus.Mined);

            //query vote ids
            var voteIds = await GetVoteIds(user1.KeyPair, registerItem.VotingItemId);
            //query result
            var voteRecord = await GetVotingRecord(voteIds.ActiveVotes.First());
            voteRecord.Option.ShouldBe(registerItem.Options[0]);
            voteRecord.Amount.ShouldBe(100);

            //withdraw
            var beforeBalance = GetUserBalance(user1.Address);
            await Withdraw(user1.KeyPair, voteIds.ActiveVotes.First());
            var afterBalance = GetUserBalance(user1.Address);

            beforeBalance.ShouldBe(afterBalance - 100);

            voteIds = await GetVoteIds(user1.KeyPair, registerItem.VotingItemId);
            voteIds.ActiveVotes.Count.ShouldBe(0);
            voteIds.WithdrawnVotes.Count.ShouldBe(1);
        }

        //phase 2
        {
            //add some more option
            var options = new[]
            {
                Accounts[3].Address.ToBase58(),
                Accounts[4].Address.ToBase58(),
                Accounts[5].Address.ToBase58()
            };
            var optionResult = (await VoteContractStub.AddOptions.SendAsync(new AddOptionsInput
            {
                VotingItemId = registerItem.VotingItemId,
                Options = { options }
            })).TransactionResult;
            optionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            //user1 vote new option 1
            var transactionResult1 = await Vote(user1.KeyPair, registerItem.VotingItemId, options[0], 100);
            transactionResult1.Status.ShouldBe(TransactionResultStatus.Mined);

            //user2 vote new option 2
            var transactionResult2 = await Vote(user2.KeyPair, registerItem.VotingItemId, options[1], 100);
            transactionResult2.Status.ShouldBe(TransactionResultStatus.Mined);

            //user3 vote new option 3 twice
            var transactionResult3 = await Vote(user3.KeyPair, registerItem.VotingItemId, options[2], 100);
            transactionResult3.Status.ShouldBe(TransactionResultStatus.Mined);
            transactionResult3 = await Vote(user3.KeyPair, registerItem.VotingItemId, options[2], 100);
            transactionResult3.Status.ShouldBe(TransactionResultStatus.Mined);

            var votingResult = await GetVotingResult(registerItem.VotingItemId, 2);
            votingResult.VotersCount.ShouldBe(7);
            votingResult.Results.Count.ShouldBe(3);
            votingResult.Results[options[0]].ShouldBe(100);
            votingResult.Results[options[1]].ShouldBe(100);
            votingResult.Results[options[2]].ShouldBe(200);

            //take snapshot
            var snapshotResult = await TakeSnapshot(registerItem.VotingItemId, 2);
            snapshotResult.Status.ShouldBe(TransactionResultStatus.Mined);

            //query vote ids
            var user1VoteIds = await GetVoteIds(user1.KeyPair, registerItem.VotingItemId);
            user1VoteIds.ActiveVotes.Count.ShouldBe(1);
            user1VoteIds.WithdrawnVotes.Count.ShouldBe(1);

            var user2VoteIds = await GetVoteIds(user2.KeyPair, registerItem.VotingItemId);
            user2VoteIds.ActiveVotes.Count.ShouldBe(2);
            user2VoteIds.WithdrawnVotes.Count.ShouldBe(0);

            var user3VoteIds = await GetVoteIds(user3.KeyPair, registerItem.VotingItemId);
            user3VoteIds.ActiveVotes.Count.ShouldBe(3);
            user3VoteIds.WithdrawnVotes.Count.ShouldBe(0);
        }

        //phase 3
        {
            //take snapshot
            var snapshotResult = await TakeSnapshot(registerItem.VotingItemId, 3);
            snapshotResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var transactionResult =
                await VoteWithException(user2.KeyPair, registerItem.VotingItemId, registerItem.Options[0], 100);
            transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            transactionResult.Error.Contains("Current voting item already ended").ShouldBeTrue();
        }
    }
```

**File:** protobuf/vote_contract.proto (L35-49)
```text
    // Add an option to a voting activity.
    rpc AddOption (AddOptionInput) returns (google.protobuf.Empty) {
    }

    // Remove an option from a voting activity.
    rpc RemoveOption (RemoveOptionInput) returns (google.protobuf.Empty) {
    }

    // Add multiple options to a voting activity.
    rpc AddOptions (AddOptionsInput) returns (google.protobuf.Empty) {
    }

    // Remove multiple options from a voting activity.
    rpc RemoveOptions (RemoveOptionsInput) returns (google.protobuf.Empty) {
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L197-209)
```csharp
    private void AddCandidateAsOption(string publicKey)
    {
        if (State.VoteContract.Value == null)
            State.VoteContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName);

        // Add this candidate as an option for the the Voting Item.
        State.VoteContract.AddOption.Send(new AddOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = publicKey
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L257-261)
```csharp
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
```
