# Audit Report

## Title
Sponsor Can Manipulate Voting Outcomes Through Unrestricted Option Modification During Active Voting

## Summary
The Vote contract allows sponsors to add or remove voting options at any time without validating whether voting is active or votes have been cast. This enables sponsors to manipulate voting outcomes by adding new options mid-vote for collusion or removing winning options to invalidate votes, directly undermining the integrity of the voting system.

## Finding Description

The Vote contract contains four option modification methods that lack critical timing and state validations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

These methods only verify sponsor authorization but fail to check:
1. Whether the voting period has started (no validation against `StartTimestamp`)
2. Whether voting is still active (no validation against `EndTimestamp`)
3. Whether votes have been cast (no check of vote existence)

The VotingItem structure contains timestamp fields that define the voting period: [5](#0-4) 

However, the option modification methods never validate against these timestamps. Meanwhile, the Vote method strictly enforces that voters can only vote for options currently in the options list: [6](#0-5) 

This creates an exploitable inconsistency window. When votes are cast, they are stored in the VotingResult.Results mapping by option name: [7](#0-6) 

If a sponsor removes an option after votes have been cast for it, those votes remain in the Results map but the option is removed from the visible options list returned by GetVotingItem: [8](#0-7) 

This effectively invalidates those votes while preventing new voters from selecting that option.

**Attack Scenarios:**

1. **Late Option Addition for Collusion**: After honest voters cast their votes for existing options A, B, C, the sponsor adds option D mid-vote and coordinates with colluding voters to vote for it. Early voters who already voted have no knowledge of option D and cannot adjust their votes.

2. **Vote Invalidation via Option Removal**: If option A is winning with significant votes, the sponsor removes option A. The votes remain in `VotingResult.Results["A"]` but option A is removed from `votingItem.Options`. New voters cannot vote for A (fails the assertion check), and the option is hidden from the visible options list, effectively invalidating those votes.

## Impact Explanation

**Severity: HIGH**

This vulnerability directly undermines the fundamental purpose of the voting system - fair and transparent democratic decision-making. The impact includes:

1. **Governance Manipulation**: Sponsors can directly control voting outcomes through option manipulation, enabling systematic capture of governance decisions.

2. **Vote Invalidation**: Sponsors can retroactively invalidate votes by removing winning options, making those votes invisible to new voters while keeping them in the underlying data structure.

3. **Unfair Advantage**: Early voters operate with incomplete information when sponsors can add options after voting begins, creating an asymmetric information advantage.

4. **Trust Breakdown**: All voters are affected as their voting decisions can be rendered meaningless through sponsor manipulation. Any system relying on this voting mechanism for governance, elections, or decision-making is compromised.

The vote contract is used throughout the AElf ecosystem for governance decisions, and this vulnerability affects the integrity of all such decisions.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Attacker Capabilities**: The sponsor role is obtained simply by calling the `Register` method to create a voting item - any user can become a sponsor. No special privileges beyond sponsor status are required.

2. **Attack Complexity: LOW**: The exploit requires only calling public methods (`AddOption`, `RemoveOption`, `AddOptions`, `RemoveOptions`) with standard transaction fees. No complex setup, precise timing, or technical sophistication is needed.

3. **Execution Practicality**: The attack is fully executable within AElf contract semantics using standard method calls. All option modification methods are public entry points accessible to sponsors.

4. **Detection Difficulty**: The contract does not emit events when options are modified, making it difficult for voters to detect mid-vote manipulation unless they continuously monitor the voting item state.

5. **Economic Rationality**: The cost is minimal (standard transaction fees), while the potential benefit is enormous (controlling governance decisions, election outcomes, or other vote-dependent processes).

## Recommendation

Add timestamp and vote state validation to all option modification methods. The fix should:

1. **Add timestamp validation**: Check that current block time is before `StartTimestamp` to ensure options cannot be modified after voting begins.

2. **Add vote existence check**: Verify that no votes have been cast before allowing option removal to prevent invalidation of existing votes.

3. **Emit events**: Add events when options are modified so voters can detect changes.

Suggested fix for `AddOption` and `RemoveOption`:

```csharp
public override Empty AddOption(AddOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // NEW: Prevent modification after voting starts
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp, 
        "Cannot add options after voting has started.");
    
    AssertOption(votingItem, input.Option);
    Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    votingItem.Options.Add(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}

public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // NEW: Prevent modification after voting starts
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp, 
        "Cannot remove options after voting has started.");
    
    // NEW: Check if votes exist for this option
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    Assert(!votingResult.Results.ContainsKey(input.Option) || votingResult.Results[input.Option] == 0,
        "Cannot remove option that has received votes.");
    
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Apply similar fixes to `AddOptions` and `RemoveOptions` methods.

## Proof of Concept

```csharp
[Fact]
public async Task VoteContract_RemoveOption_After_Votes_Cast_Exploit()
{
    // 1. Sponsor creates voting item with 3 options
    var votingItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);
    var optionA = votingItem.Options[0];
    var optionB = votingItem.Options[1];
    var optionC = votingItem.Options[2];
    
    // 2. Multiple users vote for option A (it's winning)
    var voter1 = Accounts[1].KeyPair;
    var voter2 = Accounts[2].KeyPair;
    var voter3 = Accounts[3].KeyPair;
    
    await Vote(voter1, votingItem.VotingItemId, optionA, 100);
    await Vote(voter2, votingItem.VotingItemId, optionA, 100);
    await Vote(voter3, votingItem.VotingItemId, optionA, 100);
    
    // 3. Verify votes were cast for option A
    var votingResultBefore = await VoteContractStub.GetVotingResult.CallAsync(
        new GetVotingResultInput
        {
            VotingItemId = votingItem.VotingItemId,
            SnapshotNumber = 1
        });
    
    votingResultBefore.Results[optionA].ShouldBe(300); // 300 votes for option A
    votingResultBefore.VotersCount.ShouldBe(3);
    
    // 4. EXPLOIT: Sponsor removes option A after votes have been cast
    var removeResult = await VoteContractStub.RemoveOption.SendAsync(
        new RemoveOptionInput
        {
            VotingItemId = votingItem.VotingItemId,
            Option = optionA
        });
    
    removeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Successfully removed!
    
    // 5. Verify option A is removed from visible options
    var votingItemAfter = await GetVoteItem(votingItem.VotingItemId);
    votingItemAfter.Options.Contains(optionA).ShouldBeFalse(); // Option A is gone!
    votingItemAfter.Options.Count.ShouldBe(2); // Only 2 options remain
    
    // 6. Verify votes for option A still exist in results (but option is hidden)
    var votingResultAfter = await VoteContractStub.GetVotingResult.CallAsync(
        new GetVotingResultInput
        {
            VotingItemId = votingItem.VotingItemId,
            SnapshotNumber = 1
        });
    
    votingResultAfter.Results[optionA].ShouldBe(300); // Votes still exist in data
    votingResultAfter.VotersCount.ShouldBe(3); // Vote count still includes these votes
    
    // 7. Verify new voters CANNOT vote for option A
    var newVoter = Accounts[4].KeyPair;
    var voteForA = await VoteWithException(newVoter, votingItem.VotingItemId, optionA, 100);
    voteForA.Status.ShouldBe(TransactionResultStatus.Failed);
    voteForA.Error.ShouldContain($"Option {optionA} not found"); // Cannot vote for removed option!
    
    // IMPACT: 300 votes for option A are invalidated - option removed from visible list,
    // but votes remain in underlying data. New voters cannot vote for option A.
    // Sponsor has effectively manipulated the voting outcome.
}

[Fact]
public async Task VoteContract_AddOption_During_Active_Voting_Exploit()
{
    // 1. Sponsor creates voting item with 3 options
    var votingItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 1);
    
    // 2. Early voters cast their votes for existing options
    var earlyVoter1 = Accounts[1].KeyPair;
    var earlyVoter2 = Accounts[2].KeyPair;
    
    await Vote(earlyVoter1, votingItem.VotingItemId, votingItem.Options[0], 100);
    await Vote(earlyVoter2, votingItem.VotingItemId, votingItem.Options[1], 100);
    
    // 3. EXPLOIT: Sponsor adds new option D after voting has started
    var newOption = "Option_D_Added_Mid_Vote";
    var addResult = await VoteContractStub.AddOption.SendAsync(
        new AddOptionInput
        {
            VotingItemId = votingItem.VotingItemId,
            Option = newOption
        });
    
    addResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Successfully added!
    
    // 4. Verify new option is now available
    var votingItemAfter = await GetVoteItem(votingItem.VotingItemId);
    votingItemAfter.Options.Contains(newOption).ShouldBeTrue(); // New option exists!
    votingItemAfter.Options.Count.ShouldBe(4); // Now 4 options
    
    // 5. Late voters (colluding with sponsor) can vote for the new option
    var lateVoter = Accounts[3].KeyPair;
    var voteForNewOption = await Vote(lateVoter, votingItem.VotingItemId, newOption, 200);
    voteForNewOption.Status.ShouldBe(TransactionResultStatus.Mined); // Can vote for new option!
    
    // IMPACT: Early voters had no knowledge of option D when they voted.
    // Sponsor added it mid-vote and coordinated with late voters to vote for it.
    // This creates unfair advantage and enables collusion to manipulate outcomes.
}
```

## Notes

The vulnerability is confirmed through code analysis of the Vote contract. The option modification methods lack fundamental protections that are standard in voting systems: immutability of options after voting begins and protection of cast votes from invalidation. The test suite does not include tests for these scenarios, indicating this attack vector was not considered during development.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L314-324)
```csharp
    public override Empty AddOptions(AddOptionsInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        foreach (var option in input.Options) AssertOption(votingItem, option);
        votingItem.Options.AddRange(input.Options);
        Assert(votingItem.Options.Count <= VoteContractConstants.MaximumOptionsCount,
            $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
        State.VotingItems[votingItem.VotingItemId] = votingItem;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L326-339)
```csharp
    public override Empty RemoveOptions(RemoveOptionsInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        foreach (var option in input.Options)
        {
            Assert(votingItem.Options.Contains(option), "Option doesn't exist.");
            Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
            votingItem.Options.Remove(option);
        }

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

**File:** contract/AElf.Contracts.Vote/ViewMethods.cs (L27-32)
```csharp
    public override VotingItem GetVotingItem(GetVotingItemInput input)
    {
        var votingEvent = State.VotingItems[input.VotingItemId];
        Assert(votingEvent != null, "Voting item not found.");
        return votingEvent;
    }
```
