### Title
Sponsor Can Add Voting Options Mid-Vote Allowing Vote Manipulation and Outcome Rigging

### Summary
The `AddOption()` function in VoteContract allows the sponsor to add new voting options at any time during active voting, including after votes have been cast within the current snapshot. This creates an unfair voting process where early voters cannot see options added later, and sponsors can manipulate outcomes by strategically introducing competing options to split votes from leading choices.

### Finding Description

The `AddOption()` function only validates sponsor authorization, option uniqueness, length limits, and maximum option count, but performs no checks related to the voting timeline or active voting status. [1](#0-0) 

The VotingItem structure contains `StartTimestamp` and `EndTimestamp` fields that define the voting period, set during registration. [2](#0-1) 

While the `Vote()` function validates that voting is within the active period through `AssertValidVoteInput()`, no such validation exists in `AddOption()`. [3](#0-2) 

The root cause is the absence of temporal validation checks in `AddOption()`. The function should verify:
1. Current time is before `StartTimestamp` (voting hasn't started)
2. No votes exist in the current snapshot (if mid-voting addition is intended, it should only occur between snapshots)

The only validation performed is basic option validation (length and uniqueness). [4](#0-3) 

### Impact Explanation

**Direct Governance Impact**: This vulnerability allows sponsors to manipulate voting outcomes through several attack vectors:

1. **Vote Splitting**: After observing interim results, sponsors can add similar options to split votes from the leading choice. Example: If "Option A" leads with 60% of votes, sponsor adds "Option A2" causing later voters to split between A and A2, potentially changing the winner.

2. **Unfair Information Asymmetry**: Early voters make decisions based on incomplete option sets, while later voters see additional choices. This violates the fundamental principle that all voters should have equal information.

3. **Strategic Option Injection**: Sponsors can wait to see voting patterns and inject options designed to manipulate specific outcomes, such as adding extreme options to make moderate choices appear more attractive.

The harm affects all participants in voting systems using this contract for polls, referendums, or governance decisions where option stability is expected. While the Election contract intentionally uses this feature for continuous candidate addition, general voting items require option stability once voting begins. [5](#0-4) 

### Likelihood Explanation

**Highly Likely Exploitation**:

- **Reachable Entry Point**: `AddOption()` is a public function callable by any sponsor. [6](#0-5) 

- **Minimal Attack Complexity**: The sponsor only needs to call `AddOption()` with a new option string. No complex state manipulation or timing exploits required.

- **Zero Cost**: Unlike attacks requiring capital or tokens, this manipulation is free for the sponsor to execute.

- **No Detection Mechanism**: The contract provides no events or warnings when options are modified during active voting. Users have no way to detect this manipulation.

- **Realistic Preconditions**: The attacker must be the sponsor, which is the entity creating the vote. This is not a "trusted role compromise" but rather an abuse of sponsor privileges that should be constrained during active voting.

Tests demonstrate adding options after initial registration and between snapshots, but no protection exists against adding options within an active snapshot after votes are cast. [7](#0-6) 

### Recommendation

Implement temporal access controls in `AddOption()` to prevent option modifications during active voting:

```csharp
public override Empty AddOption(AddOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // NEW: Prevent adding options after voting has started
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp, 
        "Cannot add options after voting has started.");
    
    AssertOption(votingItem, input.Option);
    Assert(votingItem.Options.Count < VoteContractConstants.MaximumOptionsCount,
        $"The count of options can't greater than {VoteContractConstants.MaximumOptionsCount}");
    votingItem.Options.Add(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Alternative approach for use cases requiring dynamic options (like elections):
- Add a `bool AllowDynamicOptions` field to VotingItem during registration
- Only allow mid-vote option changes if this flag is explicitly enabled
- Apply the StartTimestamp check when flag is false

Apply the same fix to `AddOptions()`, `RemoveOption()`, and `RemoveOptions()` methods. [8](#0-7) [9](#0-8) 

Add test cases to verify:
1. Adding options before StartTimestamp succeeds
2. Adding options after StartTimestamp fails with appropriate error
3. Continuous election scenarios still work with dynamic options flag enabled

### Proof of Concept

**Initial State:**
- Sponsor creates voting item with options: "Option A", "Option B", "Option C"
- StartTimestamp: Block 100
- EndTimestamp: Block 1000
- Current snapshot: 1

**Attack Sequence:**

1. **Block 100-200**: Voting begins
   - User1 votes 100 tokens for "Option A"
   - User2 votes 80 tokens for "Option A"
   - User3 votes 50 tokens for "Option B"
   - User4 votes 30 tokens for "Option C"
   - Current results: A=180, B=50, C=30

2. **Block 250**: Sponsor sees "Option A" winning and adds "Option A Alternative"
   - Sponsor calls `AddOption()` with option="Option A Alternative"
   - Transaction succeeds (no StartTimestamp check)
   - VotingItem now has 4 options

3. **Block 251-900**: Continued voting with manipulated options
   - User5 sees 4 options, votes 70 tokens for "Option A Alternative"
   - User6 votes 60 tokens for "Option A Alternative"
   - User7 votes 40 tokens for "Option A"
   - User8 votes 35 tokens for "Option B"

**Final Result:**
- Option A: 220 votes (180+40)
- Option A Alternative: 130 votes (70+60)
- Option B: 85 votes (50+35)
- Option C: 30 votes

**Expected vs Actual:**
- **Expected**: Without manipulation, "Option A" would have received all 350 votes from A-preferring voters, maintaining clear lead
- **Actual**: Votes split between "Option A" (220) and "Option A Alternative" (130), potentially changing the winner or requiring additional rounds

**Success Condition**: The AddOption transaction succeeds at Block 250 despite voting being active since Block 100, demonstrating the absence of temporal validation. Users 1-4 never had the opportunity to vote for "Option A Alternative", violating voting fairness principles.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L37-52)
```csharp
        var votingItem = new VotingItem
        {
            Sponsor = Context.Sender,
            VotingItemId = votingItemId,
            AcceptedCurrency = input.AcceptedCurrency,
            IsLockToken = input.IsLockToken,
            TotalSnapshotNumber = input.TotalSnapshotNumber,
            CurrentSnapshotNumber = 1,
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
            RegisterTimestamp = Context.CurrentBlockTime,
            Options = { input.Options },
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
        };
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L292-296)
```csharp
    private void AssertOption(VotingItem votingItem, string option)
    {
        Assert(option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(!votingItem.Options.Contains(option), "Option already exists.");
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-383)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
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

**File:** protobuf/vote_contract.proto (L35-37)
```text
    // Add an option to a voting activity.
    rpc AddOption (AddOptionInput) returns (google.protobuf.Empty) {
    }
```

**File:** test/AElf.Contracts.Vote.Tests/Full/VoteForBestLanguageTests.cs (L65-77)
```csharp
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
```
