### Title
Sponsor Can Manipulate Voting Outcomes Through Unrestricted Option Management and Snapshot Timing Control

### Summary
The Vote contract allows sponsors to add/remove voting options and take snapshots at any time during active voting without temporal restrictions or fairness checks. This enables malicious sponsors to manipulate voting outcomes by removing options with unfavorable vote counts, adding diluting options mid-voting, or taking snapshots at strategically favorable moments, fundamentally undermining the integrity of the voting process.

### Finding Description

**Root Cause**: Missing temporal access controls on sponsor-privileged administrative functions.

The Vote contract grants sponsors unrestricted control over critical voting parameters during active voting periods through four functions:

1. **AddOption/RemoveOption** - Only verify sponsor identity without timing restrictions: [1](#0-0) [2](#0-1) 

2. **AddOptions/RemoveOptions** - Similarly lack temporal constraints: [3](#0-2) [4](#0-3) 

3. **TakeSnapshot** - Can be called at arbitrary times with only snapshot number validation: [5](#0-4) 

**Critical Flaws**:

**Flaw 1: No Validation Against Active Voting Period**
None of these functions check whether voting is active by comparing `Context.CurrentBlockTime` against the voting item's `StartTimestamp` and `EndTimestamp`. The only temporal data stored is: [6](#0-5) 

But these timestamps are never validated in the option management or snapshot functions.

**Flaw 2: Option Removal Creates Unfair Vote Asymmetry**
When `RemoveOption` is called, it only removes the option from the available choices but does NOT update existing voting results: [7](#0-6) 

This creates a critical asymmetry because:
- Existing votes for the removed option remain in `VotingResult.Results` dictionary [8](#0-7) 

- But new voters cannot vote for that option due to this validation: [9](#0-8) 

**Flaw 3: Unrestricted Snapshot Timing**
The TakeSnapshot function only validates sponsor permission and snapshot number sequence, with no minimum duration or fairness constraints. Testing confirms snapshots can be taken in rapid succession without delays: [10](#0-9) 

**Flaw 4: Vote Function Lacks Timestamp Validation**
The vote validation function does not verify that the current time falls within the voting period: [11](#0-10) 

It only checks snapshot numbers, not actual timestamps against `StartTimestamp`/`EndTimestamp`.

### Impact Explanation

**Concrete Harm**:

1. **Vote Suppression**: Sponsor monitors real-time voting results and removes options gaining unfavorable traction, effectively disenfranchising voters who supported those options while preventing new votes for them.

2. **Vote Dilution**: Sponsor adds new options mid-voting to split votes away from a leading opposition option, manipulating the relative standings.

3. **Result Manipulation via Timing**: Sponsor takes snapshots at strategically favorable moments (e.g., immediately after their supporters vote but before opposition can participate), freezing biased results.

4. **Fairness Violation**: The asymmetric treatment of votes cast before vs. after option removal fundamentally breaks the principle that all voters should have equal opportunities under consistent rules.

**Affected Parties**:
- All voters participating in sponsor-created voting activities lose fairness guarantees
- Downstream systems relying on Vote contract results (e.g., governance decisions, resource allocation) receive manipulated data
- The entire voting system's credibility is undermined

**Severity Justification**: HIGH
- Direct governance impact through manipulated voting outcomes
- Affects core voting integrity invariant
- Enables sponsor to predetermine outcomes while maintaining appearance of fair voting
- No cryptographic or economic barriers to exploitation

### Likelihood Explanation

**Attacker Capabilities**: 
The attacker must be the sponsor of a voting item, which is set during registration: [12](#0-11) 

Any address can become a sponsor by calling `Register`, making this a realistic precondition.

**Attack Complexity**: LOW
- Single transaction calls to `RemoveOption`, `AddOption`, or `TakeSnapshot`
- No complex state setup or multi-step sequences required
- No timing windows or race conditions to exploit
- Operations are standard contract calls with no special requirements

**Feasibility Conditions**:
- Sponsor role established at registration (publicly accessible)
- No additional permissions, signatures, or approvals needed
- Real-time monitoring of vote counts is possible through view functions: [13](#0-12) 

**Detection/Operational Constraints**:
- Operations are transparent on-chain but can be executed quickly
- By the time manipulation is detected, votes may already be affected
- No contract-level prevention mechanism exists

**Probability Reasoning**: 
High likelihood due to:
- Simple execution path
- Common sponsor role availability
- Direct financial or governance incentives for manipulation
- Zero technical barriers beyond sponsor status

### Recommendation

**Immediate Mitigations**:

1. **Add Temporal Access Controls to Option Management**:
```csharp
// In AddOption, RemoveOption, AddOptions, RemoveOptions functions
Assert(Context.CurrentBlockTime < votingItem.StartTimestamp, 
    "Cannot modify options after voting has started.");
```

Add this check immediately after the sponsor verification at: [14](#0-13) [15](#0-14) [16](#0-15) [17](#0-16) 

2. **Add Minimum Snapshot Duration Constraint**:
```csharp
// In TakeSnapshot function after sponsor check
var minimumSnapshotDuration = // define appropriate duration
Assert(Context.CurrentBlockTime >= 
    votingItem.CurrentSnapshotStartTimestamp.AddSeconds(minimumSnapshotDuration),
    "Minimum snapshot duration not met.");
```

3. **Add Vote Timestamp Validation**:
```csharp
// In AssertValidVoteInput function
Assert(Context.CurrentBlockTime >= votingItem.StartTimestamp && 
       Context.CurrentBlockTime <= votingItem.EndTimestamp,
    "Voting outside allowed time period.");
```

4. **Clean Up Votes on Option Removal** (if removal must be allowed pre-voting):
When removing an option, either:
    - Refund/unlock all existing votes for that option, OR
    - Prevent removal entirely if any votes exist for that option

**Invariant Checks to Add**:
- Option list modifications only allowed before `StartTimestamp`
- Minimum time interval between consecutive snapshots
- Vote operations only allowed within `[StartTimestamp, EndTimestamp]`
- Option removal forbidden if `VotingResult.Results[option] > 0`

**Test Cases**:
1. Test that `AddOption` fails when called after `StartTimestamp`
2. Test that `RemoveOption` fails when called after `StartTimestamp`
3. Test that `TakeSnapshot` fails when called before minimum duration elapsed
4. Test that `Vote` fails when `CurrentBlockTime < StartTimestamp`
5. Test that `Vote` fails when `CurrentBlockTime > EndTimestamp`
6. Test that option removal with existing votes is properly handled

### Proof of Concept

**Initial State**:
1. Sponsor registers voting item with options ["OptionA", "OptionB"], StartTimestamp = T+1 hour, EndTimestamp = T+7 days
2. Token whitelist configured for accepted currency
3. Multiple voters have sufficient token balances

**Attack Sequence**:

**Scenario 1: Option Removal Manipulation**
1. Time = T+2 hours (voting is active)
2. Voter1 votes 1000 tokens for "OptionA"
3. Voter2 votes 500 tokens for "OptionA"
4. Sponsor queries results, sees "OptionA" leading
5. Sponsor calls `RemoveOption(votingItemId, "OptionA")` - **SUCCEEDS** (no timestamp check)
6. Voter3 attempts to vote for "OptionA" - **FAILS** ("Option OptionA not found")
7. OptionA's 1500 votes remain in VotingResult but option is no longer available
8. Sponsor's preferred "OptionB" now effectively wins by default

**Scenario 2: Snapshot Timing Manipulation**
1. Time = T+1 hour (voting just started)
2. Sponsor's supporters (Voter1, Voter2) immediately vote 2000 tokens for "OptionB"
3. Sponsor immediately calls `TakeSnapshot(votingItemId, 1)` - **SUCCEEDS** (no minimum duration)
4. Opposition voters (Voter3, Voter4) arrive 10 minutes later with 5000 tokens
5. Snapshot 1 already frozen with "OptionB" leading
6. Even though total votes eventually favor opposition, Snapshot 1 (which may be used for decisions) shows sponsor's preferred outcome

**Expected vs Actual Result**:
- **Expected**: Option modifications and snapshot timing should be restricted to ensure fair voting
- **Actual**: Sponsor can manipulate at will, with zero contract-level prevention

**Success Condition**: 
Exploitation succeeds if sponsor can modify options or take snapshots during active voting without triggering any access control failures based on timestamps or fairness constraints. Current implementation allows all attack scenarios to succeed.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-52)
```csharp
    public override Empty Register(VotingRegisterInput input)
    {
        var votingItemId = AssertValidNewVotingItem(input);

        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Accepted currency is in white list means this token symbol supports voting.
        var isInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
        {
            Symbol = input.AcceptedCurrency,
            Address = Context.Self
        }).Value;
        Assert(isInWhiteList, "Claimed accepted token is not available for voting.");

        // Initialize voting event.
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L241-273)
```csharp
    public override Empty TakeSnapshot(TakeSnapshotInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);

        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can take snapshot.");

        Assert(votingItem.CurrentSnapshotNumber - 1 < votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");

        // Update previous voting going information.
        var previousVotingResultHash = GetVotingResultHash(input.VotingItemId, votingItem.CurrentSnapshotNumber);
        var previousVotingResult = State.VotingResults[previousVotingResultHash];
        previousVotingResult.SnapshotEndTimestamp = Context.CurrentBlockTime;
        State.VotingResults[previousVotingResultHash] = previousVotingResult;

        Assert(votingItem.CurrentSnapshotNumber == input.SnapshotNumber,
            $"Can only take snapshot of current snapshot number: {votingItem.CurrentSnapshotNumber}, but {input.SnapshotNumber}");
        var nextSnapshotNumber = input.SnapshotNumber.Add(1);
        votingItem.CurrentSnapshotNumber = nextSnapshotNumber;
        State.VotingItems[votingItem.VotingItemId] = votingItem;

        // Initial next voting going information.
        var currentVotingGoingHash = GetVotingResultHash(input.VotingItemId, nextSnapshotNumber);
        State.VotingResults[currentVotingGoingHash] = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = nextSnapshotNumber,
            SnapshotStartTimestamp = Context.CurrentBlockTime,
            VotersCount = previousVotingResult.VotersCount,
            VotesAmount = previousVotingResult.VotesAmount
        };
        return new Empty();
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

**File:** test/AElf.Contracts.Vote.Tests/BVT/SnapshotTests.cs (L78-101)
```csharp
    public async Task VoteContract_TakeSnapshot_Success_Test()
    {
        var registerItem = await RegisterVotingItemAsync(10, 4, true, DefaultSender, 3);
        for (var i = 0; i < 3; i++)
        {
            var transactionResult = (await VoteContractStub.TakeSnapshot.SendAsync(
                new TakeSnapshotInput
                {
                    VotingItemId = registerItem.VotingItemId,
                    SnapshotNumber = i + 1
                })).TransactionResult;

            transactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var votingItem = await GetVoteItem(registerItem.VotingItemId);
            votingItem.CurrentSnapshotNumber.ShouldBe(i + 2);
            var voteResult = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
            {
                VotingItemId = registerItem.VotingItemId,
                SnapshotNumber = i + 2
            });
            voteResult.SnapshotNumber.ShouldBe(i + 2);
        }
    }
```

**File:** docs/resources/smart-contract-apis/vote.md (L231-265)
```markdown
### GetVotingResult

Gets a voting result according to the provided voting activity id and round number.

```Protobuf
rpc GetVotingResult (GetVotingResultInput) returns (VotingResult) {}
 
message GetVotingResultInput {
    aelf.Hash voting_item_id = 1;
    sint64 snapshot_number = 2;
}

message VotingResult {
    aelf.Hash voting_item_id = 1;
    map<string, sint64> results = 2; // option -> amount
    sint64 snapshot_number = 3;
    sint64 voters_count = 4;
    google.protobuf.Timestamp snapshot_start_timestamp = 5;
    google.protobuf.Timestamp snapshot_end_timestamp = 6;
    sint64 votes_amount = 7;
}
```

**GetVotingResultInput**:
- **voting item id**: voting activity id.
- **snapshot number**: round number.

**returns**:
- **voting item id**: voting activity id.
- **results**: candidate => vote amount.
- **snapshot number**: round number.
- **voters count**: how many voters.
- **snapshot start timestamp**: start time.
- **snapshot end timestamp**: end time.
- **votes amount** total votes(excluding withdraws).
```
