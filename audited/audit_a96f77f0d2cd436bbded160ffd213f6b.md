### Title
Vote Contract Timestamp Enforcement Missing - Sponsor Can Manipulate Snapshot Timing

### Summary
The Vote contract accepts `StartTimestamp` and `EndTimestamp` parameters during voting item registration but never enforces these time constraints. The sponsor has unrestricted control over when to call `TakeSnapshot()`, allowing strategic timing to capture favorable voting states, even indefinitely past the declared end time. This enables timing-based manipulation of voting outcomes and violates voter expectations about voting deadlines.

### Finding Description

**Root Cause:**
The Vote contract stores timestamp fields but lacks enforcement logic in critical functions. [1](#0-0) 

The only timestamp validation occurs during registration, checking that `EndTimestamp > StartTimestamp`. However, these timestamps are never validated afterward. [2](#0-1) 

The `Vote()` function validates voting eligibility through `AssertValidVoteInput()`: [3](#0-2) 

This validation only checks snapshot numbers (`CurrentSnapshotNumber <= TotalSnapshotNumber`) with no comparison of `Context.CurrentBlockTime` against the voting item's `StartTimestamp` or `EndTimestamp`. [4](#0-3) 

The `TakeSnapshot()` function similarly lacks any timestamp validation. It only verifies:
- Sponsor permission (line 245)
- Snapshot number limits (lines 247-248)  
- Sequential snapshot numbers (lines 256-257)

No code prevents the sponsor from delaying `TakeSnapshot()` indefinitely, even past `EndTimestamp`. [5](#0-4) 

The protocol documentation describes these fields as "The start time of the voting" and "The end time of the voting," creating a reasonable expectation that they define enforceable voting periods.

**Why Protections Fail:**
The contract accepts timestamp parameters and stores them in the `VotingItem` structure, but no execution path validates `Context.CurrentBlockTime` against these boundaries. This creates a misleading API where time constraints appear configurable but are actually non-functional.

### Impact Explanation

**Governance Manipulation:**
- Sponsors can strategically time snapshot captures to include/exclude specific votes
- If early votes are unfavorable, sponsor waits for more votes before taking snapshot
- If votes become unfavorable later, sponsor can take snapshot immediately
- Voting can continue indefinitely past the declared `EndTimestamp`

**Voter Expectation Violation:**
- Voters see `StartTimestamp` and `EndTimestamp` and reasonably believe voting ends at that time
- Voters may not cast votes thinking the period has ended
- Voters may rush to vote before `EndTimestamp` when timing is actually irrelevant

**Protocol-Level Impact:**
- Violates critical governance invariant: "proposal lifetime/expiration"
- Undermines trust in voting mechanisms
- Affects any contract using Vote contract infrastructure beyond the Election contract
- Creates timing attack surface for governance decisions

**Severity Justification: High**
- Direct governance impact enabling outcome manipulation
- Affects core voting infrastructure used across the protocol
- No operational constraints prevent exploitation
- Violates fundamental governance fairness principles

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker is the voting item sponsor (registered voter system creator)
- No special privileges needed beyond being sponsor
- No collusion required (though colluding with voters amplifies impact)

**Attack Complexity: Trivial**
- Sponsor simply delays calling `TakeSnapshot()` 
- No complex transactions or state manipulation required
- No race conditions or timing precision needed

**Feasibility Conditions:**
- Entry point is `TakeSnapshot()` at line 241 - publicly accessible to sponsor [6](#0-5) 

- Sponsor permission check is the only restriction
- No timestamp checks present to limit when this can be called

**Economic Rationality:**
- Zero cost to execute (just delay action)
- High benefit: control over voting outcome timing
- Particularly valuable in close votes or governance decisions
- Rational for sponsor to optimize snapshot timing

**Detection Constraints:**
- Difficult to detect as malicious vs legitimate delay
- No on-chain evidence distinguishes intentional manipulation from operational delays
- Users have no recourse if sponsor delays snapshot

**Probability: High**
- Simple to execute
- Strong economic incentive
- No technical barriers
- No enforcement mechanism exists

### Recommendation

**Code-Level Mitigation:**

Add timestamp validation to both `Vote()` and `TakeSnapshot()` functions:

**In `AssertValidVoteInput()` (around line 382):**
```csharp
Assert(Context.CurrentBlockTime >= votingItem.StartTimestamp, 
    "Voting has not started yet.");
Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
    "Voting has already ended.");
```

**In `TakeSnapshot()` (around line 248):**
```csharp
Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
    "Cannot take snapshot after voting period has ended.");
```

**Or, if timestamps should be advisory:**
Remove `StartTimestamp` and `EndTimestamp` from the contract entirely, or clearly document them as non-enforced metadata fields to avoid misleading users.

**Invariant Checks to Add:**
- `CurrentBlockTime` must be within `[StartTimestamp, EndTimestamp]` for voting
- Snapshots can only be taken before or at `EndTimestamp`
- Consider adding maximum snapshot delay constraints

**Test Cases to Add:**
- Attempt to vote before `StartTimestamp` (should fail)
- Attempt to vote after `EndTimestamp` (should fail)
- Attempt to take snapshot after `EndTimestamp` (should fail)
- Verify timestamps are actually enforced in integration tests

### Proof of Concept

**Initial State:**
1. Sponsor registers voting item with `StartTimestamp` = T0 and `EndTimestamp` = T0 + 7 days
2. Voters believe voting period is 7 days

**Attack Sequence:**

**Step 1 (Day 1-3):** Early voters cast votes
- 60% vote for Option A (unfavorable to sponsor)
- 40% vote for Option B (favorable to sponsor)

**Step 2 (Day 8 - Past EndTimestamp):** Sponsor does NOT call `TakeSnapshot()`
- Voting continues despite `EndTimestamp` being reached
- No validation prevents continued voting

**Step 3 (Day 9-14):** Additional votes are cast
- Late voters believe voting ended, but it continues
- New votes shift balance to 45% Option A, 55% Option B

**Step 4 (Day 14):** Sponsor calls `TakeSnapshot()`
- Captures favorable 55% Option B result
- No timestamp validation prevents this [7](#0-6) 

**Expected Result:** 
Voting should end at T0 + 7 days, snapshot cannot be taken after `EndTimestamp`, late votes are rejected.

**Actual Result:**
Voting continues indefinitely, sponsor can take snapshot at any time to capture most favorable state, timestamps serve no functional purpose.

**Success Condition:**
The sponsor successfully manipulates voting outcome by strategic snapshot timing, demonstrating the lack of timestamp enforcement enables timing-based governance attacks.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L361-361)
```csharp
        Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");
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

**File:** protobuf/vote_contract.proto (L87-91)
```text
message VotingRegisterInput {
    // The start time of the voting.
    google.protobuf.Timestamp start_timestamp = 1;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 2;
```
