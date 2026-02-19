### Title
Missing Timestamp Validation Allows Voting Outside Valid Time Period

### Summary
The `Vote()` function in VoteContract.cs does not validate that `Context.CurrentBlockTime` falls within the voting period defined by `StartTimestamp` and `EndTimestamp`. The `AssertValidVoteInput()` helper function only checks snapshot numbers, not actual time boundaries, allowing users to cast votes before voting begins or after it should have ended. [1](#0-0) 

### Finding Description

**Location**: `VoteContract.cs`, `Vote()` method at line 90, specifically the validation logic in `AssertValidVoteInput()` at lines 377-401.

**Root Cause**: The `AssertValidVoteInput()` function performs several validation checks but omits any verification that the current block time is within the allowed voting period: [2](#0-1) 

The function checks:
- Voting item exists (line 379)
- Option length and validity (lines 380-381)  
- Snapshot number hasn't exceeded total (lines 382-383)
- Delegation requirements (lines 384-398)

However, it **never validates** that `Context.CurrentBlockTime >= votingItem.StartTimestamp && Context.CurrentBlockTime <= votingItem.EndTimestamp`.

The `VotingItem` structure contains these timestamp fields that are set during registration: [3](#0-2) [4](#0-3) 

The only time-related check (line 382-383) validates `CurrentSnapshotNumber <= TotalSnapshotNumber`, but snapshot progression is manually controlled via `TakeSnapshot()` calls by the sponsor, not automatically tied to timestamps. [5](#0-4) 

### Impact Explanation

**Direct Operational Impact**:
- **Premature Voting**: Users can vote before `StartTimestamp`, potentially before the voting terms are finalized or announced, undermining the integrity of the voting process
- **Post-Deadline Voting**: Users can continue voting indefinitely after `EndTimestamp`, invalidating any time-based voting deadlines and allowing manipulation after results should be finalized
- **Vote Result Integrity**: The sponsor cannot rely on the defined time period to determine when voting is complete, as votes can be cast at any time regardless of the configured boundaries

**Who is Affected**:
- Voting sponsors who set specific start/end times expecting temporal enforcement
- All participants relying on fair, time-bound voting processes
- Any governance or decision-making systems depending on VoteContract for time-limited votes

**Severity Justification**: High severity because:
1. It completely bypasses the fundamental temporal constraint of voting activities
2. It's trivially exploitable by any user with voting privileges
3. It undermines the core security model of time-bounded voting
4. No mitigating controls exist to enforce the specified time boundaries

### Likelihood Explanation

**Reachability**: The `Vote()` function is a public method callable by any user who has tokens of the accepted currency. [6](#0-5) 

**Attacker Capabilities**: 
- Any user can call `Vote()` at any time after a voting item is registered
- No special privileges required beyond holding the accepted token
- Attack can be executed in a single transaction

**Execution Practicality**:
1. Wait for a voting item to be registered via `Register()`
2. Call `Vote()` either before `StartTimestamp` or after `EndTimestamp`
3. Vote is accepted and recorded despite being outside the valid time window

**Economic Rationality**: 
- Zero cost beyond normal transaction fees
- High benefit from influencing votes outside intended periods
- Particularly valuable for voting after intended deadline when results might already be considered final

**Detection Constraints**: 
- Votes outside time boundaries are indistinguishable from valid votes in contract state
- No events or checks flag out-of-period voting
- Issue may only be discovered through off-chain monitoring

**Probability**: Very high - the vulnerability is deterministic and requires no special conditions beyond a registered voting item.

### Recommendation

**Code-Level Mitigation**:

Add timestamp validation in `AssertValidVoteInput()` before line 382:

```csharp
Assert(Context.CurrentBlockTime >= votingItem.StartTimestamp, 
    "Voting has not started yet.");
Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
    "Voting has already ended.");
```

**Complete Fix Location**: [7](#0-6) 

Insert the timestamp checks between lines 381 and 382, immediately after option validation and before snapshot number validation.

**Invariant to Enforce**:
- For all votes: `votingItem.StartTimestamp <= Context.CurrentBlockTime <= votingItem.EndTimestamp`

**Regression Test Cases**:
1. Test voting before `StartTimestamp` - should fail with "Voting has not started yet."
2. Test voting after `EndTimestamp` - should fail with "Voting has already ended."
3. Test voting exactly at `StartTimestamp` - should succeed
4. Test voting exactly at `EndTimestamp` - should succeed  
5. Test voting within valid period - should succeed (existing test)

### Proof of Concept

**Initial State**:
1. Vote contract is deployed and initialized
2. Token contract has whitelisted the voting token
3. User has balance of accepted token

**Exploitation Steps**:

**Scenario 1: Voting Before Start**
1. Sponsor calls `Register()` with `StartTimestamp` = current time + 1 day, `EndTimestamp` = current time + 8 days
2. Attacker immediately calls `Vote()` with valid voting item ID and option
3. **Expected**: Transaction should fail with "Voting has not started yet."
4. **Actual**: Vote is recorded successfully despite being before StartTimestamp

**Scenario 2: Voting After End**  
1. Sponsor calls `Register()` with `StartTimestamp` = current time - 8 days, `EndTimestamp` = current time - 1 day
2. Attacker calls `Vote()` with valid voting item ID and option
3. **Expected**: Transaction should fail with "Voting has already ended."
4. **Actual**: Vote is recorded successfully despite being after EndTimestamp

**Success Condition**: 
In both scenarios, the vote transaction succeeds and the voting record is created, the voting result is updated, and tokens are locked (if applicable), all without any timestamp boundary enforcement. [8](#0-7)

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L36-52)
```csharp
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
