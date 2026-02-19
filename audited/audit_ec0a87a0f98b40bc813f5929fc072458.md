### Title
Missing Timestamp Validation in Vote Contract Allows Voting Outside Defined Time Period

### Summary
The Vote contract does not validate that votes are cast within the time period defined by `StartTimestamp` and `EndTimestamp`. While the contract accepts `TimestampHelper.MinValue` (-62135596800L seconds) during registration, the critical issue is that the `Vote` method lacks any timestamp validation, allowing users to vote before the voting period starts or after it ends, completely bypassing time-based access controls.

### Finding Description

The Vote contract's `Register` method only validates that `EndTimestamp > StartTimestamp` [1](#0-0) . This allows `TimestampHelper.MinValue` (-62135596800L seconds) to be used as `StartTimestamp` [2](#0-1) , which is intentionally used by the Election contract for permanent voting [3](#0-2) .

However, the critical vulnerability is in the `Vote` method's validation logic. The `AssertValidVoteInput` method [4](#0-3)  only checks:
- Option validity (line 381)
- Snapshot number limits (line 382)
- Delegated voting permissions (lines 384-388)

It completely omits validation that `Context.CurrentBlockTime` is within the `[StartTimestamp, EndTimestamp]` range. The voting period timestamps are stored [5](#0-4)  but never checked during vote execution [6](#0-5) .

The contract documentation claims: "If StartTimestamp of input value is smaller than current block time, will use current block time as StartTimestamp" [7](#0-6) , but this validation is not implemented in the code.

### Impact Explanation

This vulnerability completely bypasses time-based access control for voting:

1. **Early Voting**: Users can cast votes before `StartTimestamp`, gaining unfair advantage by voting before the intended voting period begins
2. **Late Voting**: Users can cast votes after `EndTimestamp`, manipulating results after the voting period should have closed
3. **Governance Manipulation**: Any voting event that relies on time-bounded voting periods (proposals, governance decisions, time-limited polls) can be compromised
4. **Trust Violation**: The `StartTimestamp` and `EndTimestamp` fields become meaningless for access control, violating the contract's intended design

While the Election contract's use of `MinValue/MaxValue` for permanent voting is intentional, the Vote contract is a generic contract used by other contracts. The absence of timestamp validation affects ANY voting event that attempts to enforce time-based restrictions.

### Likelihood Explanation

**Exploitability: HIGH**
- **Reachable Entry Point**: The `Vote` method is a public entry point accessible to all users [8](#0-7) 
- **No Preconditions**: Any user can call `Vote` at any time without special privileges
- **Trivial Execution**: Simply call `Vote` before `StartTimestamp` or after `EndTimestamp`
- **Zero Cost**: No additional resources or complex setup required
- **Undetectable**: No logging or events indicate that voting occurred outside the intended period

The validation gap is confirmed by examining the complete `AssertValidVoteInput` method which performs no timestamp checks whatsoever.

### Recommendation

Add timestamp validation in the `AssertValidVoteInput` method:

```csharp
private VotingItem AssertValidVoteInput(VoteInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    
    // Add timestamp validation
    Assert(Context.CurrentBlockTime >= votingItem.StartTimestamp, 
        "Voting has not started yet.");
    Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
        "Voting has ended.");
    
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    // ... rest of existing validations
}
```

**Test Cases to Add:**
1. Test voting before `StartTimestamp` - should fail with "Voting has not started yet"
2. Test voting after `EndTimestamp` - should fail with "Voting has ended"
3. Test voting within valid period - should succeed
4. Test that Election contract with `MinValue/MaxValue` continues to work (as current time will always be within that range)

### Proof of Concept

**Initial State:**
1. Register a voting item with `StartTimestamp = CurrentBlockTime + 1 day` and `EndTimestamp = CurrentBlockTime + 7 days`
2. Voting item is created successfully [9](#0-8) 

**Attack Steps:**
1. Immediately after registration (before `StartTimestamp`), call `Vote` method with valid parameters
2. The `Vote` method calls `AssertValidVoteInput` [10](#0-9) 
3. `AssertValidVoteInput` checks snapshot numbers but NOT timestamps [11](#0-10) 
4. Vote is recorded successfully even though current time < `StartTimestamp` [12](#0-11) 

**Expected Result:** Vote should fail with "Voting has not started yet"

**Actual Result:** Vote succeeds, bypassing time-based access control

**Success Condition:** The voting record exists in state with `VoteTimestamp < VotingItem.StartTimestamp`, proving the timestamp validation is missing

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L45-47)
```csharp
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L54-54)
```csharp
        State.VotingItems[votingItemId] = votingItem;
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

**File:** contract/AElf.Contracts.Election/TimestampHelper.cs (L10-10)
```csharp
    public static Timestamp MinValue => new() { Nanos = 0, Seconds = -62135596800L };
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L65-65)
```csharp
            StartTimestamp = TimestampHelper.MinValue,
```

**File:** contract/AElf.Contracts.Vote/README.md (L45-46)
```markdown
- If `StartTimestamp` of input value is smaller than current block time, will use current block time as `StartTimestamp`
  .
```
