### Title
Sponsor Can Extend Voting Period Indefinitely Beyond Declared EndTimestamp

### Summary
The Vote contract does not enforce the declared `EndTimestamp` when accepting votes or taking snapshots. This allows the sponsor to delay calling `TakeSnapshot()` indefinitely, keeping the voting period open well past the declared end time and enabling manipulation of voting outcomes through strategic timing.

### Finding Description

**Root Cause:**
The Vote contract lacks enforcement of the `EndTimestamp` field during voting operations. While `EndTimestamp` is validated during registration to ensure it's greater than `StartTimestamp`, [1](#0-0)  this timestamp is never checked when users vote or when the sponsor takes snapshots.

**Missing Validation in Vote Function:**
The `AssertValidVoteInput()` function only validates that the current snapshot number hasn't exceeded the total: [2](#0-1) 

There is no check comparing `Context.CurrentBlockTime` against `votingItem.EndTimestamp`.

**Missing Validation in TakeSnapshot Function:**
When the sponsor calls `TakeSnapshot()`, the function sets `SnapshotEndTimestamp` to the current block time without any validation: [3](#0-2) 

The sponsor is only required to be the voting item owner: [4](#0-3) 

**Exploitation Path:**
1. Sponsor registers a voting item with declared `StartTimestamp` and `EndTimestamp` [5](#0-4) 
2. Users vote believing the vote ends at `EndTimestamp`
3. The declared `EndTimestamp` passes
4. Sponsor observes voting trends and delays calling `TakeSnapshot()`
5. Users continue voting past the declared deadline because only snapshot number is checked
6. Sponsor strategically times `TakeSnapshot()` when results are favorable

### Impact Explanation

**Governance Manipulation:**
Voters participate under the assumption that voting ends at a specific, declared time. By extending the voting period arbitrarily, the sponsor can:
- Observe voting trends and only close the snapshot when outcomes are favorable
- Coordinate with aligned voters to cast votes after the "official" deadline when opposition has stopped participating
- Repeatedly extend deadlines to pressure or wait out opposition voters

**Trust Violation:**
The `EndTimestamp` is explicitly defined in the protocol buffer definition as "The end time of the voting" [6](#0-5)  and stored in the voting item [7](#0-6) . Users rely on this declared deadline for their participation decisions. Failure to enforce it undermines the entire voting system's credibility.

**Severity Justification:**
This is a Medium severity issue because:
- It enables manipulation of governance decisions
- The sponsor role, while trusted, can be compromised or act maliciously
- It affects all voting activities in the contract
- The impact is limited to governance outcomes rather than direct fund theft

### Likelihood Explanation

**Attacker Capabilities:**
The attacker is the voting item sponsor, who has legitimate authority to call `TakeSnapshot()`. This is a realistic threat model because:
- Sponsors may have conflicts of interest in voting outcomes
- Sponsor accounts can be compromised
- Even well-intentioned sponsors might face pressure to manipulate results

**Attack Complexity:**
The attack is trivially simple - the sponsor merely needs to **not call** `TakeSnapshot()` at the expected time. No sophisticated techniques or external resources are required.

**Feasibility Conditions:**
- Voting item must be registered (normal operation)
- Current snapshot number must not exceed total (normal condition)
- No external dependencies or timing requirements

**Detection Constraints:**
The manipulation is difficult to detect because:
- The contract provides no way to query if a vote has passed its declared `EndTimestamp`
- The sponsor's delay appears as normal operational timing
- There are no events or logs indicating timeline violations

### Recommendation

**Code-Level Mitigation:**
Add timestamp validation in the `AssertValidVoteInput()` function:

```csharp
// In AssertValidVoteInput(), add after line 383:
Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
    "Voting period has ended.");
```

**Additional Protection:**
Add validation in `TakeSnapshot()` to prevent snapshots from being taken too late:

```csharp
// In TakeSnapshot(), add after line 248:
Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp.AddDays(MaxDelayDays),
    "Snapshot must be taken within reasonable time after voting ends.");
```

**Invariant Check:**
The following invariant should always hold during voting operations:
- `Context.CurrentBlockTime <= votingItem.EndTimestamp` when accepting new votes

**Test Cases:**
1. Test that voting is rejected after `EndTimestamp` has passed
2. Test that `TakeSnapshot()` cannot be called excessively late
3. Test edge case where `EndTimestamp` equals `Context.CurrentBlockTime`

### Proof of Concept

**Initial State:**
1. Sponsor registers voting item with `StartTimestamp = T0` and `EndTimestamp = T0 + 10 days`
2. Normal users have `TotalSnapshotNumber = 1` voting item

**Exploitation Steps:**

**Transaction 1 - Register (T0):**
```
Sponsor calls Register() with:
- StartTimestamp: Current time (T0)
- EndTimestamp: T0 + 10 days
- TotalSnapshotNumber: 1
Result: Voting item created, CurrentSnapshotNumber = 1
```

**Transaction 2 - Vote (T0 + 5 days):**
```
User A votes for Option 1 with 1000 tokens
Result: Vote accepted, VotesAmount increases
```

**Transaction 3 - Delayed Vote (T0 + 15 days, 5 days AFTER EndTimestamp):**
```
User B votes for Option 2 with 1000 tokens
Expected Result: Should FAIL with "Voting period has ended"
Actual Result: Vote SUCCEEDS because only snapshot number is checked
```

**Transaction 4 - Strategic Snapshot (T0 + 20 days):**
```
Sponsor calls TakeSnapshot() after observing favorable results
Result: Snapshot closed at T0 + 20 days, 10 days after declared end time
```

**Success Condition:**
The vulnerability is confirmed if User B's vote at T0 + 15 days (after `EndTimestamp`) is accepted and counted in the voting results.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L46-47)
```csharp
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L245-245)
```csharp
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can take snapshot.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L253-253)
```csharp
        previousVotingResult.SnapshotEndTimestamp = Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L361-361)
```csharp
        Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L382-383)
```csharp
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
```

**File:** protobuf/vote_contract.proto (L90-91)
```text
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 2;
```

**File:** protobuf/vote_contract.proto (L123-124)
```text
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 9;
```
