### Title
Vote Contract Accounting Inconsistency: VotesAmount Accumulates Across Snapshots While Results Dictionary Does Not

### Summary
The `TakeSnapshot` function copies `VotesAmount` from the previous snapshot but does not copy the `Results` dictionary, causing an accounting discrepancy where `VotesAmount` accumulates across all snapshots while `Results` only reflects votes in the current snapshot. The `GetVotingResult()` view method exposes this inconsistent data without validation, violating the invariant that `VotesAmount` should equal the sum of `Results` values.

### Finding Description

**Root Cause:**

When `TakeSnapshot` is called in the Vote contract, it creates a new `VotingResult` for the next snapshot and copies `VotersCount` and `VotesAmount` from the previous snapshot, but initializes an empty `Results` dictionary: [1](#0-0) 

The `Results` map (option → vote amounts) is not copied or accumulated, starting fresh for each snapshot.

**Accounting Mechanism:**

When votes are cast, `UpdateVotingResult` increments both `Results[option]` and `VotesAmount` by the same amount: [2](#0-1) 

When votes are withdrawn, both values are decremented: [3](#0-2) 

Within a single snapshot, `VotesAmount` equals `sum(Results.values)`. However, after `TakeSnapshot` is called, the new snapshot inherits the cumulative `VotesAmount` but starts with an empty `Results` dictionary.

**Exposure Without Validation:**

The `GetVotingResult()` method simply retrieves and returns the `VotingResult` from state without any validation: [4](#0-3) 

**Semantic Inconsistency:**

The protobuf documentation describes `votes_amount` as "Total votes received during the process of this snapshot": [5](#0-4) 

This suggests per-snapshot tracking, but the implementation makes it cumulative across all snapshots, contradicting the documented semantics.

### Impact Explanation

**Data Integrity Violation:**
The exposed data violates the expected invariant where `VotesAmount == sum(Results.values)`. After any snapshot transition with subsequent voting, these values diverge permanently.

**Affected Parties:**
1. **External Consumers**: dApps, analytics tools, and monitoring systems reading `VotingResult` data will receive inconsistent information
2. **Election Contract**: While it uses `GetLatestVotingResult().VotesAmount` for informational purposes, critical election logic relies on `CandidateVotes.ObtainedActiveVotedVotesAmount` rather than this field: [6](#0-5) 

3. **Governance Transparency**: Users viewing vote totals will see inflated `VotesAmount` values that don't match the actual option tallies

**Concrete Example:**
- Snapshot 1: 1000 votes for Option A → `Results[A]=1000, VotesAmount=1000` ✓
- TakeSnapshot(1) → Snapshot 2 with `VotesAmount=1000, Results={}` 
- Snapshot 2: 500 votes for Option B → `Results[B]=500, VotesAmount=1500` 
- **Discrepancy**: `sum(Results.values) = 500` but `VotesAmount = 1500` ✗

**Severity Limitation:**
While this is a clear data integrity issue, it does not result in:
- Direct fund loss or theft
- Unauthorized governance actions
- Consensus mechanism failures
- Denial of service

The Election contract's critical victory determination logic does not depend on this field, limiting practical exploitation.

### Likelihood Explanation

**Guaranteed Occurrence:**
This issue occurs deterministically in normal protocol operation, not requiring any attack. Every term transition in the Election contract triggers `TakeSnapshot`: [7](#0-6) 

**Preconditions:**
1. A voting item exists with `total_snapshot_number > 1`
2. `TakeSnapshot` is called to transition to a new snapshot
3. New votes are cast in the subsequent snapshot

**Detection:**
The inconsistency is immediately observable by comparing `VotesAmount` with `sum(Results.values)` in any snapshot after the first.

**No Attacker Required:**
This is a logic bug in the accounting mechanism, not an exploitable vulnerability requiring malicious action.

### Recommendation

**Code-Level Mitigation:**

Option 1: Reset `VotesAmount` per snapshot (aligns with documentation):
```csharp
State.VotingResults[currentVotingGoingHash] = new VotingResult
{
    VotingItemId = input.VotingItemId,
    SnapshotNumber = nextSnapshotNumber,
    SnapshotStartTimestamp = Context.CurrentBlockTime,
    VotersCount = previousVotingResult.VotersCount,
    VotesAmount = 0  // Reset instead of copying
};
```

Option 2: Copy `Results` to make it cumulative (aligns with current behavior):
```csharp
var newResult = new VotingResult
{
    VotingItemId = input.VotingItemId,
    SnapshotNumber = nextSnapshotNumber,
    SnapshotStartTimestamp = Context.CurrentBlockTime,
    VotersCount = previousVotingResult.VotersCount,
    VotesAmount = previousVotingResult.VotesAmount
};
newResult.Results.Add(previousVotingResult.Results);  // Copy results
State.VotingResults[currentVotingGoingHash] = newResult;
```

**Invariant Check:**
Add validation in `GetVotingResult()`:
```csharp
var result = State.VotingResults[votingResultHash];
var resultsSum = result.Results.Values.Sum();
Assert(result.VotesAmount == resultsSum, 
    $"Accounting error: VotesAmount {result.VotesAmount} != sum(Results) {resultsSum}");
return result;
```

**Test Cases:**
Add tests verifying the invariant across multiple snapshots with voting in each period.

### Proof of Concept

**Initial State:**
- Register voting item with `total_snapshot_number = 3`
- Snapshot 1 is automatically created with `VotesAmount = 0, Results = {}`

**Transaction Sequence:**
1. User A votes 1000 for "Option_A" in Snapshot 1
   - `Results["Option_A"] = 1000`
   - `VotesAmount = 1000`
   - ✓ Invariant holds: `1000 == 1000`

2. Call `TakeSnapshot(1)` to transition to Snapshot 2
   - New snapshot created with `VotesAmount = 1000, Results = {}`

3. User B votes 500 for "Option_B" in Snapshot 2
   - `Results["Option_B"] = 500`
   - `VotesAmount = 1500`
   - ✗ **Invariant violated**: `sum(Results) = 500` but `VotesAmount = 1500`

4. Call `GetVotingResult(snapshot_number=2)`
   - Returns: `VotingResult { Results: {"Option_B": 500}, VotesAmount: 1500 }`
   - **Exposed inconsistency**: The sum of Results (500) does not equal VotesAmount (1500)

**Expected vs Actual:**
- Expected: Either both cumulative or both per-snapshot
- Actual: `VotesAmount` is cumulative, `Results` is per-snapshot

**Success Condition:**
The discrepancy is observable in the returned `VotingResult` and can be verified by any caller of `GetVotingResult()` or `GetLatestVotingResult()`.

### Notes

While this is a valid data integrity issue that violates accounting consistency, its practical security impact is limited because:
1. The Election contract's critical logic (miner selection) uses `CandidateVotes.ObtainedActiveVotedVotesAmount`, not `VotingResult.VotesAmount`
2. No financial loss or unauthorized access results from this inconsistency
3. The issue affects data transparency rather than protocol security

This should be classified as a **Medium severity data integrity bug** rather than a High severity security vulnerability, despite the accounting error being real and reproducible.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-221)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L264-271)
```csharp
        State.VotingResults[currentVotingGoingHash] = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = nextSnapshotNumber,
            SnapshotStartTimestamp = Context.CurrentBlockTime,
            VotersCount = previousVotingResult.VotersCount,
            VotesAmount = previousVotingResult.VotesAmount
        };
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

**File:** protobuf/vote_contract.proto (L175-176)
```text
    // Total votes received during the process of this snapshot.
    int64 votes_amount = 7;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L232-238)
```csharp
    public override Int64Value GetVotesAmount(Empty input)
    {
        return new Int64Value
        {
            Value = State.VoteContract.GetLatestVotingResult.Call(State.MinerElectionVotingItemId.Value).VotesAmount
        };
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L422-426)
```csharp
        State.VoteContract.TakeSnapshot.Send(new TakeSnapshotInput
        {
            SnapshotNumber = input.TermNumber,
            VotingItemId = State.MinerElectionVotingItemId.Value
        });
```
