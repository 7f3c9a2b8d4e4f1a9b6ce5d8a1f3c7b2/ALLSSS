# Audit Report

## Title
Vote Count Corruption Due to Incorrect State Carryover in TakeSnapshot()

## Summary
The `TakeSnapshot()` function in the Vote contract incorrectly carries over `VotersCount` and `VotesAmount` from the previous snapshot when creating a new snapshot, while correctly resetting the `Results` map to empty. This causes permanent data corruption where aggregate vote counts accumulate across snapshots instead of representing per-snapshot activity as documented.

## Finding Description

The Vote contract maintains voting results across multiple snapshots for each voting item. When a new snapshot is created via `TakeSnapshot()`, the function initializes a new `VotingResult` object by copying the previous snapshot's `VotersCount` and `VotesAmount` values: [1](#0-0) 

This carryover behavior contrasts with the first snapshot initialization during `Register()`, where all counts start at their default zero values: [2](#0-1) 

The critical issue is that while the `Results` map (option → vote amounts) is not initialized and therefore starts empty in the new snapshot, the `VotersCount` and `VotesAmount` fields are explicitly set to the previous snapshot's values. When new votes are subsequently cast, the `UpdateVotingResult()` function increments these already-inflated counts: [3](#0-2) 

This creates a fundamental state inconsistency: the `Results` map correctly shows only votes from the current snapshot, while `VotersCount` and `VotesAmount` incorrectly accumulate across all previous snapshots plus the current one.

The protobuf documentation explicitly states that `votes_amount` represents "Total votes received during the process of this snapshot," confirming that these values should be per-snapshot, not cumulative: [4](#0-3) 

The existing test suite validates this buggy behavior. After 3 votes in snapshot 1 and 4 votes in snapshot 2, the test expects and confirms `VotersCount=7` instead of the correct value of 4 for snapshot 2 alone: [5](#0-4) 

## Impact Explanation

This vulnerability causes permanent data corruption in the Vote contract's core functionality:

**Data Integrity Breach:** Voting results stored on-chain are permanently corrupted with inflated counts that misrepresent actual voting activity within each snapshot. The `VotersCount` and `VotesAmount` fields become meaningless for snapshots beyond the first one.

**API Contract Violation:** The protobuf documentation explicitly specifies that counts represent activity "during the process of this snapshot," but the implementation accumulates values across snapshots, violating the documented interface.

**Inconsistent State:** The `Results` map correctly shows per-snapshot data, while the aggregate counts show cumulative data, creating an internally inconsistent data structure that cannot be reconciled.

**External System Impact:** Any off-chain systems, analytics tools, or governance interfaces that query these values via `GetVotingResult()` will receive false data and make incorrect interpretations about voting participation.

**Concrete Example:** 
- Snapshot 1: 3 voters cast 450 total votes → VotersCount=3, VotesAmount=450
- TakeSnapshot() → Snapshot 2 starts with VotersCount=3, VotesAmount=450 
- Snapshot 2: 4 new votes for 400 tokens → Final shows VotersCount=7, VotesAmount=850
- Reality: Only 4 votes for 400 tokens occurred in snapshot 2
- Reported: 7 votes for 850 tokens (175% and 212% inflation respectively)

## Likelihood Explanation

This vulnerability triggers with 100% certainty in every multi-snapshot voting scenario:

**Entry Point:** The `TakeSnapshot()` function is a public RPC method designed to be called by the voting item sponsor as part of normal operations: [6](#0-5) 

**Preconditions:** 
- A voting item registered with `TotalSnapshotNumber > 1`
- At least one vote cast in any previous snapshot
- Sponsor calls `TakeSnapshot()` to advance to the next snapshot (intended behavior)

**Deterministic Trigger:** No special privileges, complex setup, or attack-specific inputs are required. The bug occurs during the legitimate, intended use of the multi-snapshot voting feature, which is a core functionality of the Vote contract.

**Detection:** The corrupted state is permanent, publicly visible via `GetVotingResult()`, and can be trivially verified by comparing snapshot counts.

## Recommendation

The `TakeSnapshot()` function should initialize the new `VotingResult` with zero counts, matching the behavior of the first snapshot initialization in `Register()`:

```csharp
// Fix: Initialize next voting result with zero counts
var currentVotingGoingHash = GetVotingResultHash(input.VotingItemId, nextSnapshotNumber);
State.VotingResults[currentVotingGoingHash] = new VotingResult
{
    VotingItemId = input.VotingItemId,
    SnapshotNumber = nextSnapshotNumber,
    SnapshotStartTimestamp = Context.CurrentBlockTime
    // VotersCount and VotesAmount will default to 0
    // Results will default to empty map
};
```

Remove lines 269-270 that copy the previous snapshot's counts. This ensures all vote-related fields (Results, VotersCount, VotesAmount) consistently represent per-snapshot activity.

## Proof of Concept

```csharp
[Fact]
public async Task TakeSnapshot_Corrupts_Vote_Counts()
{
    // Register voting item with 2 snapshots
    var votingItem = await RegisterVotingItemAsync(100, 3, true, DefaultSender, 2);
    
    // Snapshot 1: Cast 3 votes for 450 total
    await Vote(Accounts[1].KeyPair, votingItem.VotingItemId, votingItem.Options[0], 100);
    await Vote(Accounts[2].KeyPair, votingItem.VotingItemId, votingItem.Options[0], 150);
    await Vote(Accounts[3].KeyPair, votingItem.VotingItemId, votingItem.Options[1], 200);
    
    var snapshot1Result = await GetVotingResult(votingItem.VotingItemId, 1);
    snapshot1Result.VotersCount.ShouldBe(3);
    snapshot1Result.VotesAmount.ShouldBe(450);
    
    // Advance to snapshot 2
    await TakeSnapshot(votingItem.VotingItemId, 1);
    
    // Snapshot 2: Cast 2 votes for 300 total
    await Vote(Accounts[1].KeyPair, votingItem.VotingItemId, votingItem.Options[0], 100);
    await Vote(Accounts[2].KeyPair, votingItem.VotingItemId, votingItem.Options[1], 200);
    
    var snapshot2Result = await GetVotingResult(votingItem.VotingItemId, 2);
    
    // BUG: Counts are corrupted - should be 2 votes for 300, but shows 5 for 750
    snapshot2Result.VotersCount.ShouldBe(5); // 3 (carried over) + 2 (new) = 5 instead of 2
    snapshot2Result.VotesAmount.ShouldBe(750); // 450 (carried over) + 300 (new) = 750 instead of 300
    
    // Results map correctly shows only snapshot 2 votes
    snapshot2Result.Results[votingItem.Options[0]].ShouldBe(100);
    snapshot2Result.Results[votingItem.Options[1]].ShouldBe(200);
    // But aggregate counts are corrupted - INCONSISTENT STATE
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L58-63)
```csharp
        State.VotingResults[votingResultHash] = new VotingResult
        {
            VotingItemId = votingItemId,
            SnapshotNumber = 1,
            SnapshotStartTimestamp = input.StartTimestamp
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L241-245)
```csharp
    public override Empty TakeSnapshot(TakeSnapshotInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);

        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can take snapshot.");
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

**File:** protobuf/vote_contract.proto (L162-177)
```text
message VotingResult {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The voting result, option -> amount of votes,
    map<string, int64> results = 2;
    // The snapshot number.
    int64 snapshot_number = 3;
    // The total number of voters.
    int64 voters_count = 4;
    // The start time of this snapshot.
    google.protobuf.Timestamp snapshot_start_timestamp = 5;
    // The end time of this snapshot.
    google.protobuf.Timestamp snapshot_end_timestamp = 6;
    // Total votes received during the process of this snapshot.
    int64 votes_amount = 7;
}
```

**File:** test/AElf.Contracts.Vote.Tests/Full/VoteForBestLanguageTests.cs (L93-98)
```csharp
            var votingResult = await GetVotingResult(registerItem.VotingItemId, 2);
            votingResult.VotersCount.ShouldBe(7);
            votingResult.Results.Count.ShouldBe(3);
            votingResult.Results[options[0]].ShouldBe(100);
            votingResult.Results[options[1]].ShouldBe(100);
            votingResult.Results[options[2]].ShouldBe(200);
```
