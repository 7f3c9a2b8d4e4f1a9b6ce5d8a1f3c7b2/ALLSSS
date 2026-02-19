### Title
Unbounded Data Return in Vote Contract View Methods Enables Denial of Service

### Summary
The Vote contract's `GetVotingRecords` and `GetVotedItems` view methods lack pagination controls and size limits, allowing queries to return arbitrarily large data structures. This can cause node memory exhaustion, network bandwidth saturation, and client crashes when processing responses. Unlike the Election contract which implements a maximum page size of 20 items, the Vote contract has no such protections.

### Finding Description

**Vulnerability 1: GetVotingRecords - Unbounded Batch Query**

The `GetVotingRecords` method accepts an input containing a repeated list of vote IDs with no size limit: [1](#0-0) 

The input structure definition shows no restrictions on the number of IDs: [2](#0-1) 

The method iterates through all provided IDs and returns corresponding VotingRecord objects, each containing 9 fields including addresses, timestamps, amounts, and strings. An attacker can submit thousands of valid vote IDs in a single query, forcing the node to serialize and transmit massive response data.

**Vulnerability 2: GetVotedItems - Unbounded Data Accumulation**

The `GetVotedItems` method returns the complete voting history for a user: [3](#0-2) 

The returned `VotedItems` structure contains a map with unbounded lists: [4](#0-3) 

Each time a user votes, the vote ID is added to the `ActiveVotes` list: [5](#0-4) 

When votes are withdrawn, they are moved to `WithdrawnVotes`: [6](#0-5) 

**Critical Issue**: There is no cleanup mechanism. Withdrawn votes remain in the `WithdrawnVotes` list indefinitely, and there are no limits on how many voting activities a user can participate in or how many votes they can cast.

**Missing Protection Pattern**: The Election contract demonstrates the correct approach with pagination and a hardcoded maximum of 20 items per query: [7](#0-6) 

The Vote contract lacks any such limits: [8](#0-7) 

### Impact Explanation

**Resource Exhaustion**: Nodes attempting to process these queries face:
- **Memory exhaustion** during response serialization (10,000 VotingRecord objects could exceed hundreds of MB)
- **CPU saturation** from serialization overhead
- **Network bandwidth consumption** transmitting oversized responses

**Service Disruption**: 
- RPC nodes become unresponsive to legitimate queries
- Blockchain explorers and dApps querying vote data experience timeouts and crashes
- Users cannot retrieve their voting history when data accumulates

**Attack Cost**: View methods typically have no gas cost or minimal fees, making repeated exploitation economically viable for attackers.

**Quantified Scenario**: A user participating in 100 voting items with 100 votes each (50 active, 50 withdrawn) accumulates 10,000 Hash values (~320KB just for hashes) plus map overhead, easily exceeding reasonable response sizes. Similarly, querying 10,000 VotingRecord IDs could generate multi-megabyte responses.

**Severity**: Medium - While this doesn't directly compromise funds or authorization, it creates a practical DoS vector against voting infrastructure that degraded availability of governance functionality.

### Likelihood Explanation

**Attack Complexity**: Low
- `GetVotingRecords`: Attacker only needs to collect valid vote IDs (observable from events) and query them in bulk
- `GetVotedItems`: Attacker creates their own voting items, casts many votes, and queries their accumulated data

**Preconditions**: Minimal
- No special permissions required (view methods are public)
- Normal voting operations naturally create the exploitable state
- Vote IDs are discoverable through blockchain events

**Economic Feasibility**: High
- View method calls typically free or extremely cheap
- Voting and withdrawal operations have costs, but data accumulates legitimately over protocol lifetime
- Single query can cause disproportionate resource consumption

**Detection Difficulty**: Moderate
- Large query responses may trigger monitoring alerts
- But legitimate users with extensive voting history create same pattern
- Distinguishing malicious from legitimate queries challenging

### Recommendation

**Immediate Mitigations**:

1. **Add pagination to GetVotingRecords**:
```
message GetVotingRecordsInput {
    repeated aelf.Hash ids = 1;
    int32 start = 2;  // Offset
    int32 length = 3; // Page size
}
```

Enforce maximum page size (e.g., 20 items) following the Election contract pattern: [9](#0-8) 

2. **Add pagination to GetVotedItems**:
```
message GetVotedItemsInput {
    aelf.Address voter = 1;
    int32 start = 2;
    int32 length = 3;
    string voting_item_id_filter = 4; // Optional: query specific voting item
}
```

Return paginated subsets of the voting history with maximum limits.

3. **Implement data archival**: Consider removing withdrawn votes older than a configurable retention period, or separating historical data into archive queries with stricter limits.

4. **Add response size monitoring**: Implement size checks before serialization and return error if response would exceed safe threshold (e.g., 1MB).

**Test Cases**:
- Verify pagination correctly limits returned items to maximum page size
- Test that oversized unpaginated queries are rejected
- Confirm edge cases (start beyond data size, length=0, etc.)
- Load test with realistic data volumes (1000+ votes per user)

### Proof of Concept

**Scenario 1: GetVotingRecords DoS**

Initial State:
- Multiple users have cast votes, creating 10,000+ voting records
- Vote IDs are collected from Voted events

Attack Steps:
1. Attacker calls `GetVotingRecords` with input containing 10,000 vote IDs
2. Contract iterates through all IDs: `votingRecords.Records.AddRange(input.Ids.Select(id => State.VotingRecords[id]))`
3. Each VotingRecord serialized (9 fields × 10,000 = 90,000+ field serializations)
4. Response payload exceeds multiple megabytes

Expected Result: Query returns reasonable subset with pagination
Actual Result: Node attempts full serialization, consuming excessive memory/CPU, potentially timing out or crashing

**Scenario 2: GetVotedItems Accumulation DoS**

Initial State:
- Attacker controls an address

Attack Steps:
1. Attacker calls `Register` to create 100 voting items (costs tokens but one-time)
2. For each voting item, attacker calls `Vote` 50 times (accumulates in ActiveVotes)
3. Attacker calls `Withdraw` for each vote (moves to WithdrawnVotes, never removed)
4. Repeat steps 2-3 multiple times
5. Attacker (or anyone) calls `GetVotedItems` for the attacker's address

Expected Result: Query returns paginated voting history
Actual Result: Returns complete VotedItems map with 100 keys, each containing lists of 100+ Hash values, totaling 10,000+ hashes in single response, causing resource exhaustion

Success Condition: Response size monitoring shows multi-megabyte payload, node resource utilization spikes, query latency exceeds normal thresholds (e.g., >5 seconds for what should be instant).

### Citations

**File:** contract/AElf.Contracts.Vote/ViewMethods.cs (L8-13)
```csharp
    public override VotingRecords GetVotingRecords(GetVotingRecordsInput input)
    {
        var votingRecords = new VotingRecords();
        votingRecords.Records.AddRange(input.Ids.Select(id => State.VotingRecords[id]));
        return votingRecords;
    }
```

**File:** contract/AElf.Contracts.Vote/ViewMethods.cs (L15-18)
```csharp
    public override VotedItems GetVotedItems(Address input)
    {
        return State.VotedItemsMap[input] ?? new VotedItems();
    }
```

**File:** protobuf/vote_contract.proto (L235-245)
```text
message VotedItems {
    // The voted ids.
    map<string, VotedIds> voted_item_vote_ids = 1;
}

message VotedIds {
    // The active vote ids.
    repeated aelf.Hash active_votes = 1;
    // The withdrawn vote ids.
    repeated aelf.Hash withdrawn_votes = 2;
}
```

**File:** protobuf/vote_contract.proto (L259-262)
```text
message GetVotingRecordsInput {
    // The vote ids.
    repeated aelf.Hash ids = 1;
}
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L146-161)
```csharp
    private void UpdateVotedItems(Hash voteId, Address voter, VotingItem votingItem)
    {
        var votedItems = State.VotedItemsMap[voter] ?? new VotedItems();
        var voterItemIndex = votingItem.VotingItemId.ToHex();
        if (votedItems.VotedItemVoteIds.ContainsKey(voterItemIndex))
            votedItems.VotedItemVoteIds[voterItemIndex].ActiveVotes.Add(voteId);
        else
            votedItems.VotedItemVoteIds[voterItemIndex] =
                new VotedIds
                {
                    ActiveVotes = { voteId }
                };

        votedItems.VotedItemVoteIds[voterItemIndex].WithdrawnVotes.Remove(voteId);
        State.VotedItemsMap[voter] = votedItems;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L209-212)
```csharp
        var votedItems = State.VotedItemsMap[votingRecord.Voter];
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].ActiveVotes.Remove(input.VoteId);
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].WithdrawnVotes.Add(input.VoteId);
        State.VotedItemsMap[votingRecord.Voter] = votedItems;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L240-258)
```csharp
    public override GetPageableCandidateInformationOutput GetPageableCandidateInformation(PageInformation input)
    {
        var output = new GetPageableCandidateInformationOutput();
        var candidates = State.Candidates.Value;

        var count = candidates.Value.Count;
        if (count <= input.Start) return output;

        var length = Math.Min(Math.Min(input.Length, 20), candidates.Value.Count.Sub(input.Start));
        foreach (var candidate in candidates.Value.Skip(input.Start).Take(length))
            output.Value.Add(new CandidateDetail
            {
                CandidateInformation = State.CandidateInformationMap[candidate.ToHex()],
                ObtainedVotesAmount = GetCandidateVote(new StringValue { Value = candidate.ToHex() })
                    .ObtainedActiveVotedVotesAmount
            });

        return output;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L1-7)
```csharp
namespace AElf.Contracts.Vote;

public static class VoteContractConstants
{
    public const int MaximumOptionsCount = 64;
    public const int OptionLengthLimit = 1024;
}
```
