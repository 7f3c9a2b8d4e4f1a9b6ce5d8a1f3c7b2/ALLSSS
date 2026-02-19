### Title
Vote ID Reuse in Delegated Voting Enables Historical Record Manipulation and Audit Trail Corruption

### Summary
In delegated voting scenarios (IsLockToken = false), the Sponsor can reuse a previously withdrawn vote ID when casting a new vote, causing the original VotingRecord to be overwritten and the vote ID to be removed from the WithdrawnVotes list. This corrupts the historical audit trail and makes it impossible to retrieve original voting records, affecting governance transparency and compliance.

### Finding Description

The vulnerability exists in the `UpdateVotedItems()` and `Vote()` functions: [1](#0-0) 

At this line, the `VotingRecord` is unconditionally stored, overwriting any existing record with the same vote ID without validation. [2](#0-1) 

In `UpdateVotedItems()`, at line 159, the vote ID is removed from the `WithdrawnVotes` list when a new vote is cast, even if this vote ID was previously withdrawn.

**Root Cause**: The `Vote()` function lacks validation to check if a vote ID already exists in state. For delegated voting, the Sponsor provides the vote ID in the input: [3](#0-2) 

The Sponsor can intentionally or accidentally reuse a vote ID that was previously withdrawn.

**Why Protections Fail**: The `AssertValidVoteInput()` function validates voting item existence, options, and snapshot numbers, but does not check for vote ID uniqueness or existing records: [4](#0-3) 

For non-delegated voting (IsLockToken = true), vote IDs are generated using `Context.GenerateId()` which includes the transaction ID: [5](#0-4) 

This makes collisions impossible for non-delegated voting. However, for delegated voting, the Sponsor has full control over vote ID selection.

### Impact Explanation

**Data Integrity Corruption**:
- Original `VotingRecord` data is permanently lost and cannot be recovered
- The `WithdrawnVotes` list becomes unreliable for audit purposes
- Historical voting behavior cannot be accurately tracked

**Affected Parties**:
- Election contract's view methods `GetElectorVoteWithAllRecords()` and `GetCandidateVoteWithAllRecords()` rely on `WithdrawnVotes` to display complete voting history: [6](#0-5) [7](#0-6) 

These view methods would return incorrect or incomplete historical data.

**Severity Justification**: MEDIUM
- No direct financial loss (vote tallies remain mathematically correct due to proper addition/subtraction in voting results)
- However, audit trail corruption is a serious governance issue
- Violates data integrity invariants critical for transparent governance
- Can be used to hide evidence of previous voting decisions

### Likelihood Explanation

**Attacker Capabilities**: 
- Requires Sponsor role in a delegated voting scenario
- Sponsor must have created a voting item with `IsLockToken = false`
- Sponsor can provide arbitrary vote IDs when calling `Vote()` [8](#0-7) 

**Attack Complexity**: LOW
- Single transaction calling `Vote()` with a previously used vote ID
- No complex setup or timing requirements
- Easily reproducible

**Feasibility Conditions**:
- Delegated voting is a documented feature used by the Election contract
- The Sponsor role is typically a governance contract or authorized entity
- While Sponsors are generally trusted, lack of validation creates risk of accidental or intentional misuse

**Detection Constraints**:
- The `Voted` event would be emitted, but observers cannot detect that a previous record was overwritten
- No on-chain mechanism to prevent or detect this manipulation

### Recommendation

**Immediate Fix**: Add validation in `Vote()` function to prevent vote ID reuse:

```csharp
// In Vote() function, before line 117
var existingRecord = State.VotingRecords[input.VoteId];
Assert(existingRecord == null, "Vote ID already exists. Cannot reuse vote IDs.");
```

**Additional Safeguards**:
1. For delegated voting, enforce unique vote ID generation similar to non-delegated voting:
   - Generate vote IDs deterministically using voter address + voting item ID + nonce
   - Remove vote ID from input parameters for delegated voting

2. Add invariant check in `UpdateVotedItems()`:
   - Verify that a vote ID exists in either ActiveVotes or WithdrawnVotes before removal
   - Log warning if attempting to remove non-existent vote ID

3. Add state validation:
   - Ensure vote ID doesn't exist in any voter's ActiveVotes or WithdrawnVotes before creating new record

**Test Cases**:
- Test attempting to vote with an existing active vote ID (should fail)
- Test attempting to vote with a withdrawn vote ID (should fail)
- Test that withdrawn vote IDs remain in WithdrawnVotes permanently
- Test querying withdrawn records after attempted reuse

### Proof of Concept

**Initial State**:
- Sponsor creates delegated voting item (IsLockToken = false)
- Voting item has options ["Option A", "Option B"]

**Exploitation Steps**:

1. **Step 1 - First Vote**: Sponsor calls `Vote()` with:
   - `vote_id`: Hash("0x123")
   - `voter`: Address(Alice)
   - `option`: "Option A"
   - `amount`: 100
   - Result: `VotingRecords[0x123]` = {voter: Alice, option: "Option A", amount: 100, IsWithdrawn: false}
   - Result: `VotedItemsMap[Alice].ActiveVotes` = [0x123]

2. **Step 2 - Withdraw**: Sponsor calls `Withdraw()` with vote_id: Hash("0x123")
   - Result: `VotingRecords[0x123].IsWithdrawn` = true
   - Result: `VotedItemsMap[Alice].ActiveVotes` = []
   - Result: `VotedItemsMap[Alice].WithdrawnVotes` = [0x123]

3. **Step 3 - Reuse Vote ID**: Sponsor calls `Vote()` with:
   - `vote_id`: Hash("0x123") ← **SAME VOTE ID**
   - `voter`: Address(Bob)
   - `option`: "Option B"
   - `amount`: 50

**Expected Result**: Transaction should fail with "Vote ID already exists"

**Actual Result**: Transaction succeeds with:
- `VotingRecords[0x123]` = {voter: Bob, option: "Option B", amount: 50, IsWithdrawn: false} ← **Alice's record lost**
- `VotedItemsMap[Alice].WithdrawnVotes` = [0x123] ← **Still contains it, but record points to Bob**
- `VotedItemsMap[Bob].ActiveVotes` = [0x123]
- Query `GetVotingRecord(0x123)` returns Bob's record, not Alice's original record

**Success Condition**: 
- Original Alice voting record is irrecoverably lost
- Vote ID 0x123 is removed from Bob's WithdrawnVotes (if it was there)
- Historical audit trail is corrupted

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L117-117)
```csharp
        State.VotingRecords[input.VoteId] = votingRecord;
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

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L139-146)
```csharp
    public Hash GenerateId(Address contractAddress, IEnumerable<byte> bytes)
    {
        var contactedBytes = OriginTransactionId.Value.Concat(contractAddress.Value);
        var enumerable = bytes as byte[] ?? bytes?.ToArray();
        if (enumerable != null)
            contactedBytes = contactedBytes.Concat(enumerable);
        return HashHelper.ComputeFrom(contactedBytes.ToArray());
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L204-222)
```csharp
    public override ElectorVote GetElectorVoteWithAllRecords(StringValue input)
    {
        var votes = GetElectorVoteWithRecords(input);

        if (!votes.WithdrawnVotingRecordIds.Any()) return votes;

        var votedWithdrawnRecords = State.VoteContract.GetVotingRecords.Call(new GetVotingRecordsInput
        {
            Ids = { votes.WithdrawnVotingRecordIds }
        }).Records;
        var index = 0;
        foreach (var record in votedWithdrawnRecords)
        {
            var voteId = votes.WithdrawnVotingRecordIds[index++];
            votes.WithdrawnVotesRecords.Add(TransferVotingRecordToElectionVotingRecord(record, voteId));
        }

        return votes;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L288-304)
```csharp
    public override CandidateVote GetCandidateVoteWithAllRecords(StringValue input)
    {
        var votes = GetCandidateVoteWithRecords(input);

        //get withdrawn records
        var obtainedWithdrawnRecords = State.VoteContract.GetVotingRecords.Call(new GetVotingRecordsInput
        {
            Ids = { votes.ObtainedWithdrawnVotingRecordIds }
        }).Records;
        var index = 0;
        foreach (var record in obtainedWithdrawnRecords)
        {
            var voteId = votes.ObtainedWithdrawnVotingRecordIds[index++];
            votes.ObtainedWithdrawnVotesRecords.Add(TransferVotingRecordToElectionVotingRecord(record, voteId));
        }

        return votes;
```

**File:** protobuf/vote_contract.proto (L135-148)
```text
message VoteInput {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The address of voter.
    aelf.Address voter = 2;
    // The amount of vote.
    int64 amount = 3;
    // The option to vote.
    string option = 4;
    // The vote id.
    aelf.Hash vote_id = 5;
    // Whether vote others.
    bool is_change_target = 6;
}
```
