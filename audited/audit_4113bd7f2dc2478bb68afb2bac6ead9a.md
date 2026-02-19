# Audit Report

## Title
Vote ID Reuse in Delegated Voting Enables Historical Record Manipulation and Audit Trail Corruption

## Summary
The Vote contract's `Vote()` function unconditionally overwrites `VotingRecord` state without validating vote ID uniqueness in delegated voting scenarios. When a Sponsor reuses a previously withdrawn vote ID, the original voting record is permanently destroyed, corrupting the historical audit trail relied upon by governance view methods.

## Finding Description

The vulnerability exists in the `Vote()` function which stores voting records without checking if a vote ID already exists: [1](#0-0) 

For delegated voting (IsLockToken = false), the Sponsor provides the vote ID in the input parameter and has full control over its value: [2](#0-1) 

The validation function `AssertValidVoteInput()` checks voting item existence, options, and snapshot numbers, but critically does NOT validate vote ID uniqueness: [3](#0-2) 

When `UpdateVotedItems()` is called during voting, it removes the vote ID from the current voter's `WithdrawnVotes` list: [4](#0-3) 

**Attack Flow:**
1. Sponsor creates vote for Voter A with `voteId = X`
2. Sponsor withdraws vote X (sets `IsWithdrawn = true`, adds to Voter A's `WithdrawnVotingRecordIds`)
3. Sponsor creates NEW vote for Voter B with SAME `voteId = X`
4. `State.VotingRecords[X]` is overwritten with Voter B's data
5. Voter A's `WithdrawnVotingRecordIds` still contains X, but `GetVotingRecords(X)` now returns Voter B's record
6. Original historical record is permanently lost

The Election contract's `GetElectorVoteWithAllRecords()` method relies on these records for displaying complete voting history: [5](#0-4) 

This method fetches withdrawn records using the vote IDs, but receives corrupted data when IDs are reused.

Importantly, the Election contract's own `ChangeVotingOption` feature intentionally exploits this design by reusing vote IDs: [6](#0-5) 

This proves the vulnerability is not theoretical—it's actively used in production and causes the same audit trail corruption even for legitimate use cases.

## Impact Explanation

**Critical Governance Impact:**
- **Permanent Data Loss:** Original `VotingRecord` data is irrecoverably destroyed when overwritten
- **Audit Trail Corruption:** View methods like `GetElectorVoteWithAllRecords()` and `GetCandidateVoteWithAllRecords()` return incorrect historical data
- **Transparency Violation:** Governance systems require immutable historical records for accountability and compliance
- **Evidence Destruction:** Previous voting decisions can be erased, hiding evidence of governance actions

**Why MEDIUM Severity Despite High Impact:**
- Vote tallies remain mathematically correct (proper addition/subtraction in voting results)
- No direct financial loss to users
- Requires Sponsor role, which is typically a trusted governance contract
- However, the Vote contract is a library that should have proper validation regardless of caller trust assumptions

The severity is justified because while there's no fund loss, governance integrity and transparency are fundamental protocol invariants that must be preserved.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Capabilities:**
- Must be the Sponsor of a delegated voting item (IsLockToken = false)
- Can provide arbitrary vote IDs when calling `Vote()`
- Single transaction is sufficient to exploit

**Why This is Realistic:**
1. **Already Happening in Production:** The Election contract's `ChangeVotingOption` feature intentionally reuses vote IDs, demonstrating this issue exists in live code

2. **Documented Feature:** Delegated voting is a standard feature used by the Election contract: [7](#0-6) 

3. **Generic Library Contract:** The Vote contract is designed to be used by multiple contracts, not just Election. Other Sponsors might lack the Election contract's protections: [8](#0-7) 

4. **No Detection Mechanism:** The `Voted` event is emitted normally, and observers cannot detect that a previous record was overwritten

**Feasibility:** LOW complexity—single transaction with controlled input, no timing requirements, easily reproducible.

## Recommendation

Add vote ID uniqueness validation in the `Vote()` function before storing records:

```csharp
public override Empty Vote(VoteInput input)
{
    var votingItem = AssertValidVoteInput(input);
    
    // ADD THIS CHECK:
    if (!votingItem.IsLockToken)
    {
        Assert(State.VotingRecords[input.VoteId] == null || 
               State.VotingRecords[input.VoteId].IsWithdrawn == false,
               "Vote ID already exists or was previously withdrawn.");
    }
    
    // ... rest of existing code
}
```

For the `ChangeVotingOption` scenario, consider one of these approaches:
1. **Generate new vote IDs** for changed votes and maintain a mapping to track vote lineage
2. **Store vote history** in a separate state structure that preserves all versions
3. **Add version numbers** to VotingRecords to track changes while keeping history

The root issue is treating VotingRecords as mutable state when they should be immutable historical data.

## Proof of Concept

```csharp
[Fact]
public async Task VoteIdReuse_CorruptsAuditTrail()
{
    // Setup: Register a delegated voting item
    var sponsor = GetDefaultSponsorStub();
    await sponsor.Register.SendAsync(new VotingRegisterInput
    {
        IsLockToken = false, // Delegated voting
        AcceptedCurrency = "ELF",
        TotalSnapshotNumber = 10,
        StartTimestamp = TimestampHelper.GetUtcNow(),
        EndTimestamp = TimestampHelper.GetUtcNow().AddDays(30),
        Options = {"Option1", "Option2"}
    });
    
    var votingItemId = // ... get voting item ID
    var voteId = HashHelper.ComputeFrom("reusable-vote-id");
    
    // Step 1: Create vote for Alice
    await sponsor.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Voter = AliceAddress,
        VoteId = voteId,
        Amount = 100,
        Option = "Option1"
    });
    
    var aliceRecordOriginal = await VoteContractStub.GetVotingRecord.CallAsync(voteId);
    aliceRecordOriginal.Voter.ShouldBe(AliceAddress);
    aliceRecordOriginal.Option.ShouldBe("Option1");
    
    // Step 2: Withdraw Alice's vote
    await sponsor.Withdraw.SendAsync(new WithdrawInput { VoteId = voteId });
    
    var aliceRecordWithdrawn = await VoteContractStub.GetVotingRecord.CallAsync(voteId);
    aliceRecordWithdrawn.IsWithdrawn.ShouldBe(true);
    
    // Step 3: Reuse the SAME vote ID for Bob (VULNERABILITY)
    await sponsor.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Voter = BobAddress,
        VoteId = voteId, // SAME ID!
        Amount = 50,
        Option = "Option2"
    });
    
    // Step 4: Verify audit trail corruption
    var recordAfterReuse = await VoteContractStub.GetVotingRecord.CallAsync(voteId);
    
    // VULNERABILITY DEMONSTRATED:
    // - Original record is permanently lost
    recordAfterReuse.Voter.ShouldBe(BobAddress); // Now Bob, not Alice!
    recordAfterReuse.Option.ShouldBe("Option2"); // Now Option2, not Option1!
    recordAfterReuse.IsWithdrawn.ShouldBe(false); // Withdrawal state lost!
    
    // Alice's withdrawn records list still contains this vote ID,
    // but fetching it returns Bob's data - audit trail corrupted
}
```

## Notes

This vulnerability is particularly concerning because:
1. The Election contract's `ChangeVotingOption` feature already demonstrates this issue in production code
2. The Vote contract is a library contract that should enforce data integrity regardless of caller trust
3. Historical voting records are fundamental to governance transparency and cannot be reconstructed once destroyed
4. While Sponsors are typically trusted, the lack of validation creates systemic risk and violates expected invariants for historical data storage

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L46-60)
```csharp
        State.VoteContract.Withdraw.Send(new WithdrawInput
        {
            VoteId = input.VoteId
        });

        // Create new votes
        State.VoteContract.Vote.Send(new VoteInput
        {
            VoteId = input.VoteId,
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Amount = votingRecord.Amount,
            Voter = votingRecord.Voter,
            Option = input.CandidatePubkey,
            IsChangeTarget = true
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L432-433)
```csharp
        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L60-67)
```csharp
        var votingRegisterInput = new VotingRegisterInput
        {
            IsLockToken = false,
            AcceptedCurrency = Context.Variables.NativeSymbol,
            TotalSnapshotNumber = long.MaxValue,
            StartTimestamp = TimestampHelper.MinValue,
            EndTimestamp = TimestampHelper.MaxValue
        };
```
