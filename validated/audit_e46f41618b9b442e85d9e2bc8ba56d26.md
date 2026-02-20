# Audit Report

## Title
Vote Record Overwrite Enables Double-Counting in Delegated Voting

## Summary
The Vote contract allows sponsors to reuse the same VoteId with different voters in delegated voting mode (IsLockToken=false), causing each call to unconditionally increment vote totals while overwriting the previous record. This enables permanent vote count inflation that persists after withdrawal.

## Finding Description

In delegated voting mode, sponsors provide both Voter address and VoteId parameters. The contract's validation logic for delegated voting only verifies that the sender is the sponsor and that Voter/VoteId are non-null, without checking for duplicate VoteIds. [1](#0-0) 

The voting record is unconditionally overwritten regardless of whether a record with that VoteId already exists. [2](#0-1) 

The `UpdateVotingResult()` method always increments vote tallies (Results[option], VotersCount, VotesAmount) without checking if the VoteId has been counted before. [3](#0-2) 

The `UpdateVotedItems()` method adds the VoteId to each voter's ActiveVotes list, allowing the same VoteId to appear in multiple voters' lists. [4](#0-3) 

**Attack Sequence:**
1. Sponsor creates delegated voting item with `IsLockToken=false`
2. Sponsor calls `Vote(VoteId=X, Voter=Alice, Amount=100, Option="A")`
   - Sets VotingRecords[X] = {Voter: Alice, Amount: 100}
   - Increments Results["A"] by 100, VotersCount by 1, VotesAmount by 100
3. Sponsor calls `Vote(VoteId=X, Voter=Bob, Amount=50, Option="A")` with the same VoteId
   - Overwrites VotingRecords[X] = {Voter: Bob, Amount: 50}
   - Increments Results["A"] by 50, VotersCount by 1, VotesAmount by 50 again
4. Final state: Results["A"] = 150, but VotingRecords[X] shows only Bob with 50

When Bob withdraws, the withdrawal logic only subtracts the current record's amount from results, leaving the previous vote count permanently inflated. [5](#0-4) 

Alice retains VoteId X in her ActiveVotes but cannot withdraw it since the record shows Bob as the voter.

**Comparison with Regular Voting:**
Regular voting (IsLockToken=true) auto-generates unique VoteIds using `Context.GenerateId()`, preventing this vulnerability. [6](#0-5) 

**Election Contract Protection:**
The Election contract implements its own duplicate check with `Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.")`, but this protection is not enforced in the base Vote contract. [7](#0-6) 

## Impact Explanation

**Vote Integrity Compromise**: A malicious sponsor can artificially inflate vote totals by reusing VoteIds with different voters, creating phantom votes that manipulate voting outcomes.

**Permanent State Corruption**: The inflated vote counts persist indefinitely. When the duplicate VoteId is withdrawn, only the last voter's amount is subtracted, leaving previously counted votes permanently inflated in the results.

**Orphaned Vote Tracking**: Previous voters retain the VoteId in their ActiveVotes list but cannot withdraw since the record shows a different voter as owner, creating irrecoverable inconsistencies in user state.

**Governance Impact**: While the Election contract has its own protections, any custom voting items created by other contracts or users are vulnerable. This affects custom governance proposals, third-party voting systems, and any delegated voting scenario where the sponsor is not fully trusted.

The vulnerability breaks fundamental voting system guarantees: vote count integrity, state consistency between records and results, and correct withdrawal mechanics.

## Likelihood Explanation

**Attack Feasibility**: The exploit requires only that a sponsor create a delegated voting item by calling `Register()` with `IsLockToken=false`, then call `Vote()` multiple times with the same VoteId. No special permissions beyond sponsor status are needed.

**Attacker Profile**: Any user can become a sponsor by calling `Register()` on the Vote contract. The attack is straightforward - repeatedly calling `Vote()` with a reused VoteId and different voters.

**Detection Difficulty**: The attack leaves no obvious on-chain traces since the VotingRecords map only shows the final state after overwrites. Off-chain monitoring would need to track all Vote() transactions and detect VoteId reuse across different voters.

**Economic Constraints**: Creating a delegated voting item requires minimal resources. The sponsor controls who can vote in delegated mode, making the attack trivial for the sponsor to execute.

**Real-World Context**: While the core Election contract implements VoteId uniqueness checks, the base Vote contract is designed as a reusable component. Any custom voting implementation using delegated voting without implementing similar protections would be vulnerable.

## Recommendation

Add duplicate VoteId validation in the `AssertValidVoteInput()` method for delegated voting:

```csharp
if (!votingItem.IsLockToken)
{
    Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
    Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
    Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    Assert(State.VotingRecords[input.VoteId] == null, "Vote Id already exists."); // Add this check
}
```

This ensures that each VoteId can only be used once, maintaining the invariant that each VoteId represents exactly one vote.

## Proof of Concept

```csharp
[Fact]
public async Task DelegatedVoting_DoubleCount_VoteId_Reuse()
{
    // Register delegated voting item (IsLockToken=false)
    var votingItem = await RegisterVotingItemAsync(100, 3, false, DefaultSender, 1);
    var option = votingItem.Options[0];
    
    // Create a fixed VoteId for reuse
    var sharedVoteId = HashHelper.ComputeFrom("shared-vote-id");
    
    // Alice votes with VoteId X, amount 100
    var aliceAddress = Accounts[1].Address;
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        VoteId = sharedVoteId,
        Voter = aliceAddress,
        Amount = 100,
        Option = option
    });
    
    // Check results after Alice's vote
    var resultAfterAlice = await GetVotingResult(votingItem.VotingItemId, 1);
    resultAfterAlice.Results[option].ShouldBe(100);
    resultAfterAlice.VotersCount.ShouldBe(1);
    resultAfterAlice.VotesAmount.ShouldBe(100);
    
    // Bob votes with SAME VoteId X, amount 50 - should inflate counts
    var bobAddress = Accounts[2].Address;
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        VoteId = sharedVoteId, // Reused VoteId
        Voter = bobAddress,
        Amount = 50,
        Option = option
    });
    
    // Check results after Bob's vote - DOUBLE COUNTED
    var resultAfterBob = await GetVotingResult(votingItem.VotingItemId, 1);
    resultAfterBob.Results[option].ShouldBe(150); // 100 + 50 = INFLATED
    resultAfterBob.VotersCount.ShouldBe(2); // Counted twice
    resultAfterBob.VotesAmount.ShouldBe(150); // Inflated
    
    // But VotingRecord shows only Bob
    var record = await GetVotingRecord(sharedVoteId);
    record.Voter.ShouldBe(bobAddress); // Alice's record was overwritten
    record.Amount.ShouldBe(50); // Only Bob's amount
    
    // Withdraw - only subtracts Bob's 50, leaving 100 inflated
    await VoteContractStub.Withdraw.SendAsync(new WithdrawInput { VoteId = sharedVoteId });
    
    var resultAfterWithdraw = await GetVotingResult(votingItem.VotingItemId, 1);
    resultAfterWithdraw.Results[option].ShouldBe(100); // 150 - 50 = 100 PERMANENT INFLATION
    resultAfterWithdraw.VotersCount.ShouldBe(1);
    resultAfterWithdraw.VotesAmount.ShouldBe(100); // Permanently inflated
}
```

## Notes

This vulnerability specifically affects the **delegated voting mode** where sponsors control VoteId assignment. Regular voting mode auto-generates unique VoteIds and is not vulnerable. The Election contract implements its own duplicate check, but any custom voting systems built on the base Vote contract without similar protections are vulnerable to vote count manipulation through VoteId reuse.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-220)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-389)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L390-398)
```csharp
        else
        {
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L432-434)
```csharp
        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
        State.LockTimeMap[voteId] = lockSeconds;
```
