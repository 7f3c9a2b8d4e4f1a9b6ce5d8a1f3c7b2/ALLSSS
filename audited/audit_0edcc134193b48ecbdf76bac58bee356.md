# Audit Report

## Title
Vote Record Overwrite Enables Double-Counting in Delegated Voting

## Summary
The Vote contract allows sponsors to call Vote() multiple times with the same VoteId but different voters in delegated voting scenarios (IsLockToken=false). Each call overwrites the previous voting record while unconditionally incrementing vote totals, causing permanent inflation of vote counts that persists even after withdrawal.

## Finding Description

In the Vote contract's delegated voting mode, sponsors provide both the Voter address and VoteId parameters. The contract accepts these without validating VoteId uniqueness, enabling a double-counting attack. [1](#0-0) 

The voting record is unconditionally overwritten at line 117, replacing any previous record with the same VoteId. [2](#0-1) 

For delegated voting, the validation only checks that the sender is the sponsor and that Voter/VoteId are non-null. There is no check for duplicate VoteIds. [3](#0-2) 

The UpdateVotingResult() method always increments vote tallies (Results[option], VotersCount, VotesAmount) regardless of whether the VoteId already exists. This breaks the invariant that each VoteId represents exactly one vote. [4](#0-3) 

The UpdateVotedItems() method adds the VoteId to each voter's ActiveVotes list without preventing the same VoteId from appearing in multiple voters' lists.

**Attack Sequence:**
1. Sponsor creates delegated voting item (IsLockToken=false)
2. Sponsor calls Vote(VoteId=X, Voter=Alice, Amount=100, Option="A")
   - Sets VotingRecords[X] = {Voter: Alice, Amount: 100}
   - Increments Results["A"] += 100, VotersCount += 1, VotesAmount += 100
3. Sponsor calls Vote(VoteId=X, Voter=Bob, Amount=50, Option="A") - **same VoteId**
   - Overwrites VotingRecords[X] = {Voter: Bob, Amount: 50}
   - Increments Results["A"] += 50, VotersCount += 1, VotesAmount += 50 **again**
4. Final state: Results["A"] = 150, but VotingRecords[X] shows only Bob with 50 [5](#0-4) 

When Bob withdraws, only his 50 tokens are subtracted from the results, leaving Results["A"] = 100 permanently inflated. Alice retains X in her ActiveVotes but cannot withdraw since the record shows Bob as the voter.

**Comparison with Regular Voting:** [6](#0-5) 

Regular voting (IsLockToken=true) generates unique VoteIds using Context.GenerateId(), preventing this vulnerability. However, delegated voting relies on sponsor-provided VoteIds without enforcing uniqueness.

**Election Contract Protection:** [7](#0-6) 

The Election contract checks for duplicate VoteIds, but this protection is not enforced in the base Vote contract, leaving custom voting items vulnerable.

## Impact Explanation

**Vote Integrity Compromise**: A malicious sponsor can artificially inflate vote totals by reusing VoteIds with different voters, creating phantom votes that manipulate voting outcomes.

**Permanent State Corruption**: The inflated vote counts persist indefinitely. When the duplicate VoteId is withdrawn, only the last voter's amount is subtracted, leaving previously counted votes permanently inflated in the results.

**Orphaned Vote Tracking**: Previous voters retain the VoteId in their ActiveVotes list but cannot withdraw it since the record shows a different voter as the owner, creating irrecoverable inconsistencies in user state.

**Governance Impact**: While the Election contract has its own protections, any custom voting items created by other contracts or users are vulnerable. This could affect:
- Custom governance proposals using delegated voting
- Third-party voting systems built on the Vote contract
- Any delegated voting scenario where the sponsor is not fully trusted

The vulnerability breaks fundamental voting system guarantees: vote count integrity, state consistency between records and results, and correct withdrawal mechanics.

## Likelihood Explanation

**Attack Feasibility**: The exploit requires only that a sponsor create a delegated voting item by calling Register() with IsLockToken=false, then call Vote() multiple times with the same VoteId. No special permissions beyond sponsor status are needed.

**Attacker Profile**: Any user can become a sponsor by calling Register() on the Vote contract. The attack is straightforward - repeatedly calling Vote() with a reused VoteId and different voters.

**Detection Difficulty**: The attack leaves no obvious on-chain traces since the VotingRecords map only shows the final state after overwrites. Off-chain monitoring would need to track all Vote() transactions and detect VoteId reuse across different voters.

**Economic Constraints**: Creating a delegated voting item requires minimal resources. The sponsor controls who can vote in delegated mode, making the attack trivial for the sponsor to execute.

**Real-World Context**: While the core Election contract implements VoteId uniqueness checks, the base Vote contract is designed as a reusable component. Any custom voting implementation using delegated voting without implementing similar protections would be vulnerable.

## Recommendation

Add VoteId existence checking in the Vote() function for delegated voting scenarios:

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
        // ADD THIS CHECK:
        Assert(State.VotingRecords[input.VoteId] == null, "Vote Id already exists.");
    }
    else
    {
        // existing code...
    }
    return votingItem;
}
```

This ensures each VoteId can only be used once, preventing vote count inflation through record overwrites.

## Proof of Concept

```csharp
[Fact]
public async Task VoteRecordOverwrite_DoubleCountingAttack_Test()
{
    // Setup: Create delegated voting item
    var votingItem = await RegisterDelegatedVotingItem();
    var voteId = HashHelper.ComputeFrom("duplicate-vote-id");
    
    // Step 1: Sponsor votes for Alice with 100 tokens
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem,
        VoteId = voteId,
        Voter = Accounts[1].Address,  // Alice
        Amount = 100,
        Option = "OptionA"
    });
    
    // Check results after first vote
    var resultHash = GetVotingResultHash(votingItem, 1);
    var result1 = await VoteContractStub.GetVotingResult.CallAsync(resultHash);
    result1.Results["OptionA"].ShouldBe(100);
    result1.VotersCount.ShouldBe(1);
    
    // Step 2: Sponsor reuses same VoteId for Bob with 50 tokens
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem,
        VoteId = voteId,  // SAME VoteId
        Voter = Accounts[2].Address,  // Bob (different voter)
        Amount = 50,
        Option = "OptionA"
    });
    
    // Check results after double-voting
    var result2 = await VoteContractStub.GetVotingResult.CallAsync(resultHash);
    result2.Results["OptionA"].ShouldBe(150);  // Inflated! Should be 50
    result2.VotersCount.ShouldBe(2);  // Inflated! Should be 1
    
    // Verify record shows only Bob (Alice's record overwritten)
    var record = await VoteContractStub.GetVotingRecord.CallAsync(voteId);
    record.Voter.ShouldBe(Accounts[2].Address);  // Bob
    record.Amount.ShouldBe(50);
    
    // Step 3: Bob withdraws
    await VoteContractStub.Withdraw.SendAsync(new WithdrawInput { VoteId = voteId });
    
    // Verify permanent inflation
    var result3 = await VoteContractStub.GetVotingResult.CallAsync(resultHash);
    result3.Results["OptionA"].ShouldBe(100);  // Permanently inflated by Alice's phantom vote
    
    // Alice cannot withdraw (record shows Bob as voter)
    var aliceStub = GetVoteContractTester(Accounts[1].KeyPair);
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
        await aliceStub.Withdraw.SendAsync(new WithdrawInput { VoteId = voteId })
    );
    exception.Message.ShouldContain("No permission");
}
```

This test demonstrates that reusing a VoteId with different voters causes vote count inflation that persists after withdrawal, proving the vulnerability.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L213-222)
```csharp

        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L433-433)
```csharp
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
```
