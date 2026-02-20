# Audit Report

## Title
Sponsor Can Remove Voted Options During Active Voting, Causing DOS and Vote Manipulation

## Summary
The `RemoveOption()` function in the Vote contract lacks critical validation checks, allowing sponsors to remove options during active voting periods even when votes have been cast. This creates a denial-of-service condition for new voters and enables vote manipulation through selective option removal and re-addition, fundamentally breaking voting integrity.

## Finding Description

The `RemoveOption()` function only validates sponsor permission, option existence, and option length before removing an option from a voting item. [1](#0-0) 

The function performs no validation against the voting item's `StartTimestamp` or `EndTimestamp` fields stored in the VotingItem structure. The VotingItem has these timestamp fields defined in the protobuf specification. [2](#0-1) 

When voters call the `Vote()` function, it validates that the option exists in `votingItem.Options` list through `AssertValidVoteInput()`. [3](#0-2) 

However, votes are stored separately in the `VotingResult.Results[option]` mapping through `UpdateVotingResult()`. [4](#0-3) 

**Attack Path**:
1. Sponsor registers voting item with options A, B, C
2. Voting period becomes active (CurrentBlockTime >= StartTimestamp)
3. Multiple voters cast votes for option A via `Vote()` → stored in `VotingResult.Results["A"]`
4. Sponsor calls `RemoveOption()` to remove option A from `VotingItem.Options`
5. New voters attempting to vote for A fail at the assertion checking if the option exists in votingItem.Options
6. Existing votes for A remain in `VotingResult.Results["A"]` but option is unavailable
7. Sponsor can later re-add option A via `AddOption()`, creating inconsistent voting states

This creates a fundamental inconsistency where votes exist for options that are not available, and new voters are denied the ability to vote on options that already have votes.

## Impact Explanation

**Voting Integrity Violation**: The core invariant of fair voting - that all eligible voters have equal opportunity to vote on the same set of options - is broken. The system creates two classes of voters: those who voted before option removal and those who cannot vote after removal.

**Denial of Service**: New voters are completely blocked from voting on removed options despite existing votes, creating an availability issue for a critical governance function.

**Vote Manipulation**: Sponsors can strategically remove losing options during voting, wait for sentiment to change, then re-add them. This enables timing-based manipulation of voting outcomes.

**Governance Impact**: The Vote contract is used by the Election contract for candidate selection. The Election contract's `QuitElection` function calls `RemoveOption` to remove candidates as voting options. [5](#0-4)  This vulnerability undermines the integrity of AElf's consensus miner selection process, potentially affecting fund allocations and protocol decisions.

**Data Inconsistency**: Voting results contain orphaned votes for non-existent options, breaking result integrity and making accurate tallying impossible.

The severity is **Medium-High** because while no funds are directly stolen, the governance manipulation capability can indirectly affect fund distributions and protocol security decisions through compromised miner elections.

## Likelihood Explanation

**Attacker Profile**: Any user can be a voting sponsor by calling `Register()`. The attacker doesn't need special privileges beyond creating their own voting item.

**Execution Complexity**: **Low** - Single transaction calling `RemoveOption()` with voting item ID and option name. No complex state setup, timing windows, or race conditions required.

**Prerequisites**: 
- Voting item must exist (trivial - attacker creates it)
- Attacker must be sponsor (trivial - attacker sponsors their own voting)
- Option must exist (trivial - attacker knows their voting options)

**Detection**: Difficult - No events are emitted when options are removed (no event emission in RemoveOption function), creating no on-chain audit trail. Off-chain systems would need to continuously poll voting item state to detect modifications.

**Reproducibility**: **High** - Can be executed repeatedly during any voting period with no rate limits or cooldowns.

The likelihood is **High** due to low technical barriers and easy executability by any sponsor.

## Recommendation

Add timestamp validation to the `RemoveOption()` function to prevent option removal during active voting periods:

```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // Add timestamp validation
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp || 
           Context.CurrentBlockTime > votingItem.EndTimestamp, 
           "Cannot remove options during active voting period.");
    
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Additionally, consider:
1. Emitting an event when options are removed for audit trail purposes
2. Checking if votes exist for the option before allowing removal
3. Applying the same validation to `AddOption()` and `RemoveOptions()` functions

## Proof of Concept

```csharp
[Fact]
public async Task RemoveOption_During_Active_Voting_Causes_DOS()
{
    // 1. Register voting item with options A, B, C
    var startTime = TimestampHelper.GetUtcNow().AddSeconds(10);
    var endTime = startTime.AddDays(7);
    
    var registerInput = new VotingRegisterInput
    {
        StartTimestamp = startTime,
        EndTimestamp = endTime,
        AcceptedCurrency = "ELF",
        IsLockToken = true,
        TotalSnapshotNumber = 1,
        Options = { "OptionA", "OptionB", "OptionC" }
    };
    
    await VoteContractStub.Register.SendAsync(registerInput);
    var votingItemId = HashHelper.ComputeFrom(registerInput);
    
    // 2. Advance time to active period
    BlockTimeProvider.SetBlockTime(startTime.AddSeconds(1));
    
    // 3. Voter1 casts vote for OptionA
    var voter1 = SampleAccount.Accounts.First();
    var voteInput1 = new VoteInput
    {
        VotingItemId = votingItemId,
        Amount = 100,
        Option = "OptionA"
    };
    await GetVoteContractStub(voter1.KeyPair).Vote.SendAsync(voteInput1);
    
    // 4. Sponsor removes OptionA
    var removeInput = new RemoveOptionInput
    {
        VotingItemId = votingItemId,
        Option = "OptionA"
    };
    await VoteContractStub.RemoveOption.SendAsync(removeInput);
    
    // 5. Voter2 attempts to vote for OptionA - SHOULD FAIL
    var voter2 = SampleAccount.Accounts.Skip(1).First();
    var voteInput2 = new VoteInput
    {
        VotingItemId = votingItemId,
        Amount = 100,
        Option = "OptionA"
    };
    
    var result = await GetVoteContractStub(voter2.KeyPair).Vote.SendWithExceptionAsync(voteInput2);
    result.TransactionResult.Error.ShouldContain("Option OptionA not found");
    
    // 6. Verify votes for OptionA still exist in results
    var votingResult = await VoteContractStub.GetLatestVotingResult.CallAsync(votingItemId);
    votingResult.Results.ShouldContainKey("OptionA");
    votingResult.Results["OptionA"].ShouldBe(100);
}
```

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L303-312)
```csharp
    public override Empty RemoveOption(RemoveOptionInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
        votingItem.Options.Remove(input.Option);
        State.VotingItems[votingItem.VotingItemId] = votingItem;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-381)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
```

**File:** protobuf/vote_contract.proto (L122-124)
```text
    google.protobuf.Timestamp start_timestamp = 8;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 9;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L257-261)
```csharp
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
```
