# Audit Report

## Title
Sponsor Can Remove Voted Options During Active Voting, Causing DOS and Vote Manipulation

## Summary
The `RemoveOption()` function allows voting sponsors to remove options at any time without validating whether voting is active or whether votes have been cast. This creates denial-of-service for new voters and enables vote manipulation through selective option removal during active voting periods.

## Finding Description

The `RemoveOption()` function only validates sponsor permission, option existence, and option length before removing an option: [1](#0-0) 

**Root Cause**: The function lacks critical checks:
1. No validation that voting period is inactive (no check against `StartTimestamp` or `EndTimestamp`)
2. No verification that the option has zero votes before removal
3. No protection against repeated add/remove operations

The `Vote()` function requires options to exist in the voting item's option list when validating input: [2](#0-1) 

When an option is removed, existing votes remain in the `VotingResult.Results[option]` mapping (updated via `UpdateVotingResult()`): [3](#0-2) 

The voting item structure stores timestamps but `RemoveOption()` never enforces them for option modifications: [4](#0-3) 

**Execution Path**:
1. Sponsor registers voting with options A, B, C via `Register()`
2. Voting period starts (`CurrentBlockTime >= StartTimestamp`)  
3. Voters cast 1000 votes for option A via `Vote()` → stored in `VotingResult.Results["A"]`
4. Sponsor calls `RemoveOption()` with option A → removed from `VotingItem.Options`
5. New voters attempting to vote for A encounter: "Option A not found" assertion failure
6. Existing 1000 votes for A remain in results but option is unavailable for new votes
7. Sponsor can re-add option A later via `AddOption()`, effectively resetting the voting context

**Real-World Usage**: The Election contract uses `RemoveOption()` when candidates quit, demonstrating this issue occurs in production: [5](#0-4) 

## Impact Explanation

**Direct Harm**:
- **Denial of Service**: New voters are blocked from voting on options that have existing votes, fragmenting the voting pool and preventing fair participation
- **Vote Manipulation**: Sponsor can selectively remove losing options temporarily, wait for voting patterns to change, then re-add them to influence outcomes
- **Result Inconsistency**: Voting results contain votes for options that no longer exist in the voting item, breaking result integrity and making tallying unreliable
- **Voter Confusion**: Voters see different option sets at different times, undermining trust in the governance process

**Affected Parties**:
- New voters attempting to vote on previously popular options
- Existing voters whose votes become "orphaned" when options are removed  
- Election contract users relying on Vote contract for candidate selection
- Any governance processes dependent on voting results

**Severity Justification**: Medium-High
- Breaks voting integrity invariant (governance impact)
- Enables sponsor to manipulate outcomes through timing-based option management
- Creates operational DOS for legitimate voters during active voting periods
- While no funds are directly stolen, governance decisions can be manipulated, potentially affecting fund allocations and protocol parameters

## Likelihood Explanation

**Attacker Capabilities**:
- Attacker must be the sponsor of the voting item (legitimate role)
- Single transaction execution via public `RemoveOption()` method
- No special permissions beyond sponsor role required

**Attack Complexity**: Low
- Direct function call with voting item ID and option name
- No complex state setup or precise timing requirements
- Can be repeated arbitrarily during voting period without rate limiting

**Feasibility Conditions**:
- Voting item must exist (trivial - sponsor creates it via `Register()`)
- Option must currently exist in list (trivial - sponsor knows current options)
- No cooldown periods or transaction limits prevent repeated calls

**Detection Constraints**:
- No events emitted when options are removed (no audit trail)
- No on-chain indication of option modifications
- Off-chain monitoring would need to continuously poll option lists to detect changes

**Probability**: High - Simple to execute with legitimate sponsor role, no technical barriers, and already occurring in Election contract usage.

## Recommendation

Add validation checks to `RemoveOption()` to prevent removal during active voting or when votes exist:

```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    
    // NEW: Prevent removal during active voting period
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp || 
           Context.CurrentBlockTime > votingItem.EndTimestamp,
           "Cannot remove options during active voting period.");
    
    // NEW: Prevent removal if votes exist for this option
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    if (votingResult.Results.ContainsKey(input.Option))
    {
        Assert(votingResult.Results[input.Option] == 0, 
               "Cannot remove option with existing votes.");
    }
    
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

Alternatively, implement a two-phase approach where option removal is only allowed before voting starts or after it ends completely.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveOption_DuringActiveVoting_CausesDoS()
{
    // Setup: Create voting item with options A, B, C
    var startTime = TimestampHelper.GetUtcNow();
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
    
    // Step 1: Cast votes for OptionA during active period
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Amount = 1000,
        Option = "OptionA"
    });
    
    // Step 2: Sponsor removes OptionA during active voting
    await VoteContractStub.RemoveOption.SendAsync(new RemoveOptionInput
    {
        VotingItemId = votingItemId,
        Option = "OptionA"
    });
    
    // Step 3: Verify new voters cannot vote for OptionA (DOS)
    var result = await VoteContractStub.Vote.SendWithExceptionAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Amount = 500,
        Option = "OptionA"
    });
    
    result.TransactionResult.Error.ShouldContain("Option OptionA not found");
    
    // Step 4: Verify existing votes remain in results (inconsistency)
    var votingResult = await VoteContractStub.GetLatestVotingResult.CallAsync(votingItemId);
    votingResult.Results["OptionA"].ShouldBe(1000); // Votes still exist
    
    // Step 5: Verify removed option not in available options
    var votingItem = await VoteContractStub.GetVotingItem.CallAsync(
        new GetVotingItemInput { VotingItemId = votingItemId });
    votingItem.Options.ShouldNotContain("OptionA"); // Option removed but votes remain
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L381-381)
```csharp
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
```

**File:** protobuf/vote_contract.proto (L106-133)
```text
message VotingItem {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The token symbol which will be accepted.
    string accepted_currency = 2;
    // Whether the vote will lock token.
    bool is_lock_token = 3;
    // The current snapshot number.
    int64 current_snapshot_number = 4;
    // The total snapshot number.
    int64 total_snapshot_number = 5;
    // The list of options.
    repeated string options = 6;
    // The register time of the voting activity.
    google.protobuf.Timestamp register_timestamp = 7;
    // The start time of the voting.
    google.protobuf.Timestamp start_timestamp = 8;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 9;
    // The start time of current round of the voting.
    google.protobuf.Timestamp current_snapshot_start_timestamp = 10;
    // The sponsor address of the voting activity.
    aelf.Address sponsor = 11;
    // Is quadratic voting.
    bool is_quadratic = 12;
    // Quadratic voting item ticket cost.
    int64 ticket_cost = 13;
}
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L256-261)
```csharp
        // Remove candidate public key from the Voting Item options.
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
```
