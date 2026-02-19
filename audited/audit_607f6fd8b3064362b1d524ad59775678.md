### Title
Sponsor Can Remove Voted Options During Active Voting, Causing DOS and Vote Manipulation

### Summary
The `RemoveOption()` function allows the sponsor to remove options from a voting item at any time without checking if voting is active or if votes have been cast on that option. This creates a denial-of-service for new voters attempting to vote on removed options and enables vote manipulation through selective option removal and re-addition. The vulnerability breaks voting integrity by creating inconsistency between stored votes and available options.

### Finding Description

The `RemoveOption()` function only validates sponsor permission, option existence, and option length before removing an option from the voting item: [1](#0-0) 

**Root Cause**: The function lacks critical checks:
1. No validation that voting period is inactive (no check against `StartTimestamp` or `EndTimestamp`)
2. No verification that the option has zero votes before removal
3. No protection against repeated add/remove operations

When the `Vote()` function validates input, it requires the option to exist in the voting item's option list: [2](#0-1) 

**Why Protections Fail**: When an option is removed:
- Existing votes remain in `VotingResult.Results[option]` mapping (updated via `UpdateVotingResult()`)
- The option is removed from `VotingItem.Options` list
- New voters cannot vote on the removed option (assertion at line 381 fails)
- The voting item structure stores timestamps but never enforces them for option modifications: [3](#0-2) 

**Execution Path**:
1. Sponsor registers voting with options A, B, C
2. Voting period starts (`CurrentBlockTime >= StartTimestamp`)
3. Voters cast 1000 votes for option A via `Vote()` → stored in `VotingResult.Results["A"]`
4. Sponsor calls `RemoveOption()` with option A → removed from `VotingItem.Options`
5. New voters attempting to vote for A encounter: "Option A not found" error
6. Existing 1000 votes for A remain in results but option is unavailable for new votes
7. Sponsor can re-add option A later, effectively creating a new voting opportunity separate from original votes

### Impact Explanation

**Direct Harm**:
- **Denial of Service**: New voters are blocked from voting on options that have existing votes, fragmenting the voting pool and preventing fair participation
- **Vote Manipulation**: Sponsor can selectively remove losing options, wait for voting patterns to change, then re-add them to reset vote counts
- **Result Inconsistency**: Voting results contain votes for options that no longer exist in the voting item, breaking result integrity
- **Voter Confusion**: Voters see different option sets at different times, undermining trust in the voting process

**Affected Parties**:
- New voters attempting to vote on previously popular options
- Existing voters whose votes become "orphaned" when options are removed
- Election contract users relying on Vote contract for candidate selection
- Governance processes dependent on voting results

**Severity Justification**: Medium-High
- Breaks voting integrity invariant (governance impact)
- Enables sponsor to manipulate outcomes through timing-based option management
- Creates operational DOS for legitimate voters
- No funds directly stolen but governance decisions can be manipulated, affecting fund allocations

### Likelihood Explanation

**Attacker Capabilities**: 
- Attacker must be the sponsor of the voting item (legitimate role)
- Single transaction execution via `RemoveOption()` public method
- No special permissions beyond sponsor role required

**Attack Complexity**: Low
- Direct function call with voting item ID and option name
- No complex state setup or timing requirements
- Can be repeated arbitrarily during voting period

**Feasibility Conditions**:
- Voting item must exist (trivial - sponsor creates it)
- Option must currently exist in list (trivial - sponsor knows current options)
- No rate limiting or cooldown periods prevent repeated calls

**Detection Constraints**:
- No events emitted when options are removed
- No on-chain audit trail of option modifications
- Off-chain monitoring would need to track option list changes manually

**Probability**: High - Simple to execute with legitimate sponsor role, no technical barriers

### Recommendation

**Code-Level Mitigation**:

1. **Add timestamp validation** in `RemoveOption()` and `AddOption()`:
```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // NEW: Prevent option modification during active voting
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp || 
           Context.CurrentBlockTime > votingItem.EndTimestamp,
           "Cannot modify options during active voting period.");
    
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

2. **Add vote existence check** (optional, stricter protection):
```csharp
// Check if any votes exist for this option
var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
var votingResult = State.VotingResults[votingResultHash];
if (votingResult.Results.ContainsKey(input.Option))
{
    Assert(votingResult.Results[input.Option] == 0, 
           "Cannot remove option with existing votes.");
}
```

3. **Emit events** for option modifications to enable monitoring:
```csharp
Context.Fire(new OptionRemoved
{
    VotingItemId = votingItem.VotingItemId,
    Option = input.Option,
    Timestamp = Context.CurrentBlockTime
});
```

**Test Cases to Add**:
- Test that `RemoveOption()` fails when `CurrentBlockTime` is between `StartTimestamp` and `EndTimestamp`
- Test that `RemoveOption()` fails when votes exist on the option being removed
- Test that `RemoveOption()` succeeds only before voting starts or after voting ends
- Test repeated add/remove cycles are prevented during active voting
- Integration test showing new voters cannot vote on removed options while existing votes remain

### Proof of Concept

**Initial State**:
- Sponsor address: `SponsorA`
- Voting item registered with options: `["OptionA", "OptionB", "OptionC"]`
- `StartTimestamp`: Day 1, `EndTimestamp`: Day 10
- Current time: Day 5 (voting is active)

**Transaction Steps**:

1. **Setup**: Sponsor creates voting item
   - Call: `Register(VotingRegisterInput{ Options: ["OptionA", "OptionB", "OptionC"], StartTimestamp: Day1, EndTimestamp: Day10 })`
   - Result: Voting item created with ID `VotingItem1`

2. **Voting Phase**: Multiple users vote for OptionA
   - User1 calls: `Vote(VoteInput{ VotingItemId: VotingItem1, Option: "OptionA", Amount: 1000 })`
   - User2 calls: `Vote(VoteInput{ VotingItemId: VotingItem1, Option: "OptionA", Amount: 500 })`
   - User3 calls: `Vote(VoteInput{ VotingItemId: VotingItem1, Option: "OptionB", Amount: 300 })`
   - State: `VotingResult.Results["OptionA"] = 1500`, `VotingResult.Results["OptionB"] = 300`

3. **Attack**: Sponsor removes OptionA during active voting (Day 5)
   - Call: `RemoveOption(RemoveOptionInput{ VotingItemId: VotingItem1, Option: "OptionA" })`
   - **Expected**: Transaction should fail with "Cannot modify options during active voting period"
   - **Actual**: Transaction succeeds, OptionA removed from `VotingItem.Options`

4. **DOS Effect**: New voter attempts to vote for OptionA
   - User4 calls: `Vote(VoteInput{ VotingItemId: VotingItem1, Option: "OptionA", Amount: 800 })`
   - Result: Transaction fails with "Option OptionA not found"
   - Impact: User4 is denied ability to vote for option that has 1500 existing votes

5. **Manipulation**: Sponsor re-adds OptionA
   - Call: `AddOption(AddOptionInput{ VotingItemId: VotingItem1, Option: "OptionA" })`
   - Result: OptionA is back in options list
   - State: Original 1500 votes still in `VotingResult.Results["OptionA"]`, but option was temporarily unavailable

**Success Condition**: 
The attack succeeds if `RemoveOption()` completes successfully during the active voting period (between `StartTimestamp` and `EndTimestamp`), causing subsequent `Vote()` calls for that option to fail despite existing votes remaining in the results.

### Citations

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-382)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
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
