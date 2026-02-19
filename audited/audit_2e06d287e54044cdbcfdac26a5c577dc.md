### Title
Sponsor Can Remove Voting Options Mid-Vote to Manipulate Perception of Voting Outcomes

### Summary
The `RemoveOption()` function lacks temporal restrictions, allowing the sponsor to remove options at any time during active voting. This enables manipulation of voting perception by hiding losing options mid-vote, while their historical votes remain in the results. This undermines voting integrity and can mislead voters about the true distribution of support.

### Finding Description

The `RemoveOption()` function performs only three checks before removing an option: [1](#0-0) 

The function critically lacks temporal validation—it does not verify whether:
- Voting has started (`StartTimestamp` vs current time)
- Voting is currently active (before `EndTimestamp`)
- The option being removed has accumulated votes

When an option is removed, only the `VotingItem.Options` list is updated: [2](#0-1) 

However, the `VotingResult` state containing vote counts per option is NOT updated. The historical votes for the removed option remain in the `Results` map: [3](#0-2) 

This creates a critical discrepancy: `GetVotingItem()` returns the updated options list without the removed option: [4](#0-3) 

While `GetVotingResult()` still contains all votes including for removed options: [5](#0-4) 

Additionally, the vote validation logic prevents new votes for removed options: [6](#0-5) 

### Impact Explanation

**Governance Integrity Violation:**
- Sponsor can selectively hide losing options during active voting
- Creates false perception of voting distribution (e.g., removing options C and D that have 200 and 50 votes makes options A and B with 1000 and 800 votes appear to have overwhelming support)
- Misleads voters who base decisions on visible option popularity
- Historical votes remain in `VotingResult` but typical UI implementations only display current options from `GetVotingItem()`

**Operational Impact:**
- Undermines fairness and transparency of voting process
- Voters cannot cast new votes for removed options, even if they were valid when voting started
- Creates confusion: votes exist for options no longer listed
- Damages protocol trust and governance credibility

**Affected Parties:**
- Current and future voters who see manipulated option lists
- Option creators whose options can be arbitrarily removed
- Protocol governance integrity overall

**Severity Justification:**
Medium severity due to governance manipulation without direct fund theft, but significant impact on voting fairness and protocol trust.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires sponsor role (trusted but can abuse timing)
- No special privileges beyond sponsor authorization needed
- Single transaction execution

**Attack Complexity:**
- Trivial: Call `RemoveOption()` at any time during voting
- No complex setup or preconditions required
- Immediate effect on vote perception

**Feasibility Conditions:**
- Sponsor has legitimate access to `RemoveOption()`
- Voting must be registered and active (common scenario)
- Options with votes can be removed without restriction

**Detection Constraints:**
- On-chain: Transparent via events and state changes
- User-facing: May not be immediately obvious if UI only shows current options
- Historical analysis: Can detect by comparing `VotingItem` changes over time

**Probability:**
High likelihood of exploitation if sponsor has incentive to manipulate voting outcomes, as execution is trivial and unrestricted.

### Recommendation

**Code-Level Mitigation:**

Add temporal restrictions to `RemoveOption()` and `RemoveOptions()` functions:

```csharp
public override Empty RemoveOption(RemoveOptionInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
    
    // Add temporal checks
    Assert(Context.CurrentBlockTime < votingItem.StartTimestamp, 
        "Cannot remove options after voting has started.");
    
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
    votingItem.Options.Remove(input.Option);
    State.VotingItems[votingItem.VotingItemId] = votingItem;
    return new Empty();
}
```

**Alternative Approach:**

If mid-vote option removal is intended functionality, add a mechanism to:
1. Clean up votes for removed options from `VotingResult`
2. Emit events clearly indicating option removal with vote counts
3. Provide refunds/notifications to affected voters

**Invariant Checks:**
- Options can only be modified before `StartTimestamp`
- Or if modification is allowed, ensure vote data consistency across all states

**Test Cases:**

Add regression tests:
1. Test removing option after `StartTimestamp` fails
2. Test removing option with existing votes fails (or cleans up votes)
3. Test removing option during active voting period fails
4. Test option removal only succeeds before voting starts

### Proof of Concept

**Initial State:**
1. Sponsor registers voting item with options ["A", "B", "C", "D"]
2. `StartTimestamp` = T0, `EndTimestamp` = T0 + 10 days
3. Current time advances to T0 + 1 day (voting active)

**Attack Steps:**

Step 1: Voters cast votes during day 1-2:
- Option A: 1000 votes
- Option B: 800 votes  
- Option C: 200 votes
- Option D: 50 votes

Step 2: At time T0 + 2 days (mid-vote), sponsor calls:
```
RemoveOption({
    VotingItemId: <vote_id>,
    Option: "C"
})

RemoveOption({
    VotingItemId: <vote_id>,
    Option: "D"
})
```

**Expected vs Actual Result:**

Expected (Secure): Transaction reverts with "Cannot remove options after voting has started"

Actual (Vulnerable): 
- Transactions succeed
- `GetVotingItem()` returns options: ["A", "B"] only
- `GetVotingResult()` still shows: {A: 1000, B: 800, C: 200, D: 50}
- New voters see only A and B as available options
- Voting perception manipulated: A and B appear to have 100% of "valid" options

**Success Condition:**
Options C and D removed from `VotingItem.Options` during active voting without temporal restriction enforcement, demonstrating manipulation capability.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L305-310)
```csharp
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can update options.");
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), "Option doesn't exist.");
        votingItem.Options.Remove(input.Option);
        State.VotingItems[votingItem.VotingItemId] = votingItem;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L381-381)
```csharp
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
```

**File:** protobuf/vote_contract.proto (L162-167)
```text
message VotingResult {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The voting result, option -> amount of votes,
    map<string, int64> results = 2;
    // The snapshot number.
```

**File:** contract/AElf.Contracts.Vote/ViewMethods.cs (L27-32)
```csharp
    public override VotingItem GetVotingItem(GetVotingItemInput input)
    {
        var votingEvent = State.VotingItems[input.VotingItemId];
        Assert(votingEvent != null, "Voting item not found.");
        return votingEvent;
    }
```

**File:** contract/AElf.Contracts.Vote/ViewMethods.cs (L34-42)
```csharp
    public override VotingResult GetVotingResult(GetVotingResultInput input)
    {
        var votingResultHash = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = input.SnapshotNumber
        }.GetHash();
        return State.VotingResults[votingResultHash];
    }
```
