### Title
Voting Items Can Be Created With Zero Options, Rendering Them Unusable

### Summary
The `Register` method in VoteContract does not validate that the options array is non-empty, allowing voting items to be created with zero options. This renders the voting item completely unusable until the sponsor manually adds options, wasting blockchain resources and potentially blocking time-sensitive voting periods.

### Finding Description
The root cause is in the `Register` method which copies input options without validation. [1](#0-0) 

The validation method `AssertValidNewVotingItem` checks voting item uniqueness, timestamp validity, and snapshot numbers, but never validates that the options array contains at least one element. [2](#0-1) 

The protobuf definition allows empty options arrays with no minimum constraint. [3](#0-2) 

When users attempt to vote on a voting item with zero options, the vote will always fail at the validation check. [4](#0-3) 

This assertion requires the option to exist in `votingItem.Options`, but an empty collection will never contain any option, causing all vote attempts to fail until the sponsor adds options via `AddOption` or `AddOptions` methods.

Test evidence confirms that all normal use cases provide at least one option during registration. [5](#0-4) 

### Impact Explanation
**Operational Impact:**
- Voting items can be created in an invalid, unusable state
- Any vote attempt fails because `Options.Contains()` returns false for empty collections
- Blockchain storage and transaction fees are wasted on unusable voting items
- If created during an active voting period (between StartTimestamp and EndTimestamp), users cannot participate until the sponsor adds options
- Time-sensitive governance decisions may be delayed

**Affected Parties:**
- Users who want to vote but cannot until options are added
- Sponsors who waste transaction fees creating incomplete voting items
- The protocol which stores invalid state

**Severity:** Medium - This creates operational DoS conditions and violates the business logic invariant that voting items must have voteable options, but does not directly lead to fund theft or critical security breaches.

### Likelihood Explanation
**Attacker Capabilities:**
- Any user can call the public `Register` method
- No special permissions required beyond transaction fee payment

**Attack Complexity:**
- Trivial: Simply call `Register` with an empty options array
- No preconditions needed beyond having transaction fees

**Feasibility:**
- Immediately executable on any deployment
- Can be used for griefing by creating many unusable voting items
- Could be accidental (developer mistake) or intentional

**Economic Rationality:**
- Attack cost is only normal transaction fees
- Could cause significant disruption to governance processes at minimal cost

**Probability:** High - No technical barriers prevent this condition from occurring.

### Recommendation
Add validation in the `AssertValidNewVotingItem` method to enforce that at least one option must be provided:

```csharp
Assert(input.Options != null && input.Options.Count > 0, 
    "At least one option must be provided when registering a voting item.");
```

Additionally, consider adding an upper bound check alongside the existing maximum: [6](#0-5) 

**Test Cases to Add:**
1. Test that Register with empty options array is rejected
2. Test that Register with null options is rejected  
3. Test that Register with exactly 1 option succeeds
4. Test boundary conditions (0, 1, 64, 65 options)

### Proof of Concept
**Initial State:**
- VoteContract deployed and initialized
- User has sufficient tokens for transaction fees

**Exploit Steps:**
1. User calls `Register` with `VotingRegisterInput`:
   - `StartTimestamp`: current time
   - `EndTimestamp`: current time + 7 days  
   - `AcceptedCurrency`: "ELF"
   - `IsLockToken`: true
   - `Options`: [] (empty array)

2. Transaction succeeds, voting item is created with zero options

3. Any user attempting to vote receives error: "Option {input.Option} not found"

**Expected vs Actual:**
- **Expected:** Registration should fail with error "At least one option must be provided"
- **Actual:** Registration succeeds, creating an unusable voting item

**Success Condition:**
- Voting item exists in state with `Options.Count == 0`
- All subsequent vote attempts fail regardless of option value provided

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L49-49)
```csharp
            Options = { input.Options },
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L351-365)
```csharp
    private Hash AssertValidNewVotingItem(VotingRegisterInput input)
    {
        // Use input without options and sender's address to calculate voting item id.
        var votingItemId = input.GetHash(Context.Sender);

        Assert(State.VotingItems[votingItemId] == null, "Voting item already exists.");

        // total snapshot number can't be 0. At least one epoch is required.
        if (input.TotalSnapshotNumber == 0) input.TotalSnapshotNumber = 1;

        Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");

        Context.LogDebug(() => $"Voting item created by {Context.Sender}: {votingItemId.ToHex()}");

        return votingItemId;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L381-381)
```csharp
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
```

**File:** protobuf/vote_contract.proto (L87-104)
```text
message VotingRegisterInput {
    // The start time of the voting.
    google.protobuf.Timestamp start_timestamp = 1;
    // The end time of the voting.
    google.protobuf.Timestamp end_timestamp = 2;
    // The token symbol which will be accepted.
    string accepted_currency = 3;
    // Whether the vote will lock token.
    bool is_lock_token = 4;
    // The total number of snapshots of the vote.
    int64 total_snapshot_number = 5;
    // The list of options.
    repeated string options = 6;
    // Is quadratic voting.
    bool is_quadratic = 7;
    // Quadratic voting item ticket cost.
    int64 ticket_cost = 8;
}
```

**File:** test/AElf.Contracts.Vote.Tests/VoteContractTestHelper.cs (L38-38)
```csharp
            Options = { GenerateOptions(optionsCount) },
```

**File:** contract/AElf.Contracts.Vote/VoteContractConstants.cs (L5-5)
```csharp
    public const int MaximumOptionsCount = 64;
```
