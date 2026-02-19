### Title
Quadratic Voting Results Corruption Due to Inconsistent Amount Tracking

### Summary
The Vote contract has a critical inconsistency in how it tracks quadratic voting results. During voting, it increments the Results map by 1 (vote count), but during withdrawal, it decrements by the token amount. This causes voting results to become negative and completely corrupts the voting tallies for quadratic voting items.

### Finding Description

The vulnerability exists in the Vote contract's handling of quadratic voting in two key functions:

**During Voting (`Vote` function):** [1](#0-0) 

For quadratic voting, the `amount` variable is calculated as `votingItem.TicketCost.Mul(currentVotesCount)`, representing the token amount to be locked. However: [2](#0-1) 

The `UpdateVotingResult` is called with `1` (vote count) instead of `amount` (token amount) for quadratic voting.

**In UpdateVotingResult:** [3](#0-2) 

This increments `Results[option]` and `VotesAmount` by the passed parameter (which is `1` for quadratic voting).

**During Withdrawal:** [4](#0-3) 

The withdrawal decrements both `Results[option]` and `VotesAmount` by `votingRecord.Amount`, which is the token amount (not 1).

**The VotingRecord stores the token amount:** [5](#0-4) 

This creates a fundamental mismatch: the Results map is incremented by 1 during voting but decremented by potentially large token amounts during withdrawal.

### Impact Explanation

**Concrete Harm:**
- Voting results become negative or severely underflow after withdrawals
- The `Results` map (which shows votes per option) displays incorrect tallies
- The `VotesAmount` field becomes corrupted
- Quadratic voting feature is completely broken and unusable
- Any governance or decision-making relying on these vote results will be based on corrupted data

**Example Scenario:**
1. User votes quadratically with `ticketCost = 100`
2. First vote: `Results["OptionA"] += 1`, locks 100 tokens
3. Second vote: `Results["OptionA"] += 1`, locks 200 tokens (total: `Results = 2`, locked = 300)
4. Withdraw second vote: `Results["OptionA"] -= 200` → **Results = -198** (NEGATIVE!)

**Who is Affected:**
- All users participating in quadratic voting items
- Voting item sponsors who rely on accurate vote counts
- Any downstream contracts or systems depending on vote results

**Severity:** Critical - renders quadratic voting completely non-functional and produces corrupted data.

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required - any regular user can trigger this
- Simply requires participating in a quadratic voting item and later withdrawing

**Attack Complexity:**
- Extremely low - happens during normal voting and withdrawal operations
- No sophisticated setup or timing requirements needed

**Feasibility Conditions:**
- Voting item must have `IsQuadratic = true` [6](#0-5) 
- User performs normal vote and withdrawal operations

**Detection/Operational Constraints:**
- Bug manifests immediately upon first withdrawal in a quadratic voting item
- Easily observable through negative or incorrect vote tallies

**Probability:** Very High - occurs automatically in any quadratic voting scenario with withdrawals.

### Recommendation

**Code-level Mitigation:**
Change line 119 to pass `amount` instead of the conditional expression:

```csharp
UpdateVotingResult(votingItem, input.Option, amount);
```

This ensures consistency: both voting and withdrawal will use the token amount for all voting types (quadratic and non-quadratic).

**Invariant Checks:**
Add an assertion in `UpdateVotingResult` to ensure Results never goes negative:
```csharp
Assert(votingResult.Results[option] >= 0, "Vote results cannot be negative");
Assert(votingResult.VotesAmount >= 0, "Votes amount cannot be negative");
```

**Test Cases:**
1. Create a quadratic voting item with `ticketCost = 100`
2. Cast multiple votes from the same voter (delegated mode) or different voters
3. Withdraw votes and verify `Results[option]` and `VotesAmount` remain non-negative and accurate
4. Verify that Results equals the sum of all locked token amounts for that option

### Proof of Concept

**Initial State:**
- Quadratic voting item registered with `ticketCost = 100`, `IsLockToken = false` (delegated mode)
- Option "OptionA" exists

**Attack Sequence:**

1. **First Vote (VoteId = "vote1"):**
   - Call `Vote(votingItemId, voter=Alice, voteId="vote1", option="OptionA", amount=ignored)`
   - `QuadraticVotesCountMap["vote1"]` = 0 + 1 = 1
   - `amount` = 100 * 1 = 100
   - `VotingRecord.Amount` = 100
   - `UpdateVotingResult` called with `1`
   - **Result: `Results["OptionA"]` = 1, `VotesAmount` = 1**

2. **Second Vote (same VoteId):**
   - Call `Vote(votingItemId, voter=Alice, voteId="vote1", option="OptionA", amount=ignored)`
   - `QuadraticVotesCountMap["vote1"]` = 1 + 1 = 2
   - `amount` = 100 * 2 = 200
   - `VotingRecord.Amount` = 200
   - `UpdateVotingResult` called with `1`
   - **Result: `Results["OptionA"]` = 2, `VotesAmount` = 2**

3. **Withdraw Second Vote:**
   - Call `Withdraw(voteId="vote1")`
   - Retrieves `VotingRecord.Amount` = 200
   - `Results["OptionA"]` = 2 - 200 = **-198**
   - `VotesAmount` = 2 - 200 = **-198**

**Expected Result:** 
Results should remain positive and reflect actual locked token amounts.

**Actual Result:**
Results become negative (-198), completely corrupting the voting tally.

**Success Condition:**
Query `GetVotingResult` and observe negative values in `Results["OptionA"]` and `VotesAmount` fields.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L50-51)
```csharp
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L94-103)
```csharp
        if (!votingItem.IsQuadratic)
        {
            amount = input.Amount;
        }
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L105-115)
```csharp
        var votingRecord = new VotingRecord
        {
            VotingItemId = input.VotingItemId,
            Amount = amount,
            SnapshotNumber = votingItem.CurrentSnapshotNumber,
            Option = input.Option,
            IsWithdrawn = false,
            VoteTimestamp = Context.CurrentBlockTime,
            Voter = input.Voter,
            IsChangeTarget = input.IsChangeTarget
        };
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
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
