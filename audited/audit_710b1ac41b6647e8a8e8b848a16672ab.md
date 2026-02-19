### Title
VotersCount Permanent Inflation Due to Asymmetric Increment/Decrement Logic in Withdraw Function

### Summary
The Vote contract's `Withdraw()` function contains a critical logic error where `VotersCount` is only decremented when a voter has no remaining active votes, while the `Vote()` function increments `VotersCount` for every individual vote cast. This asymmetry allows any voter who casts multiple votes and withdraws them incrementally to permanently inflate the `VotersCount` metric, corrupting voting statistics used by the Election contract and governance systems.

### Finding Description
The vulnerability exists in the asymmetric handling of `VotersCount` between the voting and withdrawal operations:

**Vote Function - Per-Vote Increment:**
In `UpdateVotingResult()`, `VotersCount` is incremented by 1 for every vote cast, regardless of whether the voter has already voted on the same voting item. [1](#0-0) 

**Withdraw Function - Per-Voter Decrement:**
In `Withdraw()`, `VotersCount` is only decremented when the voter has NO active votes remaining for that voting item. The check at line 217 verifies if `ActiveVotes.Any()` is false before decrementing. [2](#0-1) 

**Root Cause:**
The increment logic operates per-transaction (every vote increments), while the decrement logic operates per-voter (only when all votes are withdrawn). This creates a mathematical imbalance where:
- N votes cast → VotersCount += N
- N votes withdrawn incrementally → VotersCount -= 1 (only on the last withdrawal)
- Net effect: VotersCount inflated by (N-1)

**Test Evidence:**
The test suite confirms that `VotersCount` tracks total vote transactions, not unique voters. When two users each vote twice, `VotersCount` reaches 4: [3](#0-2) 

### Impact Explanation
**Direct Impact:**
- `VotersCount` becomes permanently inflated and no longer reflects accurate voting statistics
- The Election contract's `GetVotersCount()` method returns corrupted data, affecting governance metrics [4](#0-3) 

**Cascading Effects:**
- Voting statistics displayed to users are misleading
- Governance decisions or analytics relying on voter participation metrics are corrupted
- The inflation persists across snapshot transitions, as `VotersCount` is carried forward [5](#0-4) 

**Who is Affected:**
- All users relying on voting statistics for governance decisions
- UI/frontend systems displaying voter counts
- Analytics systems tracking participation metrics
- Election contract consumers expecting accurate voter counts

**Severity Justification:**
Medium severity - While this doesn't directly result in fund theft, it corrupts critical governance state that is permanent and accumulates over time. The metric is publicly exposed and used by the Election contract, affecting the integrity of the voting system.

### Likelihood Explanation
**Attacker Capabilities:**
- Any user can vote multiple times on the same voting item (confirmed by test cases)
- No special privileges required - any address with sufficient token balance can exploit
- The withdrawal function is publicly accessible with only ownership checks

**Attack Complexity:**
- Trivial to execute: vote N times, then withdraw votes one by one
- No complex timing or state manipulation required
- Works under normal contract operation

**Feasibility Conditions:**
- Voting item must be active and accept multiple votes from same voter
- Attacker needs sufficient token balance for initial votes (tokens are returned on withdrawal)
- No economic barrier - the attack is cost-neutral since tokens are unlocked

**Detection Constraints:**
- The inflation is subtle and accumulates gradually
- No obvious transaction failure or error occurs
- The inflated count persists indefinitely across snapshots

**Probability:**
High - This occurs naturally whenever any user votes multiple times and withdraws incrementally, whether intentionally malicious or not. The behavior is inherent to the contract logic.

### Recommendation
**Fix the Decrement Logic:**
Modify the `Withdraw()` function to decrement `VotersCount` by 1 for EACH vote withdrawn, not just when all votes are withdrawn. The corrected logic should be:

```csharp
// Remove the conditional check - always decrement
votingResult.VotersCount = votingResult.VotersCount.Sub(1);
```

Replace lines 217-218 with an unconditional decrement to match the per-vote increment behavior.

**Invariant to Enforce:**
`VotersCount` must equal the total number of non-withdrawn voting records for a given snapshot. Add assertions to verify:
```csharp
Assert(votingResult.VotersCount >= 0, "VotersCount cannot be negative");
```

**Test Cases to Add:**
1. Test multiple votes from same voter followed by incremental withdrawals
2. Verify `VotersCount` returns to 0 when all votes are withdrawn
3. Test `VotersCount` accuracy across snapshot transitions with partial withdrawals
4. Validate that `VotersCount` matches the sum of active voting records

### Proof of Concept
**Initial State:**
- VotingItem A exists with current snapshot
- VotersCount = 0
- Alice has sufficient token balance

**Attack Steps:**
1. Alice calls `Vote()` on VotingItem A with 100 tokens
   - Transaction succeeds
   - VotersCount = 1
   - Alice's ActiveVotes = [vote1]

2. Alice calls `Vote()` again on VotingItem A with 200 tokens
   - Transaction succeeds
   - VotersCount = 2 (incremented again)
   - Alice's ActiveVotes = [vote1, vote2]

3. Alice calls `Withdraw(vote1)`
   - Transaction succeeds
   - Alice's ActiveVotes = [vote2] (still has active votes)
   - Check at line 217: `!ActiveVotes.Any()` evaluates to FALSE
   - VotersCount = 2 (NOT decremented)

4. Alice calls `Withdraw(vote2)`
   - Transaction succeeds
   - Alice's ActiveVotes = [] (now empty)
   - Check at line 217: `!ActiveVotes.Any()` evaluates to TRUE
   - VotersCount = 1 (decremented by 1)

**Expected Result:**
VotersCount should be 0 (Alice has no active votes)

**Actual Result:**
VotersCount = 1 (permanently inflated)

**Success Condition:**
Query `GetVotingResult()` and observe VotersCount = 1 despite no active votes from Alice, confirming the permanent inflation.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L207-222)
```csharp
        var votingResultHash = GetVotingResultHash(votingRecord.VotingItemId, votingRecord.SnapshotNumber);

        var votedItems = State.VotedItemsMap[votingRecord.Voter];
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].ActiveVotes.Remove(input.VoteId);
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].WithdrawnVotes.Add(input.VoteId);
        State.VotedItemsMap[votingRecord.Voter] = votedItems;

        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L262-272)
```csharp
        // Initial next voting going information.
        var currentVotingGoingHash = GetVotingResultHash(input.VotingItemId, nextSnapshotNumber);
        State.VotingResults[currentVotingGoingHash] = new VotingResult
        {
            VotingItemId = input.VotingItemId,
            SnapshotNumber = nextSnapshotNumber,
            SnapshotStartTimestamp = Context.CurrentBlockTime,
            VotersCount = previousVotingResult.VotersCount,
            VotesAmount = previousVotingResult.VotesAmount
        };
        return new Empty();
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L606-624)
```csharp
    [Fact]
    public async Task VoteContract_GetLatestVotingResult_Test()
    {
        var voteUser1 = Accounts[2].KeyPair;
        var voteUser2 = Accounts[3].KeyPair;
        var votingItem = await RegisterVotingItemAsync(10, 3, true, DefaultSender, 2);

        await Vote(voteUser1, votingItem.VotingItemId, votingItem.Options.First(), 100L);
        await Vote(voteUser1, votingItem.VotingItemId, votingItem.Options.First(), 200L);
        var votingResult = await GetLatestVotingResult(votingItem.VotingItemId);
        votingResult.VotersCount.ShouldBe(2);
        votingResult.VotesAmount.ShouldBe(300L);

        await Vote(voteUser2, votingItem.VotingItemId, votingItem.Options.Last(), 100L);
        await Vote(voteUser2, votingItem.VotingItemId, votingItem.Options.Last(), 200L);
        votingResult = await GetLatestVotingResult(votingItem.VotingItemId);
        votingResult.VotersCount.ShouldBe(4);
        votingResult.VotesAmount.ShouldBe(600L);
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L224-230)
```csharp
    public override Int64Value GetVotersCount(Empty input)
    {
        return new Int64Value
        {
            Value = State.VoteContract.GetLatestVotingResult.Call(State.MinerElectionVotingItemId.Value).VotersCount
        };
    }
```
