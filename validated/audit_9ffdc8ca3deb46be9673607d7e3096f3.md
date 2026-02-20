# Audit Report

## Title
Broken Quadratic Voting Mechanism Allows Vote Manipulation with Minimal Token Cost

## Summary
The VoteContract's quadratic voting implementation is fundamentally broken because VoteId generation is based on the cumulative `VotesAmount`, which changes after each vote. This causes each new vote to receive a unique VoteId, preventing the `QuadraticVotesCountMap` from accumulating vote counts per user. As a result, every vote costs only the fixed `TicketCost` instead of quadratically increasing costs, completely defeating the Sybil resistance mechanism.

## Finding Description

The vulnerability stems from the interaction between VoteId generation and quadratic cost calculation in the VoteContract.

**Root Cause 1: Broken VoteId Generation**

When a user votes on a quadratic voting item with `IsLockToken=true`, the VoteId is auto-generated based on the **current total votes amount**: [1](#0-0) 

The critical flaw is that `votingResult.VotesAmount` increases after each vote: [2](#0-1) 

This means every subsequent vote by the same user generates a **different VoteId** because the global `VotesAmount` has changed.

**Root Cause 2: Broken Cost Calculation**

When the quadratic cost is calculated: [3](#0-2) 

Since each vote transaction generates a unique VoteId (due to the changing `VotesAmount`), the lookup `State.QuadraticVotesCountMap[input.VoteId]` always returns 0 for new VoteIds. This makes `currentVotesCount = 0 + 1 = 1` for every vote, so `amount` is always `TicketCost * 1`, never increasing quadratically.

**Root Cause 3: Zero-Cost Delegated Voting**

For delegated voting (`IsLockToken=false`), token locking is entirely skipped: [4](#0-3) 

The sponsor can vote unlimited times on behalf of users without locking any tokens.

**Missing Validation**

The `Register()` function accepts `TicketCost` without any validation: [5](#0-4) 

This allows attackers to register voting items with `TicketCost=1` or even `TicketCost=0`.

## Impact Explanation

**Direct Governance Manipulation:**
- An attacker can register a quadratic voting item with `TicketCost=1` token
- For `IsLockToken=true`: Accumulate 100 votes by locking only 100 tokens (instead of 5,050 tokens under true quadratic voting where costs are 1+2+3+...+100)
- For `IsLockToken=false`: Accumulate unlimited votes at zero token cost
- This represents a **98% cost reduction** compared to legitimate quadratic voting

**Quantified Impact:**
- With `TicketCost=1` and 1,000 votes needed to win a governance decision:
  - Legitimate quadratic cost: 500,500 tokens (sum of 1 to 1,000)
  - Actual cost under this bug: 1,000 tokens (`IsLockToken=true`) or 0 tokens (`IsLockToken=false`)
  - **99.8% cost reduction** enables cheap vote manipulation

**Severity Justification:**
- **HIGH severity** due to direct governance compromise
- Breaks the fundamental security assumption of quadratic voting (Sybil resistance)
- Any governance system relying on this VoteContract for quadratic voting can be manipulated with minimal economic barrier
- Legitimate voters are disadvantaged as attackers pay far less per vote

## Likelihood Explanation

**Attacker Capabilities:**
- Any user can call the public `Register()` function with arbitrary `TicketCost` value
- Any user can call `Vote()` multiple times on their own voting item
- No special privileges required

**Attack Complexity:**
- **Trivial**: Single `Register()` call with `TicketCost=1`, followed by multiple `Vote()` calls
- No complex state manipulation or timing requirements needed
- The bug is inherent in the design, not dependent on specific conditions

**Feasibility:**
- Works immediately after contract deployment
- Attacker needs minimal tokens (as low as 1 token per vote for `IsLockToken=true`, or 0 for `IsLockToken=false`)
- No dependency on external conditions or compromised trusted roles

**Probability: VERY HIGH**
- Attack is economically rational (cheap manipulation)
- Technically simple to execute
- Immediately exploitable on any deployed VoteContract using quadratic voting

## Recommendation

**Fix 1: Use Per-User VoteId Generation**

Instead of basing VoteId on the global `VotesAmount`, generate it based on user-specific data:

```csharp
// In AssertValidVoteInput(), replace line 397 with:
input.VoteId = Context.GenerateId(Context.Self, 
    HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender),
        HashHelper.ComputeFrom(votingItem.VotingItemId),
        HashHelper.ComputeFrom(Context.CurrentBlockTime)
    ).ToByteArray());
```

This ensures each user gets a unique VoteId per voting session, allowing proper accumulation in `QuadraticVotesCountMap`.

**Fix 2: Track Per-User Vote Counts**

Add a new state mapping to track votes per user per voting item:

```csharp
// In VoteContractState.cs:
public MappedState<Hash, MappedState<Address, long>> UserVoteCountMap { get; set; }

// In Vote() method, replace lines 100-102 with:
var userKey = HashHelper.ConcatAndCompute(
    HashHelper.ComputeFrom(votingItem.VotingItemId),
    HashHelper.ComputeFrom(input.Voter)
);
var currentVotesCount = State.UserVoteCountMap[userKey][input.Voter].Add(1);
State.UserVoteCountMap[userKey][input.Voter] = currentVotesCount;
amount = votingItem.TicketCost.Mul(currentVotesCount);
```

**Fix 3: Validate TicketCost**

Add minimum value validation in `Register()`:

```csharp
// After line 51:
Assert(input.TicketCost > 0, "TicketCost must be greater than zero.");
Assert(input.TicketCost >= VoteContractConstants.MinimumTicketCost, 
    "TicketCost below minimum threshold.");
```

## Proof of Concept

**Attack Scenario:**
1. Attacker registers a quadratic voting item with `TicketCost=1` and `IsLockToken=true`
2. Attacker votes 10 times on their own voting item
3. Expected cost: 1+2+3+4+5+6+7+8+9+10 = 55 tokens
4. Actual cost: 10 votes × 1 token = 10 tokens (82% reduction)

**Expected Test Result:**
- Each successive vote should cost more: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 tokens
- Actual result: Each vote costs 1 token due to unique VoteId generation

The vulnerability is confirmed by the code analysis showing that `votingResult.VotesAmount` changes after each vote (line 179), causing VoteId generation (line 397) to produce different values for each vote, which prevents `QuadraticVotesCountMap` from accumulating vote counts per user.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L50-52)
```csharp
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
        };
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L98-103)
```csharp
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L122-130)
```csharp
        if (votingItem.IsLockToken)
            // Lock voted token.
            State.TokenContract.Lock.Send(new LockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                LockId = input.VoteId,
                Amount = amount
            });
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
