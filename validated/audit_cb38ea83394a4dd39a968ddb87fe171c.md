# Audit Report

## Title
Quadratic Voting Cost Progression Broken for Locked Token Voting

## Summary
The Vote contract's quadratic voting implementation fails to enforce progressive cost increases when `IsLockToken` is true. Each vote generates a unique `VoteId` based on the accumulating `VotesAmount`, causing the `QuadraticVotesCountMap` to reset for each vote. This results in constant cost (`TicketCost * 1`) instead of the intended quadratic progression (`TicketCost * 1, 2, 3...`), completely defeating quadratic voting's vote-buying resistance.

## Finding Description

The vulnerability exists in the interaction between VoteId generation and quadratic cost tracking.

**Root Cause:**

For locked token voting (`IsLockToken=true`), the `VoteId` is generated using the current `VotesAmount` from the voting result: [1](#0-0) 

Since `VotesAmount` increases with each vote, every vote generates a unique `VoteId`. The quadratic cost calculation uses this `VoteId` as the key: [2](#0-1) 

The map tracking is defined as: [3](#0-2) 

**Execution Flow:**

1. **First vote:** `VotesAmount = 0` → `VoteId_1 = GenerateId(..., 0.ToBytes())` → `QuadraticVotesCountMap[VoteId_1] = 1` → `cost = TicketCost * 1`
2. **Second vote:** `VotesAmount = TicketCost` → `VoteId_2 = GenerateId(..., TicketCost.ToBytes())` → `QuadraticVotesCountMap[VoteId_2] = 1` (new key!) → `cost = TicketCost * 1` (same!)
3. Pattern continues - each vote costs `TicketCost * 1`

The `VotesAmount` update after each vote: [4](#0-3) 

**Why Protections Fail:**

The `Register` method accepts both flags without validation: [5](#0-4) 

The validation function does not check for incompatible flag combinations: [6](#0-5) 

## Impact Explanation

**Token Economics Manipulation:**
- Voters acquire unlimited votes at constant cost instead of quadratic cost
- Expected cost for N votes: `TicketCost * (1+2+...+N) = TicketCost * N(N+1)/2` ≈ O(N²)
- Actual cost: `TicketCost * N` = O(N)

**Quantified Damage:**
For 100 votes with `TicketCost=1000`:
- **Intended cost:** 1,000 × 5,050 = 5,050,000 tokens
- **Actual cost:** 1,000 × 100 = 100,000 tokens
- **Savings:** 4,950,000 tokens (98% discount!)

**Governance Integrity Compromise:**
- Wealthy actors can cheaply dominate any voting item with both flags enabled
- Nullifies quadratic voting's vote-buying resistance
- Creates unfair advantage for voters who understand the exploit vs honest voters

## Likelihood Explanation

**Attacker Capabilities:**
- Any address can call `Register` (public method) [7](#0-6) 
- Any address can call `Vote` (public method) [8](#0-7) 

**Attack Complexity:**
- **Trivial:** Two transactions: `Register(IsQuadratic=true, IsLockToken=true, TicketCost=X)` then multiple `Vote()` calls
- No sophisticated contract interactions needed
- Attacker controls all parameters

**Feasibility:**
- Public methods accessible to all
- No validation prevents the flag combination
- No economic barriers
- Works in current contract state

**Probability:** VERY HIGH - Exploitable in every voting item where both flags are true.

## Recommendation

**Option 1: Prohibit the Incompatible Combination**
Add validation in `AssertValidNewVotingItem` to reject voting items with both `IsQuadratic=true` and `IsLockToken=true`:

```csharp
Assert(!(input.IsQuadratic && input.IsLockToken), 
    "Quadratic voting is not supported with locked token voting.");
```

**Option 2: Fix VoteId Generation for Locked Token Quadratic Voting**
Generate VoteId based on voter address and voting item instead of VotesAmount:

```csharp
// In AssertValidVoteInput, for IsLockToken=true case:
input.VoteId = Context.GenerateId(Context.Self, 
    HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender),
        votingItem.VotingItemId
    ).ToBytes());
```

Then track per-voter vote counts in a separate map structure.

**Recommended:** Option 1 is simpler and safer until proper per-voter tracking is implemented.

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_ConstantCost_Exploit()
{
    // Register quadratic voting item with locked tokens
    var startTime = TimestampHelper.GetUtcNow();
    var ticketCost = 1000;
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(100),
        StartTimestamp = startTime,
        Options = { "Option1", "Option2" },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true,
        IsQuadratic = true,
        TicketCost = ticketCost
    };
    
    await VoteContractStub.Register.SendAsync(input);
    input.Options.Clear();
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(input), 
        HashHelper.ComputeFrom(DefaultSender));
    
    var voter = Accounts[11].KeyPair;
    
    // First vote - should cost 1000 * 1 = 1000
    await Vote(voter, votingItemId, "Option1", 0);
    var result1 = await GetVotingResult(votingItemId, 1);
    result1.VotesAmount.ShouldBe(1000); // Cost: 1000
    
    // Second vote - should cost 1000 * 2 = 2000, but actually costs 1000!
    await Vote(voter, votingItemId, "Option1", 0);
    var result2 = await GetVotingResult(votingItemId, 1);
    result2.VotesAmount.ShouldBe(2000); // Total: 2000 (should be 3000!)
    
    // Third vote - should cost 1000 * 3 = 3000, but actually costs 1000!
    await Vote(voter, votingItemId, "Option1", 0);
    var result3 = await GetVotingResult(votingItemId, 1);
    result3.VotesAmount.ShouldBe(3000); // Total: 3000 (should be 6000!)
    
    // Expected for 3 votes: 1000 + 2000 + 3000 = 6000
    // Actual cost: 1000 + 1000 + 1000 = 3000
    // Attacker saves 50%!
}
```

## Notes

This vulnerability completely breaks the quadratic voting mechanism for locked token voting. The issue stems from using the cumulative `VotesAmount` to generate unique VoteIds, which causes the quadratic vote counter to reset for each vote. The lack of validation allowing both `IsQuadratic` and `IsLockToken` flags together enables this exploit. No tests exist for quadratic voting functionality in the codebase, suggesting this feature was never properly validated.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-20)
```csharp
    public override Empty Register(VotingRegisterInput input)
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L42-51)
```csharp
            IsLockToken = input.IsLockToken,
            TotalSnapshotNumber = input.TotalSnapshotNumber,
            CurrentSnapshotNumber = 1,
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
            RegisterTimestamp = Context.CurrentBlockTime,
            Options = { input.Options },
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-90)
```csharp
    public override Empty Vote(VoteInput input)
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L100-102)
```csharp
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L179-179)
```csharp
        votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L351-366)
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
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L392-397)
```csharp
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
```

**File:** contract/AElf.Contracts.Vote/VoteContractState.cs (L30-33)
```csharp
    /// <summary>
    ///     Vote Id -> Votes Count
    /// </summary>
    public MappedState<Hash, long> QuadraticVotesCountMap { get; set; }
```
