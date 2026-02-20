# Audit Report

## Title
Quadratic Voting Implementation Broken - All Votes Cost Same Amount Due to Incorrect Vote Count Tracking

## Summary
The quadratic voting mechanism in the Vote contract is fundamentally broken because `QuadraticVotesCountMap` is keyed by `VoteId`, which changes with every vote. This causes each vote to start with a fresh counter at zero instead of accumulating, resulting in all votes costing a flat `TicketCost × 1` instead of the intended progressive quadratic cost (1x, 2x, 3x, etc.).

## Finding Description

The quadratic voting security mechanism is designed to prevent plutocracy by making each subsequent vote exponentially more expensive. However, the implementation tracks vote counts incorrectly.

The `QuadraticVotesCountMap` is keyed by `VoteId`: [1](#0-0) 

During vote processing, the `VoteId` is generated using the current `VotesAmount` value: [2](#0-1) 

The quadratic cost calculation retrieves the count for this VoteId: [3](#0-2) 

After each vote, `VotesAmount` is incremented: [4](#0-3) 

**The Critical Flaw:** Since `VoteId` is generated using `VotesAmount` (which changes after each vote), every vote by the same voter generates a different `VoteId`. This means `QuadraticVotesCountMap[VoteId]` will always be a fresh entry starting at 0, so after incrementing by 1, every vote costs `TicketCost × 1`.

**Execution Flow:**
1. **First vote:** VotesAmount=0 → VoteId₁ = Hash(contract_address, "0") → QuadraticVotesCountMap[VoteId₁] = 0+1 = 1 → cost = TicketCost × 1
2. **Second vote:** VotesAmount=TicketCost → VoteId₂ = Hash(contract_address, "TicketCost") (different!) → QuadraticVotesCountMap[VoteId₂] = 0+1 = 1 → cost = TicketCost × 1 (should be 2×!)
3. **Nth vote:** Always creates new VoteId → Always costs TicketCost × 1

The map should be keyed by `(Voter, VotingItemId, SnapshotNumber)` to properly track cumulative votes per voter per voting session. Multiple votes by the same voter are allowed by design in the AElf Vote contract.

## Impact Explanation

**Severity: High** - This completely negates the fundamental security mechanism of quadratic voting.

Quadratic voting is designed to prevent plutocracy by making it exponentially more expensive to dominate voting outcomes. The intended cost progression is:
- 1st vote: TicketCost × 1
- 2nd vote: TicketCost × 2  
- 3rd vote: TicketCost × 3
- Total for N votes: TicketCost × (1+2+3+...+N) = TicketCost × N(N+1)/2

**With this bug:**
- Every vote costs: TicketCost × 1
- Total for N votes: TicketCost × N

**Concrete Impact:**
- A voter wanting 100 votes should pay: TicketCost × 5,050
- Instead they pay: TicketCost × 100 (50× cheaper!)
- For 1000 votes: should pay TicketCost × 500,500, actually pays TicketCost × 1,000 (500× cheaper!)

**Protocol Damage:**
- Wealthy voters can buy disproportionate voting power cheaply
- Governance becomes plutocratic (money-based) instead of quadratic (preference-intensity-based)
- All decisions made through quadratic voting are invalidated
- The core security property that distinguishes quadratic voting from simple token-weighted voting is completely broken

The vulnerability affects all voting items where `IsQuadratic = true`: [5](#0-4) 

## Likelihood Explanation

**Likelihood: Certain** - This bug triggers automatically for every quadratic vote.

**Attacker Capabilities:** Any user can call the public `Vote()` method: [6](#0-5) 

**Attack Complexity:** Trivial - simply call `Vote()` multiple times on the same quadratic voting item. Each subsequent call will cost the same flat `TicketCost` instead of increasing quadratically.

**Preconditions:** Only requires:
- A voting item registered with `IsQuadratic = true`
- The voting item must be active (within start/end timestamps)

The bug is inherent in the design - there are no special conditions, timing windows, or state manipulations required. Every single quadratic vote in the system suffers from this issue.

**Economic Rationality:** Exploiting this provides maximum voting power for minimum cost with no downside. A rational voter would always exploit this to maximize their influence.

## Recommendation

Change the `QuadraticVotesCountMap` key from `VoteId` to a composite key that tracks per-voter vote counts:

```csharp
// In VoteContractState.cs, replace:
public MappedState<Hash, long> QuadraticVotesCountMap { get; set; }

// With a composite key structure:
public MappedState<Address, Hash, long, long> QuadraticVotesCountPerVoter { get; set; }
// Key structure: [Voter][VotingItemId][SnapshotNumber] -> VoteCount

// In VoteContract.cs Vote() method, replace lines 100-102:
var quadraticKey = HashHelper.ConcatAndCompute(
    HashHelper.ComputeFrom(input.Voter),
    input.VotingItemId,
    HashHelper.ComputeFrom(votingItem.CurrentSnapshotNumber)
);
var currentVotesCount = State.QuadraticVotesCountPerVoter[input.Voter][input.VotingItemId][votingItem.CurrentSnapshotNumber].Add(1);
State.QuadraticVotesCountPerVoter[input.Voter][input.VotingItemId][votingItem.CurrentSnapshotNumber] = currentVotesCount;
amount = votingItem.TicketCost.Mul(currentVotesCount);
```

This ensures that each voter's vote count accumulates properly across multiple votes on the same voting item and snapshot, implementing the correct quadratic cost progression.

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_MultipleVotes_ShouldIncreaseCostvProgressively()
{
    // Register a quadratic voting item
    var votingItemId = await RegisterQuadraticVotingItem(ticketCost: 100);
    
    var voter = Accounts[0].Address;
    var initialBalance = 10000;
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = voter,
        Symbol = "ELF",
        Amount = initialBalance
    });
    
    // First vote - should cost 100 (1 × ticketCost)
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "OptionA",
        Amount = 0 // Ignored for quadratic
    });
    var balanceAfterVote1 = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput { Owner = voter, Symbol = "ELF" });
    Assert.Equal(initialBalance - 100, balanceAfterVote1.Balance);
    
    // Second vote - should cost 200 (2 × ticketCost) but actually costs 100!
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "OptionA",
        Amount = 0
    });
    var balanceAfterVote2 = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput { Owner = voter, Symbol = "ELF" });
    
    // Expected: initialBalance - 100 - 200 = 9700
    // Actual: initialBalance - 100 - 100 = 9800 (BUG!)
    Assert.Equal(9800, balanceAfterVote2.Balance); // This proves the vulnerability
    // Should be: Assert.Equal(9700, balanceAfterVote2.Balance);
}
```

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContractState.cs (L30-33)
```csharp
    /// <summary>
    ///     Vote Id -> Votes Count
    /// </summary>
    public MappedState<Hash, long> QuadraticVotesCountMap { get; set; }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-90)
```csharp
    public override Empty Vote(VoteInput input)
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L392-397)
```csharp
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
```
