# Audit Report

## Title
Vote Manipulation via Negative Amount in Delegated Voting

## Summary
The Vote contract accepts signed integer amounts without validating positivity for delegated voting scenarios where `IsLockToken = false`. This allows sponsors to vote with negative amounts, subtracting from vote counts, and enables double manipulation through withdrawals that add to counts instead of subtracting.

## Finding Description

The `Vote()` function accepts an `amount` parameter of type `int64` (signed integer) without validating it is positive for delegated voting scenarios. [1](#0-0) 

For non-quadratic voting, the amount is directly assigned from user input without validation: [2](#0-1) 

The `AssertValidVoteInput()` validation function checks that the sender is the sponsor for delegated voting but does NOT validate that the amount is positive: [3](#0-2) 

**Why Protections Fail:**

For locked token voting (`IsLockToken = true`), the token contract's `Lock()` method validates the amount through `AssertValidToken()`: [4](#0-3) 

The `AssertValidToken()` method properly validates that amounts are positive: [5](#0-4) 

However, for delegated voting (`IsLockToken = false`), the lock operation never occurs, bypassing this validation: [6](#0-5) 

**Attack Execution:**

When a sponsor votes with a negative amount, the `UpdateVotingResult()` method adds the negative value to vote counts: [7](#0-6) 

The `Add()` extension method performs `a + b` in checked context: [8](#0-7) 

Therefore, adding a negative amount (e.g., `1000 + (-1000) = 0`) effectively subtracts from the vote count.

**Double Manipulation on Withdrawal:**

When withdrawing a vote with negative amount, the contract subtracts the recorded negative amount: [9](#0-8) 

The `Sub()` method performs `a - b`: [10](#0-9) 

Since subtracting a negative equals adding (`a - (-b) = a + b`), withdrawing a negative vote ADDS to the vote count instead of subtracting, enabling a second manipulation.

## Impact Explanation

**High Severity** - This vulnerability breaks fundamental vote integrity guarantees:

1. **Vote Count Manipulation**: Sponsors can arbitrarily decrease vote counts by voting with negative amounts, directly manipulating election/governance outcomes

2. **Double Exploitation**: Withdrawing negative votes increases counts instead of decreasing them, allowing sponsors to add votes without legitimate voting action

3. **VotesAmount Corruption**: The total `VotesAmount` can become negative or arbitrary, breaking accounting invariants and potentially causing issues in dependent systems

4. **Zero Economic Cost**: Delegated voting requires no tokens, so attacks have no economic cost or barrier

5. **Governance Compromise**: Delegated voting is designed for off-chain oracle-style systems. This vulnerability allows complete manipulation of results that governance decisions may rely upon

While only sponsors can exploit this, sponsors are NOT in the trusted roles list (genesis method-fee provider, organization controllers, consensus system contracts). This is critical when sponsor keys are compromised, the sponsor is a vulnerable contract, or off-chain systems have bugs.

## Likelihood Explanation

**Medium Likelihood** - The attack is straightforward but requires specific preconditions:

**Attacker Capabilities:**
- Must be the sponsor of a delegated voting item [11](#0-10) 
- Can call the public `Vote()` function with crafted input

**Attack Complexity:**
LOW - Single transaction with negative amount parameter. No complex setup required.

**Preconditions:**
- Voting item must have `IsLockToken = false` (delegated voting)
- Attacker must be the sponsor
- No additional preconditions required

**Feasibility:**
While requiring sponsor privileges, this remains feasible because:
1. Sponsor keys can be compromised
2. Sponsors may be smart contracts with vulnerabilities
3. Off-chain systems may have bugs
4. No economic barrier exists

## Recommendation

Add explicit validation in `AssertValidVoteInput()` to check that amount is positive for all voting scenarios:

```csharp
private VotingItem AssertValidVoteInput(VoteInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
    Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
        "Current voting item already ended.");
    
    // Add validation for positive amount
    if (!votingItem.IsQuadratic)
    {
        Assert(input.Amount > 0, "Vote amount must be positive.");
    }
    
    if (!votingItem.IsLockToken)
    {
        Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
        Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
        Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    }
    else
    {
        var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
        var votingResult = State.VotingResults[votingResultHash];
        input.Voter = Context.Sender;
        input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
    }

    return votingItem;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task NegativeVoteAmount_ShouldNotSubtractFromVoteCounts()
{
    // Setup: Create a delegated voting item (IsLockToken = false)
    var sponsor = Accounts[0];
    var votingItemId = await RegisterDelegatedVotingItem(sponsor);
    
    // Initial vote with positive amount
    await VoteWithAmount(sponsor, votingItemId, "Option1", 1000);
    var result1 = await GetVotingResult(votingItemId);
    Assert.Equal(1000, result1.Results["Option1"]); // Should be 1000
    
    // Malicious vote with NEGATIVE amount
    await VoteWithAmount(sponsor, votingItemId, "Option1", -500);
    var result2 = await GetVotingResult(votingItemId);
    
    // BUG: Vote count decreased to 500 instead of rejecting negative amount
    Assert.Equal(500, result2.Results["Option1"]); // Vulnerability confirmed
    
    // Double manipulation: Withdraw the negative vote
    await WithdrawVote(sponsor, voteId);
    var result3 = await GetVotingResult(votingItemId);
    
    // BUG: Vote count increased to 1000 instead of decreasing
    Assert.Equal(1000, result3.Results["Option1"]); // Double manipulation confirmed
}
```

## Notes

This vulnerability specifically affects delegated voting scenarios (`IsLockToken = false`) because the token locking mechanism that normally validates positive amounts is bypassed. The validation in `AssertValidToken()` exists in the TokenContract but is never invoked for delegated voting. The issue stems from the Vote contract trusting that sponsors will only provide positive amounts, which is an incorrect security assumption for a public function that accepts signed integers.

### Citations

**File:** protobuf/vote_contract.proto (L141-141)
```text
    int64 amount = 3;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L94-96)
```csharp
        if (!votingItem.IsQuadratic)
        {
            amount = input.Amount;
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-222)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-389)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L207-207)
```csharp
        AssertValidToken(input.Symbol, input.Amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L100-106)
```csharp
    public static long Add(this long a, long b)
    {
        checked
        {
            return a + b;
        }
    }
```
