# Audit Report

## Title
Vote Manipulation via Negative Amount in Delegated Voting

## Summary
The Vote contract fails to validate that the `amount` parameter is positive for delegated voting scenarios (`IsLockToken = false`). This allows the voting sponsor to manipulate vote results by voting with negative amounts, which subtracts from vote counts instead of adding. Withdrawing such negative votes further corrupts results by adding to vote counts instead of subtracting.

## Finding Description

The `Vote()` function accepts an `amount` parameter of type `int64` (signed integer) without validating positivity for delegated voting. [1](#0-0) 

For non-quadratic voting, the amount is directly assigned from user input without validation: [2](#0-1) 

The `AssertValidVoteInput()` function validates voting item existence, option validity, and authorization, but does NOT check if `amount` is positive: [3](#0-2) 

**Why Token Contract Protection Fails:**

For locked token voting (`IsLockToken = true`), the MultiToken contract's `Lock()` method validates the amount through `AssertValidToken()`, which calls `AssertValidSymbolAndAmount()` that enforces `amount > 0`: [4](#0-3) 

The Lock validation is invoked here: [5](#0-4) 

However, for delegated voting (`IsLockToken = false`), the Lock operation is completely bypassed, so token contract validation never occurs: [6](#0-5) 

**Attack Execution Path:**

When `UpdateVotingResult()` is called with a negative amount, it uses the SafeMath `Add()` extension: [7](#0-6) 

The `Add()` method performs standard addition in checked context: [8](#0-7) 

Therefore, adding a negative amount (e.g., `1000 + (-1000) = 0`) effectively subtracts from the vote count.

**Double Manipulation on Withdrawal:**

When withdrawing, the contract subtracts the recorded amount using SafeMath `Sub()`: [9](#0-8) 

The `Sub()` method performs standard subtraction: [10](#0-9) 

Subtracting a negative amount (e.g., `result - (-1000) = result + 1000`) adds to the vote count instead of subtracting, enabling further manipulation.

**Authorization Confirms Sponsor-Only Access:**

For delegated voting, only the sponsor can call `Vote()`: [11](#0-10) 

And only the sponsor can call `Withdraw()` for delegated votes: [12](#0-11) 

## Impact Explanation

**Critical Governance Integrity Breach:**
- **Vote Count Manipulation**: Sponsor can arbitrarily decrease any option's vote count by voting with negative amounts (e.g., voting with -1000 subtracts 1000 votes)
- **Double Exploitation**: Withdrawing negative votes increases vote counts, allowing cumulative manipulation across multiple vote-withdraw cycles
- **State Corruption**: The total `VotesAmount` can become negative or arbitrary, breaking fundamental accounting invariants
- **VotersCount Inconsistency**: The voter count increases even with negative vote amounts, creating logical inconsistencies

**Affected Systems:**
- All participants in delegated voting systems rely on vote count integrity for decision-making
- Governance decisions that depend on delegated vote results can be completely subverted
- Any off-chain systems or contracts that trust Vote contract results for oracle-style data feeds

**Severity Justification:**
While only the sponsor can exploit this, the sponsor is not a trusted privileged role in the system design. Sponsors should not have the power to arbitrarily manipulate vote counts. This is especially critical when:
- The sponsor's private key is compromised
- The sponsor is a smart contract with exploitable logic
- The sponsor's off-chain vote aggregation system has bugs generating negative amounts
- Delegated voting is used in trustless scenarios where sponsors are semi-adversarial

## Likelihood Explanation

**Attacker Profile:**
- Must be the sponsor of a delegated voting item (`IsLockToken = false`)
- Can call the public `Vote()` function with crafted negative amounts

**Attack Complexity:**
**LOW** - Single transaction attack with minimal setup:
1. Register voting item with `IsLockToken = false` 
2. Call `Vote()` with negative `Amount` parameter
3. Optionally call `Withdraw()` to further manipulate results

**Preconditions:**
- Voting item must have `IsLockToken = false` (delegated voting mode)
- Attacker must be the sponsor (enforced by authorization check)
- No additional economic or technical barriers exist

**Economic Cost:**
**ZERO** - Delegated voting requires no token locks or payments, making the attack completely free to execute repeatedly.

**Detection Difficulty:**
Negative amounts in vote records could appear as legitimate entries unless vote record state is specifically audited for sign validation.

## Recommendation

Add explicit validation in `AssertValidVoteInput()` to ensure the amount is positive:

```csharp
private VotingItem AssertValidVoteInput(VoteInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
    Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
        "Current voting item already ended.");
    
    // ADD THIS VALIDATION
    if (!votingItem.IsQuadratic)
    {
        Assert(input.Amount > 0, "Invalid amount. Amount must be positive.");
    }
    
    if (!votingItem.IsLockToken)
    {
        Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
        Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
        Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    }
    else
    {
        // ... existing logic ...
    }
    
    return votingItem;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task VoteContract_NegativeAmount_Manipulation_Test()
{
    // Register delegated voting item (IsLockToken = false)
    var votingItem = await RegisterVotingItemAsync(10, 2, false, DefaultSender, 1);
    
    // Sponsor votes with NEGATIVE amount
    var voteResult = await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Amount = -1000,  // Negative amount!
        Option = votingItem.Options[0],
        Voter = Accounts[1].Address,
        VoteId = HashHelper.ComputeFrom("vote1")
    });
    
    // Verify vote succeeded (should fail but doesn't due to missing validation)
    voteResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Check voting result - vote count should be negative (corrupted state)
    var result = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = votingItem.VotingItemId,
        SnapshotNumber = 1
    });
    
    result.Results[votingItem.Options[0]].ShouldBe(-1000); // Vote count is negative!
    result.VotesAmount.ShouldBe(-1000); // Total votes amount is negative!
    
    // Withdraw the negative vote - this ADDS to vote count instead of subtracting
    var withdrawResult = await VoteContractStub.Withdraw.SendAsync(new WithdrawInput
    {
        VoteId = HashHelper.ComputeFrom("vote1")
    });
    
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Check result after withdrawal - vote count becomes 0 instead of remaining negative
    var resultAfterWithdraw = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = votingItem.VotingItemId,
        SnapshotNumber = 1
    });
    
    // Proves double manipulation: -1000 - (-1000) = 0 instead of expected behavior
    resultAfterWithdraw.Results[votingItem.Options[0]].ShouldBe(0);
}
```

## Notes

This vulnerability demonstrates a critical missing input validation that bypasses the defense-in-depth provided by the MultiToken contract. While the token contract properly validates amounts for locked voting, the Vote contract must independently validate amounts for delegated voting scenarios where token locking is intentionally skipped. The sponsor role, while having legitimate administrative privileges, should never have the power to arbitrarily manipulate vote arithmetic through negative amounts.

### Citations

**File:** protobuf/vote_contract.proto (L135-148)
```text
message VoteInput {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The address of voter.
    aelf.Address voter = 2;
    // The amount of vote.
    int64 amount = 3;
    // The option to vote.
    string option = 4;
    // The vote id.
    aelf.Hash vote_id = 5;
    // Whether vote others.
    bool is_change_target = 6;
}
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L197-200)
```csharp
        if (votingItem.IsLockToken)
            Assert(votingRecord.Voter == Context.Sender, "No permission to withdraw votes of others.");
        else
            Assert(votingItem.Sponsor == Context.Sender, "No permission to withdraw votes of others.");
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-401)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
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
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }

        return votingItem;
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-207)
```csharp
    public override Empty Lock(LockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Lock behaviour should be initialed by origin address.");

        var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
        if (allowance >= input.Amount)
            State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
        AssertValidToken(input.Symbol, input.Amount);
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
