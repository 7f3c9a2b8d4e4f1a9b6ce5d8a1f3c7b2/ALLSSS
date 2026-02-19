# Audit Report

## Title
Vote Manipulation via Negative Amount in Delegated Voting

## Summary
The Vote contract accepts signed integer amounts without validating they are positive for delegated voting scenarios. This allows sponsors to vote with negative amounts, subtracting from vote counts instead of adding, and enables double manipulation through withdrawal operations that incorrectly add to vote counts.

## Finding Description

The `Vote()` function accepts an `amount` parameter of type `int64` (signed integer) without validating that it is positive for delegated voting scenarios where `IsLockToken = false`. [1](#0-0) 

For non-quadratic voting, the amount is directly assigned from user input without any validation: [2](#0-1) 

The `AssertValidVoteInput()` validation function checks that the sender is the sponsor for delegated voting but does NOT validate that the amount is positive: [3](#0-2) 

**Why Protections Fail:**

For locked token voting (`IsLockToken = true`), the token contract's `Lock()` method would validate the amount through `AssertValidToken()`: [4](#0-3) 

The `AssertValidToken()` method properly validates that amounts are positive: [5](#0-4) 

However, for delegated voting (`IsLockToken = false`), the lock operation never occurs, bypassing this validation: [6](#0-5) 

**Attack Execution:**

When a sponsor votes with a negative amount, the `UpdateVotingResult()` method adds the negative value to vote counts: [7](#0-6) 

The `Add()` extension method simply performs `a + b` in checked context: [8](#0-7) 

Therefore, adding a negative amount (e.g., `1000 + (-1000) = 0`) effectively subtracts from the vote count.

**Double Manipulation on Withdrawal:**

When withdrawing a vote with negative amount, the contract subtracts the recorded negative amount: [9](#0-8) 

The `Sub()` method performs `a - b`: [10](#0-9) 

Since subtracting a negative equals adding (`a - (-b) = a + b`), withdrawing a negative vote ADDS to the vote count instead of subtracting, enabling a second manipulation.

## Impact Explanation

**Critical Severity** - This vulnerability breaks fundamental vote integrity guarantees:

1. **Vote Count Manipulation**: Sponsors can arbitrarily decrease vote counts by voting with negative amounts, directly manipulating election/governance outcomes

2. **Double Exploitation**: Withdrawing negative votes increases counts instead of decreasing them, allowing sponsors to add votes without any legitimate voting action

3. **VotesAmount Corruption**: The total `VotesAmount` can become negative or arbitrary, breaking accounting invariants and potentially causing integer underflow issues in dependent systems

4. **Zero Economic Cost**: Delegated voting requires no tokens, so attacks have no economic cost or barrier

5. **Governance Compromise**: Delegated voting is designed for off-chain oracle-style systems. This vulnerability allows complete manipulation of results that governance decisions may rely upon

While only sponsors can exploit this, sponsors are **not** in the trusted roles list (genesis method-fee provider, organization controllers, consensus system contracts), and even semi-trusted sponsors should not have unlimited power to manipulate votes. This is especially critical when:
- Sponsor private keys are compromised
- The sponsor is a contract with vulnerabilities
- Off-chain systems have bugs generating negative amounts

## Likelihood Explanation

**Medium-High Likelihood** - The attack is straightforward:

**Attacker Capabilities:**
- Must be the sponsor of a delegated voting item (enforced at line 386)
- Can call the public `Vote()` function with crafted input

**Attack Complexity:**
LOW - Single transaction with negative amount parameter. No complex setup or multi-step process required.

**Preconditions:**
- Voting item must have `IsLockToken = false` (delegated voting)
- Sponsor must be the caller
- No additional preconditions required

**Feasibility:**
While requiring sponsor privileges, this remains highly feasible because:
1. Sponsor keys can be compromised through standard attack vectors
2. Sponsors may be smart contracts with their own vulnerabilities
3. Off-chain systems feeding vote data may have bugs
4. No economic barrier exists (zero token cost)

## Recommendation

Add explicit validation in the `Vote()` function to ensure amounts are positive:

```csharp
public override Empty Vote(VoteInput input)
{
    var votingItem = AssertValidVoteInput(input);
    
    // Add validation for positive amount
    Assert(input.Amount > 0, "Vote amount must be positive.");
    
    var amount = 0L;
    if (!votingItem.IsQuadratic)
    {
        amount = input.Amount;
    }
    // ... rest of the method
}
```

Alternatively, validate in `AssertValidVoteInput()`:

```csharp
private VotingItem AssertValidVoteInput(VoteInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
    Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
    Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
        "Current voting item already ended.");
    
    // Add amount validation for delegated voting
    if (!votingItem.IsLockToken)
    {
        Assert(input.Amount > 0, "Vote amount must be positive.");
        Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
        Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
        Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    }
    // ... rest of validation
}
```

## Proof of Concept

```csharp
[Fact]
public void Vote_WithNegativeAmount_ManipulatesVoteCounts()
{
    // Setup: Create delegated voting item (IsLockToken = false)
    var sponsor = SampleAccount.Accounts[0].Address;
    var votingItemId = RegisterDelegatedVotingItem(sponsor);
    
    // Initial state: Option "A" has 0 votes
    var initialResult = VoteContractStub.GetVotingResult.Call(new GetVotingResultInput
    {
        VotingItemId = votingItemId,
        SnapshotNumber = 1
    });
    Assert.Equal(0, initialResult.Results["A"]);
    
    // Attack: Sponsor votes with NEGATIVE amount
    VoteContractStub.Vote.Send(new VoteInput
    {
        VotingItemId = votingItemId,
        Voter = SampleAccount.Accounts[1].Address,
        Amount = -1000, // Negative amount
        Option = "A",
        VoteId = HashHelper.ComputeFrom("vote1")
    });
    
    // Verify: Vote count DECREASED instead of increased
    var resultAfterVote = VoteContractStub.GetVotingResult.Call(new GetVotingResultInput
    {
        VotingItemId = votingItemId,
        SnapshotNumber = 1
    });
    Assert.Equal(-1000, resultAfterVote.Results["A"]); // DECREASED by 1000
    Assert.Equal(-1000, resultAfterVote.VotesAmount);  // Total corrupted
    
    // Double attack: Withdraw the negative vote
    VoteContractStub.Withdraw.Send(new WithdrawInput
    {
        VoteId = HashHelper.ComputeFrom("vote1")
    });
    
    // Verify: Vote count INCREASED on withdrawal
    var resultAfterWithdraw = VoteContractStub.GetVotingResult.Call(new GetVotingResultInput
    {
        VotingItemId = votingItemId,
        SnapshotNumber = 1
    });
    Assert.Equal(0, resultAfterWithdraw.Results["A"]); // INCREASED back to 0
    
    // Net effect: Sponsor can arbitrarily manipulate vote counts
    // without any token cost or legitimate voting action
}
```

## Notes

This vulnerability specifically affects **delegated voting** scenarios where `IsLockToken = false`. Regular token-locked voting is protected by the MultiToken contract's amount validation. However, the Vote contract should not rely solely on external validation and should enforce its own input constraints to maintain vote integrity invariants regardless of the voting mode.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-222)
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
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
        DealWithExternalInfoDuringLocking(new TransferFromInput
        {
            From = input.Address,
            To = virtualAddress,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        return new Empty();
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
