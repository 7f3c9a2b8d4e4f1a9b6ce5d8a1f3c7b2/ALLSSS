# Audit Report

## Title
Missing Validation of Zero/Negative Vote Amount in Delegated Voting Allows Vote Manipulation

## Summary
The `Vote()` function in VoteContract fails to validate the `amount` field for delegated (non-token-locked) voting scenarios. This allows sponsors to submit votes with zero or negative amounts, enabling voter count inflation and vote total manipulation, thereby violating protocol voting invariants.

## Finding Description

In delegated voting mode (`IsLockToken == false`), the Vote Contract accepts and processes votes without validating that the vote amount is positive. [1](#0-0) 

For non-quadratic voting, the `amount` is directly assigned from `input.Amount` without validation. The function then calls `AssertValidVoteInput()` which validates the sender, voter, and voting item status, but specifically does NOT validate the amount field for delegated voting: [2](#0-1) 

The unvalidated amount is then passed to `UpdateVotingResult()`, which unconditionally adds it to vote totals and increments the voter count: [3](#0-2) 

**Critical observation:** When `IsLockToken == true`, the Token Contract's `Lock()` method provides validation through `AssertValidToken()`: [4](#0-3) [5](#0-4) 

This validation rejects zero or negative amounts with "Invalid amount." However, for delegated voting, no token locking occurs, so this validation is bypassed entirely.

**Attack scenarios:**
1. **Zero-amount votes**: Sponsor casts votes with `amount = 0`, incrementing `VotersCount` without increasing vote totals, distorting participation metrics
2. **Negative-amount votes**: Sponsor casts votes with `amount < 0`, reducing vote totals for specific options while still incrementing voter count

## Impact Explanation

This vulnerability breaks fundamental voting protocol invariants:

1. **Vote integrity violation**: Vote totals can be arbitrarily decreased through negative amounts, allowing sponsors to manipulate results
2. **Voter count manipulation**: Zero-amount votes inflate voter counts without corresponding vote contributions, corrupting turnout statistics
3. **Governance compromise**: If delegated voting is used for governance decisions, malicious sponsors can skew results
4. **Protocol trust erosion**: Users cannot trust that vote counts accurately represent voting behavior

The impact is direct state corruption affecting the core voting mechanism. While only sponsors can exploit this (not arbitrary users), the protocol should not permit sponsors to violate voting invariants through malformed inputs.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Feature availability**: Delegated voting (`IsLockToken = false`) is a legitimate, documented feature that will be used in production
2. **No special privileges required**: Any address that registers a voting item becomes the sponsor and can exploit this
3. **Deterministic execution**: The vulnerability is not dependent on timing, race conditions, or external state - it executes reliably
4. **No mitigating controls**: No existing validation or access control prevents this behavior
5. **Straightforward exploitation**: Simply requires calling `Vote()` with a zero or negative amount value

The protobuf definition confirms `amount` is `int64`, which allows negative values: [6](#0-5) 

## Recommendation

Add amount validation in the `Vote()` method before processing, regardless of voting mode:

```csharp
public override Empty Vote(VoteInput input)
{
    var votingItem = AssertValidVoteInput(input);
    var amount = 0L;
    if (!votingItem.IsQuadratic)
    {
        amount = input.Amount;
        // ADD THIS VALIDATION
        Assert(amount > 0, "Invalid vote amount. Amount must be positive.");
    }
    else
    {
        // ... existing quadratic logic
    }
    // ... rest of method
}
```

Alternatively, add the validation in `AssertValidVoteInput()` for delegated voting:

```csharp
if (!votingItem.IsLockToken)
{
    Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
    Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
    Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    // ADD THIS VALIDATION
    if (!votingItem.IsQuadratic)
    {
        Assert(input.Amount > 0, "Amount must be positive for delegated voting.");
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DelegatedVoting_ZeroAndNegativeAmount_VulnerabilityTest()
{
    // Register a delegated voting item (IsLockToken = false)
    var votingItem = await RegisterVotingItemAsync(100, 3, false, DefaultSender, 1);
    
    // Test 1: Zero-amount vote inflates voter count without adding votes
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Voter = Accounts[1].Address,
        VoteId = HashHelper.ComputeFrom("zero_vote"),
        Option = votingItem.Options[0],
        Amount = 0  // Zero amount
    });
    
    var result1 = await GetVotingResult(votingItem.VotingItemId, 1);
    result1.VotersCount.ShouldBe(1);  // Voter count increased
    result1.VotesAmount.ShouldBe(0);  // But no votes added
    result1.Results[votingItem.Options[0]].ShouldBe(0);
    
    // Test 2: First cast a legitimate vote
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Voter = Accounts[2].Address,
        VoteId = HashHelper.ComputeFrom("legit_vote"),
        Option = votingItem.Options[0],
        Amount = 100
    });
    
    var result2 = await GetVotingResult(votingItem.VotingItemId, 1);
    result2.VotersCount.ShouldBe(2);
    result2.VotesAmount.ShouldBe(100);
    result2.Results[votingItem.Options[0]].ShouldBe(100);
    
    // Test 3: Negative-amount vote reduces totals
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Voter = Accounts[3].Address,
        VoteId = HashHelper.ComputeFrom("negative_vote"),
        Option = votingItem.Options[0],
        Amount = -50  // Negative amount
    });
    
    var result3 = await GetVotingResult(votingItem.VotingItemId, 1);
    result3.VotersCount.ShouldBe(3);  // Voter count still increased
    result3.VotesAmount.ShouldBe(50);  // But total votes DECREASED from 100 to 50
    result3.Results[votingItem.Options[0]].ShouldBe(50);  // Option votes also decreased
    
    // This proves the vulnerability: sponsors can manipulate vote totals and counts
}
```

## Notes

This vulnerability demonstrates a critical validation gap between delegated and token-locked voting modes. While token-locked voting inherits amount validation from the Token Contract's `Lock()` method, delegated voting has no equivalent safeguard. The fix requires ensuring consistent validation across both voting modes to maintain protocol invariants.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-96)
```csharp
    public override Empty Vote(VoteInput input)
    {
        var votingItem = AssertValidVoteInput(input);
        var amount = 0L;
        if (!votingItem.IsQuadratic)
        {
            amount = input.Amount;
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-389)
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```

**File:** protobuf/vote_contract.proto (L135-141)
```text
message VoteInput {
    // The voting activity id.
    aelf.Hash voting_item_id = 1;
    // The address of voter.
    aelf.Address voter = 2;
    // The amount of vote.
    int64 amount = 3;
```
