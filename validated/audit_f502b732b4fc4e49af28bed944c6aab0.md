# Audit Report

## Title
Vote Manipulation via Negative Amount in Delegated Voting

## Summary
The Vote contract fails to validate that the `amount` parameter is positive for delegated voting scenarios (`IsLockToken = false`). This allows the voting sponsor to manipulate vote results by voting with negative amounts, which subtracts from vote counts instead of adding. Withdrawing such negative votes further corrupts results by adding to vote counts instead of subtracting.

## Finding Description

The `Vote()` function accepts an `amount` parameter of type `int64` (signed integer) defined in the protobuf schema [1](#0-0) , which allows negative values.

For non-quadratic voting, the amount is directly assigned from user input without any positivity validation [2](#0-1) .

The `AssertValidVoteInput()` function validates voting item existence, option validity, and authorization for delegated voting [3](#0-2) , but does NOT check if `amount` is positive.

**Why Token Contract Protection Fails:**

For locked token voting (`IsLockToken = true`), the MultiToken contract's `Lock()` method validates amounts through `AssertValidSymbolAndAmount()` which enforces `amount > 0` [4](#0-3) . This validation is invoked by the Lock call [5](#0-4) .

However, for delegated voting (`IsLockToken = false`), the Lock operation is completely bypassed [6](#0-5) , so token contract validation never occurs.

**Attack Execution Path:**

When `UpdateVotingResult()` is called with a negative amount, it uses SafeMath `Add()` [7](#0-6) . The `Add()` method performs standard addition in checked context [8](#0-7) . Therefore, adding a negative amount (e.g., `1000 + (-1000) = 0`) effectively subtracts from the vote count.

**Double Manipulation on Withdrawal:**

When withdrawing, the contract subtracts the recorded amount using SafeMath `Sub()` [9](#0-8) . The `Sub()` method performs standard subtraction [10](#0-9) . Subtracting a negative amount (e.g., `result - (-1000) = result + 1000`) adds to the vote count instead of subtracting.

**Authorization Confirms Sponsor-Only Access:**

For delegated voting, only the sponsor can call `Vote()` [11](#0-10)  and only the sponsor can call `Withdraw()` for delegated votes [12](#0-11) .

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
While only the sponsor can exploit this, the sponsor is not a trusted privileged role in the system design (trusted roles are: genesis method-fee provider, organization controllers, consensus system contracts). Sponsors should not have the power to arbitrarily manipulate vote counts. This is especially critical when:
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
- Attacker must be the sponsor (any user can become a sponsor by registering a voting item)
- No additional economic or technical barriers exist

**Economic Cost:**
**ZERO** - Delegated voting requires no token locks or payments, making the attack completely free to execute repeatedly.

**Detection Difficulty:**
Negative amounts in vote records could appear as legitimate entries unless vote record state is specifically audited for sign validation.

## Recommendation

Add explicit amount validation in the `Vote()` function for delegated voting scenarios:

```csharp
// In VoteContract.cs, Vote() method
if (!votingItem.IsQuadratic)
{
    amount = input.Amount;
    Assert(amount > 0, "Vote amount must be positive.");
}
```

Alternatively, add the check in `AssertValidVoteInput()`:

```csharp
// In VoteContract.cs, AssertValidVoteInput() method
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
        Assert(input.Amount > 0, "Vote amount must be positive for delegated voting.");
    }
    // ... rest of method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Vote_With_Negative_Amount_Manipulation_Test()
{
    // Register delegated voting item (IsLockToken = false)
    var votingItem = await RegisterVotingItemAsync(10, 3, false, DefaultSender, 1);
    
    // Sponsor votes with negative amount (-1000)
    var negativeVoteId = HashHelper.ComputeFrom("negative_vote");
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        Voter = Accounts[1].Address,
        VoteId = negativeVoteId,
        Option = votingItem.Options[0],
        Amount = -1000
    });
    
    // Check voting result - should show -1000 votes (vote count decreased!)
    var votingResult = await GetVotingResult(votingItem.VotingItemId, 1);
    votingResult.Results[votingItem.Options[0]].ShouldBe(-1000); // Vote count is negative!
    votingResult.VotesAmount.ShouldBe(-1000); // Total votes amount is negative!
    
    // Withdraw the negative vote - this ADDS to vote count instead of subtracting
    await VoteContractStub.Withdraw.SendAsync(new WithdrawInput { VoteId = negativeVoteId });
    
    var votingResultAfterWithdraw = await GetVotingResult(votingItem.VotingItemId, 1);
    votingResultAfterWithdraw.Results[votingItem.Options[0]].ShouldBe(0); // -1000 - (-1000) = 0
    
    // This proves the manipulation: negative votes subtract from counts,
    // and withdrawing them adds back, allowing arbitrary vote manipulation
}
```

**Notes:**
This vulnerability represents a critical flaw in the delegated voting mechanism where the absence of amount validation allows sponsors to manipulate vote results arbitrarily. The exploitation path is straightforward and requires no special privileges beyond being a sponsor, which any user can achieve by registering a voting item. The fix is simple: add explicit validation to ensure vote amounts are positive in delegated voting scenarios.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L177-179)
```csharp
        votingResult.Results[option] = currentVotes.Add(amount);
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
        votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L199-200)
```csharp
        else
            Assert(votingItem.Sponsor == Context.Sender, "No permission to withdraw votes of others.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L215-220)
```csharp
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-388)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L207-207)
```csharp
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
