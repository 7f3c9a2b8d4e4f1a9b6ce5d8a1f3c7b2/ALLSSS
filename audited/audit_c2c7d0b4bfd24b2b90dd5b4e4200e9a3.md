### Title
Vote Manipulation via Negative Amount in Delegated Voting

### Summary
The Vote contract fails to validate that the `amount` parameter is positive for delegated voting scenarios (`IsLockToken = false`). This allows the voting sponsor to vote with negative amounts, which directly subtracts from vote counts instead of adding. Additionally, withdrawing such negative-amount votes adds to the vote count instead of subtracting, enabling double manipulation of voting results.

### Finding Description

**Root Cause:**
The `Vote()` function accepts an `amount` parameter of type `int64` (signed integer) without validating that it is positive for delegated voting scenarios. [1](#0-0) 

For non-quadratic voting, the amount is directly assigned from user input: [2](#0-1) 

The `AssertValidVoteInput()` function validates various conditions but does NOT check if `amount` is positive: [3](#0-2) 

**Why Protections Fail:**

For **locked token voting** (`IsLockToken = true`), the token contract's `Lock()` method validates the amount: [4](#0-3) [5](#0-4) 

However, for **delegated voting** (`IsLockToken = false`), the lock operation never occurs, so the token contract validation is bypassed: [6](#0-5) 

**Execution Path:**

1. Sponsor creates voting item with `IsLockToken = false`
2. Sponsor calls `Vote()` with negative `amount` (e.g., -1000)
3. For non-quadratic: `amount = input.Amount` (negative value)
4. `UpdateVotingResult()` is called with the negative amount
5. Line 177 performs: `votingResult.Results[option] = currentVotes.Add(amount)` [7](#0-6) 

The `Add()` extension method simply performs `a + b` in checked context: [8](#0-7) 

So adding a negative amount (e.g., `1000 + (-1000) = 0`) effectively subtracts from the vote count.

**Double Manipulation on Withdrawal:**

When withdrawing, the contract subtracts the recorded amount (which is negative): [9](#0-8) 

Since `Sub(negative_amount)` performs `a - (negative_amount) = a + positive_amount`, withdrawing a negative vote ADDS to the vote count instead of subtracting.

### Impact Explanation

**Harm:**
- **Vote Count Manipulation**: Sponsor can arbitrarily decrease any option's vote count by voting with negative amounts
- **Double Exploitation**: Withdrawing negative votes increases vote counts, allowing further manipulation  
- **VotesAmount Corruption**: The total `VotesAmount` can become negative or arbitrary, breaking accounting invariants
- **Governance Compromise**: Delegated voting is used for off-chain oracle-style voting systems; this vulnerability allows complete result manipulation

**Affected Parties:**
- All participants in delegated voting systems (IsLockToken = false)
- Governance decisions relying on delegated vote counts
- Any contracts/systems that trust Vote contract results

**Severity Justification:**
CRITICAL - Direct manipulation of voting results without any token cost or external dependencies. While only the sponsor can exploit this in delegated voting, this breaks the fundamental integrity of the voting system. Even if sponsors are semi-trusted, they should not have the power to arbitrarily manipulate vote counts. This is especially critical if:
- The sponsor's private key is compromised
- The sponsor is a contract with a vulnerability
- The sponsor's off-chain system has a bug generating negative amounts

### Likelihood Explanation

**Attacker Capabilities:**
- Must be the sponsor of a delegated voting item (`IsLockToken = false`)
- Can call the public `Vote()` function with crafted input

**Attack Complexity:**
LOW - Single transaction with negative `amount` parameter:
```
Vote({
    VotingItemId: <voting_item>,
    Amount: -1000,  // Negative amount
    Option: <target_option>,
    Voter: <any_address>,
    VoteId: <any_hash>
})
```

**Feasibility Conditions:**
- Voting item must have `IsLockToken = false` (delegated voting)
- Sponsor must be the caller (enforced by line 386 check)
- No additional preconditions required

**Economic Rationality:**
ZERO COST - Delegated voting requires no tokens, so the attack is completely free. The sponsor can manipulate votes unlimited times without any economic cost.

**Detection:**
Difficult to detect unless vote records are audited, as negative amounts would appear as legitimate vote records in state.

### Recommendation

**Code-Level Mitigation:**

Add amount validation in `AssertValidVoteInput()` before line 401:

```csharp
// For non-quadratic voting, validate amount is positive
if (!votingItem.IsQuadratic)
{
    Assert(input.Amount > 0, "Invalid amount. Amount must be positive.");
}
```

Alternatively, add validation at the beginning of `Vote()` function after line 92:

```csharp
// Validate amount for non-quadratic voting
if (!votingItem.IsQuadratic)
{
    Assert(input.Amount > 0, "Invalid amount. Amount must be positive.");
}
```

**Invariant Checks:**
1. Enforce `amount > 0` for all non-quadratic voting operations
2. Add assertion that `votingResult.VotesAmount >= 0` after updates
3. Add assertion that individual option vote counts are non-negative

**Test Cases:**
```csharp
[Fact]
public async Task Vote_With_Negative_Amount_Should_Fail()
{
    var votingItem = await RegisterVotingItemAsync(10, 4, false, DefaultSender, 10);
    var result = await VoteWithException(DefaultSenderKeyPair, 
        votingItem.VotingItemId, 
        votingItem.Options[0], 
        -100); // Negative amount
    result.Error.ShouldContain("Invalid amount");
}

[Fact]
public async Task Vote_With_Zero_Amount_Should_Fail()
{
    var votingItem = await RegisterVotingItemAsync(10, 4, false, DefaultSender, 10);
    var result = await VoteWithException(DefaultSenderKeyPair, 
        votingItem.VotingItemId, 
        votingItem.Options[0], 
        0); // Zero amount
    result.Error.ShouldContain("Invalid amount");
}
```

### Proof of Concept

**Initial State:**
1. Sponsor creates delegated voting item: `Register({IsLockToken: false, ...})`
2. Initial vote count for Option A: 0

**Attack Steps:**

Step 1 - Vote with negative amount:
```
Transaction 1: Vote({
    VotingItemId: <item_id>,
    Amount: -5000,
    Option: "Option A",
    Voter: <any_address>,
    VoteId: <hash1>
})
```

**Expected Result:** Transaction should fail with "Invalid amount"

**Actual Result:** 
- Transaction succeeds
- `votingResult.Results["Option A"]` = 0 + (-5000) = -5000 (negative votes!)
- `votingResult.VotesAmount` = -5000 (negative total!)
- Vote record stored with `Amount = -5000`

Step 2 - Withdraw the negative vote:
```
Transaction 2: Withdraw({
    VoteId: <hash1>
})
```

**Actual Result:**
- `votingResult.Results["Option A"]` = -5000 - (-5000) = 0 (vote count increases!)
- `votingResult.VotesAmount` = -5000 - (-5000) = 0

**Success Condition:**
The attack succeeds if negative amounts are accepted and vote counts can be decreased (on vote) or increased (on withdrawal) without any token cost or validation failure.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L94-97)
```csharp
        if (!votingItem.IsQuadratic)
        {
            amount = input.Amount;
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-220)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);
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
