# Audit Report

## Title
Broken Quadratic Voting Mechanism Allows Vote Manipulation with Minimal Token Cost

## Summary
The quadratic voting implementation in VoteContract is fundamentally broken due to VoteId generation based on the cumulative `VotesAmount`, which changes after each vote. This causes each new vote to receive a unique VoteId, preventing the `QuadraticVotesCountMap` from accumulating vote counts per user. As a result, every vote costs only the fixed `TicketCost` instead of quadratically increasing costs (1x, 2x, 3x, etc.), completely defeating the Sybil resistance mechanism that quadratic voting is designed to provide.

## Finding Description

The vulnerability stems from the interaction between VoteId generation and quadratic cost calculation:

**Root Cause 1: Broken Quadratic Cost for IsLockToken=true**

When a user votes on a quadratic voting item with `IsLockToken=true`, the VoteId is auto-generated based on the current total votes amount: [1](#0-0) 

The critical flaw is that `votingResult.VotesAmount` increases after each vote, meaning every subsequent vote generates a different VoteId. When the quadratic cost is calculated: [2](#0-1) 

Since each transaction has a unique VoteId (due to the changing `VotesAmount`), the lookup `State.QuadraticVotesCountMap[input.VoteId]` always returns 0 for new VoteIds, making `currentVotesCount = 0 + 1 = 1` for every vote. Therefore, `amount` is always `TicketCost * 1`, never increasing quadratically.

**Root Cause 2: Zero-Cost Voting for IsLockToken=false**

For delegated voting (`IsLockToken=false`), token locking is entirely skipped: [3](#0-2) 

The sponsor can vote unlimited times on behalf of users without locking any tokens.

**Missing Validation**

The `Register()` function accepts `TicketCost` without validation: [4](#0-3) 

No minimum value check exists in the registration flow: [5](#0-4) 

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
- Any governance system relying on this Vote contract for quadratic voting can be manipulated with minimal economic barrier
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

**Fix 1: Change VoteId Generation for IsLockToken=true**

The VoteId should be based on the voter's address, not the cumulative votes amount:

```csharp
// In AssertValidVoteInput() for IsLockToken=true case:
input.Voter = Context.Sender;
// Generate VoteId based on voter address and voting item, not VotesAmount
input.VoteId = Context.GenerateId(Context.Self, 
    HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender), 
        votingItem.VotingItemId
    ).ToByteArray());
```

This ensures the same voter gets the same VoteId across multiple votes on the same voting item, allowing `QuadraticVotesCountMap` to properly accumulate.

**Fix 2: Add Minimum TicketCost Validation**

```csharp
// In Register() function after line 51:
Assert(input.IsQuadratic == false || input.TicketCost > 0, 
    "Quadratic voting requires positive TicketCost.");
```

**Fix 3: Enforce Token Locking for Delegated Quadratic Voting**

Consider disallowing `IsLockToken=false` with `IsQuadratic=true`, or implement proper cost tracking for delegated quadratic votes.

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_CostDoesNotIncrease_Vulnerability()
{
    InitializeContracts();
    
    var voter = Accounts[1];
    var initialBalance = GetUserBalance(voter.Address);
    
    // Register quadratic voting item with TicketCost=1
    var registerInput = new VotingRegisterInput
    {
        StartTimestamp = TimestampHelper.GetUtcNow(),
        EndTimestamp = TimestampHelper.GetUtcNow().AddDays(7),
        AcceptedCurrency = "ELF",
        IsLockToken = true,
        TotalSnapshotNumber = 1,
        Options = { "OptionA", "OptionB" },
        IsQuadratic = true,
        TicketCost = 1 // Minimal cost
    };
    
    await VoteContractStub.Register.SendAsync(registerInput);
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(registerInput), 
        HashHelper.ComputeFrom(DefaultSender)
    );
    
    // Vote 10 times - each should cost TicketCost*1 instead of increasing
    var voterStub = GetVoteContractTester(voter.KeyPair);
    for (int i = 0; i < 10; i++)
    {
        await voterStub.Vote.SendAsync(new VoteInput
        {
            VotingItemId = votingItemId,
            Option = "OptionA",
            Amount = 0 // Ignored for quadratic
        });
    }
    
    // Check total cost - should be 10 tokens, not 55 tokens (1+2+3+...+10)
    var finalBalance = GetUserBalance(voter.Address);
    var totalCost = initialBalance - finalBalance;
    
    // BUG: totalCost is 10 instead of 55
    totalCost.ShouldBe(10); // This proves the vulnerability
    // Expected for true quadratic voting: totalCost.ShouldBe(55);
    
    // Verify vote count is correct (10 votes recorded)
    var result = await VoteContractStub.GetLatestVotingResult.CallAsync(votingItemId);
    result.Results["OptionA"].ShouldBe(10); // 10 votes counted (weight=1 each)
}
```

## Notes

This vulnerability completely breaks the quadratic voting mechanism in the AElf Vote contract. The design flaw in VoteId generation prevents the quadratic cost accumulation from working as intended. The `QuadraticVotesCountMap` state variable [6](#0-5)  exists to track vote counts per VoteId, but since VoteId changes on every transaction, this tracking mechanism fails.

Any governance system currently using this contract's quadratic voting feature is vulnerable to cheap vote manipulation. The lack of `TicketCost` validation exacerbates the issue by allowing attackers to set arbitrarily low costs.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L51-51)
```csharp
            TicketCost = input.TicketCost
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L351-365)
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
