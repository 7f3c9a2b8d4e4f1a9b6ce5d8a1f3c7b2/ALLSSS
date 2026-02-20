# Audit Report

## Title
Arithmetic Underflow in Quadratic Voting Withdrawal Due to Vote/Withdraw Amount Mismatch

## Summary
The Vote contract contains a critical arithmetic mismatch in quadratic voting where only `1` is added to `Results[option]` during voting, but the full `votingRecord.Amount` (equal to `TicketCost * votesCount`) is subtracted during withdrawal. This causes checked arithmetic underflow, permanently preventing token withdrawal and creating a complete denial-of-service for all quadratic voting items.

## Finding Description

The Vote contract implements quadratic voting where users pay increasing costs for each vote, but there is a fundamental inconsistency between vote tracking and withdrawal.

**During Vote Execution:**

When a user votes on a quadratic voting item, the contract calculates the full cost and stores it in the voting record [1](#0-0) , but when calling `UpdateVotingResult()`, it passes only `1` instead of the actual amount for quadratic votes [2](#0-1) .

The `UpdateVotingResult()` function then adds this value to `Results[option]` [3](#0-2) , meaning only `1` is accumulated in the results for quadratic voting items.

**During Withdrawal:**

The `Withdraw()` function subtracts the full `votingRecord.Amount` from `Results[option]` without any special handling for quadratic voting [4](#0-3) .

**Why This Fails:**

The `.Sub()` method uses checked arithmetic that throws `OverflowException` on underflow [5](#0-4) . Since `Results[option]` contains only `1` but the withdrawal attempts to subtract e.g., `100` (for `TicketCost=100, votesCount=1`), the operation triggers underflow and the transaction fails.

The vulnerability affects the entire quadratic voting feature as there is no special handling in the `Withdraw()` function to check the `IsQuadratic` flag.

## Impact Explanation

**Direct Fund Impact:**
- All tokens locked for quadratic voting become permanently unrecoverable
- Users cannot withdraw their funds, resulting in complete loss of locked tokens
- For example: If `TicketCost = 100` and a user votes once, they lock 100 tokens but `Results[option]` only contains `1`, making withdrawal impossible

**Operational Impact:**
- Complete denial-of-service on the `Withdraw()` function for ALL quadratic voting items
- Voting results are corrupted as `Results[option]` values don't reflect actual token amounts locked
- The entire quadratic voting feature is non-functional in production

**Affected Parties:**
- All users who participate in quadratic voting items lose their locked tokens
- Vote sponsors who create quadratic voting items unknowingly create token traps
- The protocol's voting mechanism integrity is compromised

This represents a HIGH severity vulnerability due to guaranteed permanent fund loss and complete feature DoS with no available workaround.

## Likelihood Explanation

**No Attack Required:**
This is a fundamental logic bug that triggers during normal, legitimate operation. No malicious intent or special conditions are needed.

**Trivial Reproduction:**
Any user participating in quadratic voting encounters this issue:
1. Sponsor creates a quadratic voting item with `IsQuadratic = true` and any `TicketCost > 1`
2. User votes normally using the public `Vote()` function
3. User attempts to withdraw using the public `Withdraw()` function
4. Transaction fails with `OverflowException`

**Feasibility:**
- Quadratic voting feature must be enabled (`IsQuadratic = true`)
- `TicketCost` must be greater than the accumulated vote count (always true for reasonable ticket costs)
- No special permissions or state manipulation required
- Uses standard public contract methods

**Probability:**
100% reproducible on every quadratic voting withdrawal attempt. The arithmetic mismatch guarantees the failure.

## Recommendation

Modify the `UpdateVotingResult()` function call in the `Vote()` method to pass the full amount for quadratic voting as well, or modify the `Withdraw()` function to subtract only `1` when handling quadratic voting withdrawals.

**Option 1 - Fix Vote() (Recommended):**
```csharp
// Line 119 in VoteContract.cs
UpdateVotingResult(votingItem, input.Option, amount); // Remove the ternary operator
```

**Option 2 - Fix Withdraw():**
```csharp
// Line 215-216 in VoteContract.cs
var amountToSubtract = votingItem.IsQuadratic ? 1 : votingRecord.Amount;
votingResult.Results[votingRecord.Option] = votingResult.Results[votingRecord.Option].Sub(amountToSubtract);
```

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_Withdrawal_Underflow_Test()
{
    // Register a quadratic voting item with TicketCost = 100
    var startTime = TimestampHelper.GetUtcNow();
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(10),
        StartTimestamp = startTime,
        Options = { GenerateOptions(2) },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true,
        IsQuadratic = true,
        TicketCost = 100
    };
    await VoteContractStub.Register.SendAsync(input);
    input.Options.Clear();
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(input), 
        HashHelper.ComputeFrom(DefaultSender)
    );
    
    // User votes (locks 100 tokens, but only 1 is added to Results)
    var voter = Accounts[1].KeyPair;
    await GetVoteContractTester(voter).Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = GenerateOptions(2)[0],
        Amount = 0 // Amount ignored for quadratic voting
    });
    
    // Get vote ID for withdrawal
    var voteIds = await GetVoteIds(voter, votingItemId);
    var voteId = voteIds.ActiveVotes.First();
    
    // Attempt withdrawal - should fail with OverflowException
    var withdrawResult = await WithdrawWithException(voter, voteId);
    withdrawResult.Status.ShouldBe(TransactionResultStatus.Failed);
    withdrawResult.Error.ShouldContain("Overflow"); // Underflow throws OverflowException
}
```

**Notes:**
- This vulnerability is in production scope file `contract/AElf.Contracts.Vote/VoteContract.cs`
- No existing tests cover quadratic voting functionality, which allowed this bug to remain undetected
- The issue breaks the fundamental invariant that users can withdraw their locked tokens after voting
- The vulnerability requires no special privileges and affects all users of the quadratic voting feature

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L98-108)
```csharp
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }

        var votingRecord = new VotingRecord
        {
            VotingItemId = input.VotingItemId,
            Amount = amount,
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L176-177)
```csharp
        var currentVotes = votingResult.Results[option];
        votingResult.Results[option] = currentVotes.Add(amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L215-216)
```csharp
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
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
