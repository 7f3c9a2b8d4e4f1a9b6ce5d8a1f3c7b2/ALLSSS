# Audit Report

## Title
Quadratic Voting Double-Count Vulnerability via VoteId Reuse in Delegated Voting

## Summary
The `Vote()` function in the Vote contract lacks validation to prevent reuse of VoteIds in delegated quadratic voting scenarios. A sponsor can call `Vote()` multiple times with the same VoteId, causing vote inflation where N votes are counted but only one VotingRecord exists, resulting in permanent state corruption and governance manipulation.

## Finding Description

The vulnerability exists in delegated quadratic voting (when `IsLockToken = false` and `IsQuadratic = true`).

**Root Cause:**

For delegated voting, the validation only checks that VoteId is not null, but does not verify whether the VoteId already exists in storage. [1](#0-0) 

When quadratic voting is enabled, the code unconditionally increments `QuadraticVotesCountMap[input.VoteId]` on every call and calculates amount as `ticketCost * count`. [2](#0-1) 

The `VotingRecords` mapping is then directly assigned, overwriting any previous record at that VoteId. [3](#0-2) 

For quadratic voting, `UpdateVotingResult` is called with amount of `1` (not the calculated token amount), incrementing vote counts by 1 each time. [4](#0-3) 

The `UpdateVotingResult` function adds this amount to Results, VotersCount, and VotesAmount. [5](#0-4) 

**Attack Execution:**
1. Sponsor registers voting item with `IsLockToken = false`, `IsQuadratic = true`, `TicketCost = 100`
2. Sponsor calls `Vote()` with `VoteId = X` first time:
   - QuadraticVotesCountMap[X] = 1, amount = 100
   - VotingRecords[X] stored with Amount = 100
   - Results[option] = 1, VotesAmount = 1
3. Sponsor calls `Vote()` with same `VoteId = X` second time:
   - QuadraticVotesCountMap[X] = 2, amount = 200
   - VotingRecords[X] overwritten with Amount = 200
   - Results[option] = 2, VotesAmount = 2
4. After N calls: Results[option] = N, but VotingRecords[X].Amount = 100×N

**Withdrawal Failure:**

When withdrawing, the code attempts to subtract `votingRecord.Amount` from Results and VotesAmount. [6](#0-5) 

If sponsor voted 3 times (Results[option] = 3, VotingRecords[X].Amount = 300), withdrawal tries to subtract 300 from 3, causing arithmetic underflow.

AElf's SafeMath uses checked blocks that throw OverflowException on underflow. [7](#0-6) 

No tokens are locked for delegated voting, making this a zero-cost attack. [8](#0-7) 

## Impact Explanation

**Critical Severity** due to:

1. **Vote Manipulation**: Sponsor can artificially inflate vote counts by factor of N with zero cost
2. **Permanent State Corruption**: Inflated votes cannot be withdrawn due to arithmetic underflow, making manipulation permanent
3. **Governance Integrity Break**: Voting results become unreliable, undermining any governance decisions
4. **Protocol Invariant Violation**: N votes counted but only 1 VotingRecord exists, breaking accounting consistency
5. **Zero Detection**: No on-chain mechanism to detect or prevent VoteId reuse

All voting activities using delegated quadratic voting are affected, potentially impacting significant protocol governance decisions.

## Likelihood Explanation

**High Likelihood** because:

1. **Low Attack Complexity**: Simply call `Vote()` multiple times with same VoteId - no complex transactions required
2. **No Special Privileges**: Anyone can register voting items and become a sponsor
3. **Zero Cost**: No tokens need to be locked for delegated voting, removing economic disincentive
4. **Direct Exploit Path**: Public methods with no validation against VoteId reuse
5. **Strong Incentive**: Complete control over vote outcomes with no risk or cost

The sponsor has both capability and motivation to exploit this for governance manipulation.

## Recommendation

Add validation to prevent VoteId reuse in the `AssertValidVoteInput` function:

```csharp
if (!votingItem.IsLockToken)
{
    Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
    Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
    Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    
    // Add this check:
    var existingRecord = State.VotingRecords[input.VoteId];
    Assert(existingRecord == null || existingRecord.IsWithdrawn, 
        "Vote Id already used and not withdrawn.");
}
```

This ensures each VoteId can only be used once for active votes, preventing double-counting.

## Proof of Concept

```csharp
[Fact]
public async Task Quadratic_Voting_VoteId_Reuse_Vulnerability_Test()
{
    // Setup: Register delegated quadratic voting item
    var votingItemId = HashHelper.ComputeFrom("test_voting_item");
    await VoteContractStub.Register.SendAsync(new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        StartTimestamp = TimestampHelper.GetUtcNow(),
        EndTimestamp = TimestampHelper.GetUtcNow().AddDays(1),
        AcceptedCurrency = "ELF",
        IsLockToken = false,  // Delegated voting
        IsQuadratic = true,   // Quadratic voting
        TicketCost = 100,
        Options = { "OptionA", "OptionB" }
    });

    var voter = Accounts[1].Address;
    var reuseVoteId = HashHelper.ComputeFrom("reused_vote_id");

    // Attack: Call Vote() three times with same VoteId
    for (int i = 0; i < 3; i++)
    {
        await VoteContractStub.Vote.SendAsync(new VoteInput
        {
            VotingItemId = votingItemId,
            Voter = voter,
            VoteId = reuseVoteId,
            Amount = 0, // Not used in delegated voting
            Option = "OptionA"
        });
    }

    // Verify vulnerability: 3 votes counted
    var votingResult = await VoteContractStub.GetLatestVotingResult.CallAsync(votingItemId);
    votingResult.Results["OptionA"].ShouldBe(3); // 3 votes counted
    votingResult.VotesAmount.ShouldBe(3);

    // Verify only 1 record with amount = 300 (100 * 3)
    var votingRecord = await VoteContractStub.GetVotingRecord.CallAsync(reuseVoteId);
    votingRecord.Amount.ShouldBe(300);

    // Attempt withdrawal - will fail with OverflowException
    // Trying to subtract 300 from 3 causes underflow
    var withdrawResult = await VoteContractStub.Withdraw.SendWithExceptionAsync(new WithdrawInput
    {
        VoteId = reuseVoteId
    });
    
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    withdrawResult.TransactionResult.Error.ShouldContain("Overflow"); // Underflow = negative overflow
}
```

**Notes:**
- This vulnerability only affects delegated quadratic voting configurations where both `IsLockToken = false` AND `IsQuadratic = true`
- The lack of VoteId uniqueness validation is the root cause
- The accounting mismatch between vote counting (increments by 1) and amount storage (grows quadratically) creates permanent state corruption
- No existing tests validate quadratic voting functionality, which likely contributed to this oversight

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L98-103)
```csharp
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L105-117)
```csharp
        var votingRecord = new VotingRecord
        {
            VotingItemId = input.VotingItemId,
            Amount = amount,
            SnapshotNumber = votingItem.CurrentSnapshotNumber,
            Option = input.Option,
            IsWithdrawn = false,
            VoteTimestamp = Context.CurrentBlockTime,
            Voter = input.Voter,
            IsChangeTarget = input.IsChangeTarget
        };

        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L214-221)
```csharp
        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

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
