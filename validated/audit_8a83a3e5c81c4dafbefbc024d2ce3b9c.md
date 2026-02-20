# Audit Report

## Title
Sponsor Can Manipulate Voting Timing Through Unrestricted Snapshot Control

## Summary
The Vote contract's `TakeSnapshot()` function lacks temporal constraints, allowing sponsors to manipulate voting periods arbitrarily. While the `Register` function accepts and validates `StartTimestamp` and `EndTimestamp` parameters, these timestamps are never enforced during snapshot operations or voting, enabling sponsors to close all snapshots immediately or delay them indefinitely, effectively denying voters their expected participation window.

## Finding Description

The Vote contract creates an implicit temporal contract with users through its public API but fails to enforce it, constituting a critical governance security flaw.

**1. Temporal Parameters Accepted But Not Enforced:**

The `Register` function validates the timestamp relationship [1](#0-0)  and stores them in the VotingItem state [2](#0-1) . This creates user expectations that voting will respect these declared timeframes.

**2. TakeSnapshot Lacks Time Validation:**

The `TakeSnapshot()` function only validates sponsor authorization [3](#0-2) , snapshot count limits [4](#0-3) , and snapshot number sequence [5](#0-4) . Critically, it performs no checks against `Context.CurrentBlockTime` relative to the declared `StartTimestamp` or `EndTimestamp`, nor does it enforce minimum durations between snapshots.

**3. Vote Function Ignores Timestamps:**

The `AssertValidVoteInput` validation function checks snapshot limits [6](#0-5)  but never validates whether `Context.CurrentBlockTime` falls within the declared voting period, allowing voting operations to proceed based solely on snapshot availability rather than temporal constraints.

**4. Test Evidence Confirms Vulnerability:**

Test cases demonstrate that snapshots can be taken in rapid succession without any time delays [7](#0-6) , confirming the complete absence of temporal protections.

**Attack Execution:**

A malicious sponsor can:
1. Call `Register()` with legitimate-appearing timestamps (e.g., StartTimestamp = now, EndTimestamp = now + 30 days, TotalSnapshotNumber = 10) - the method is public with no access restrictions [8](#0-7) 
2. Immediately call `TakeSnapshot()` nine times in succession
3. All snapshots close before any voter can participate, despite the declared 30-day voting period
4. Alternatively, delay snapshots indefinitely past the EndTimestamp, keeping voting open contrary to declared parameters

## Impact Explanation

**Severity Assessment: HIGH**

This vulnerability has severe governance implications:

**1. Denial of Voting Rights:** Voters planning participation based on declared timestamps are completely denied their voting rights when sponsors close snapshots immediately. This violates the fundamental guarantee of fair voting access.

**2. Governance Manipulation:** Sponsors can strategically time snapshots to achieve desired outcomes:
   - Close snapshots when favorable results are obtained
   - Delay snapshots when results are unfavorable
   - Front-run unfavorable votes by taking snapshots just before they execute

**3. Trust Undermining:** The contract's API creates expectations through its validated timestamp parameters, but the complete lack of enforcement constitutes a breach of implicit contract with users. This undermines trust in the governance system.

**4. Scope of Impact:** While the Election contract usage is protected through consensus control [9](#0-8) , the Vote contract is a public system contract. Any standalone usage (direct calls to `Register`) creates vulnerable voting items with no temporal protections.

The contract's validation of timestamp relationships during registration but complete ignoring of them during operations is a classic security anti-pattern that enables manipulation.

## Likelihood Explanation

**Likelihood Assessment: HIGH**

This vulnerability is highly likely to be exploited due to:

**1. Trivial Attack Complexity:**
- Entry point is the public `Register` method with no access restrictions
- Becoming a sponsor requires only calling `Register` - any user can do this
- Exploitation requires simple successive calls to `TakeSnapshot()` with no complex preconditions or cryptographic challenges

**2. Low Attack Cost:**
- Only requires gas fees for transactions
- No token staking or financial commitment needed beyond gas
- No risk of detection before damage is done (snapshots close atomically)

**3. High Incentive:**
- Complete control over voting timeline and outcomes
- Strong motivation for any sponsor with vested interests in voting results
- Economic rationality strongly favors exploitation when outcomes affect governance decisions or resource allocations

**4. No Defensive Mechanisms:**
- No rate limiting on snapshot operations
- No minimum duration enforcement between snapshots
- No validation that snapshots respect declared timeframes
- On-chain monitoring can detect but not prevent exploitation

The combination of trivial execution, low cost, and high benefit makes exploitation inevitable in any adversarial scenario where sponsors have conflicting interests with voters.

## Recommendation

Implement temporal constraint enforcement in both `TakeSnapshot()` and `Vote()` functions:

```csharp
public override Empty TakeSnapshot(TakeSnapshotInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    
    Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can take snapshot.");
    
    // Add temporal validation
    Assert(Context.CurrentBlockTime >= votingItem.StartTimestamp, 
        "Cannot take snapshot before voting start time.");
    Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
        "Cannot take snapshot after voting end time.");
    
    Assert(votingItem.CurrentSnapshotNumber - 1 < votingItem.TotalSnapshotNumber,
        "Current voting item already ended.");
        
    // Existing validation continues...
}

private VotingItem AssertValidVoteInput(VoteInput input)
{
    var votingItem = AssertVotingItem(input.VotingItemId);
    
    // Add temporal validation for voting
    Assert(Context.CurrentBlockTime >= votingItem.StartTimestamp, 
        "Voting has not started yet.");
    Assert(Context.CurrentBlockTime <= votingItem.EndTimestamp, 
        "Voting period has ended.");
    
    // Existing validation continues...
}
```

Additionally, consider implementing minimum duration requirements between snapshots to prevent rapid succession manipulation.

## Proof of Concept

```csharp
[Fact]
public async Task VoteContract_RapidSnapshot_DenialOfVoting_Test()
{
    // Register voting item with 30-day duration and 3 snapshots
    var registerItem = await RegisterVotingItemAsync(30, 3, true, DefaultSender, 3);
    
    // Malicious sponsor immediately takes all snapshots in rapid succession
    for (var i = 1; i <= 3; i++)
    {
        var snapshotResult = await VoteContractStub.TakeSnapshot.SendAsync(
            new TakeSnapshotInput
            {
                VotingItemId = registerItem.VotingItemId,
                SnapshotNumber = i
            });
        snapshotResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    }
    
    // Verify all snapshots closed immediately
    var votingItem = await GetVoteItem(registerItem.VotingItemId);
    votingItem.CurrentSnapshotNumber.ShouldBe(4); // All snapshots exhausted
    
    // Attempt to vote - should fail despite being within declared 30-day period
    var voter = Accounts[11].KeyPair;
    var voteResult = await VoteWithException(voter, registerItem.VotingItemId, 
        registerItem.Options[0], 100);
    voteResult.Status.ShouldBe(TransactionResultStatus.Failed);
    voteResult.Error.ShouldContain("Current voting item already ended");
    
    // Verify current time is still within the declared voting period
    var currentTime = TimestampHelper.GetUtcNow();
    Assert.True(currentTime < registerItem.EndTimestamp, 
        "Voting should still be open according to declared timestamps");
}
```

This test demonstrates that despite registering a 30-day voting period, a sponsor can close all snapshots immediately, denying voters their expected participation window.

## Notes

The vulnerability is particularly concerning because the `Register` function explicitly validates timestamp relationships, creating reasonable user expectations that these constraints will be enforced. The contract stores these timestamps in state and exposes them through the public API, yet never uses them for validation during actual operations. This represents a fundamental breach of the implicit contract between the system and its users, enabling arbitrary manipulation of voting timelines regardless of declared parameters.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-22)
```csharp
    public override Empty Register(VotingRegisterInput input)
    {
        var votingItemId = AssertValidNewVotingItem(input);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L45-47)
```csharp
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L245-245)
```csharp
        Assert(votingItem.Sponsor == Context.Sender, "Only sponsor can take snapshot.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L247-248)
```csharp
        Assert(votingItem.CurrentSnapshotNumber - 1 < votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L256-257)
```csharp
        Assert(votingItem.CurrentSnapshotNumber == input.SnapshotNumber,
            $"Can only take snapshot of current snapshot number: {votingItem.CurrentSnapshotNumber}, but {input.SnapshotNumber}");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L361-361)
```csharp
        Assert(input.EndTimestamp > input.StartTimestamp, "Invalid active time.");
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L382-383)
```csharp
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/SnapshotTests.cs (L81-100)
```csharp
        for (var i = 0; i < 3; i++)
        {
            var transactionResult = (await VoteContractStub.TakeSnapshot.SendAsync(
                new TakeSnapshotInput
                {
                    VotingItemId = registerItem.VotingItemId,
                    SnapshotNumber = i + 1
                })).TransactionResult;

            transactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var votingItem = await GetVoteItem(registerItem.VotingItemId);
            votingItem.CurrentSnapshotNumber.ShouldBe(i + 2);
            var voteResult = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
            {
                VotingItemId = registerItem.VotingItemId,
                SnapshotNumber = i + 2
            });
            voteResult.SnapshotNumber.ShouldBe(i + 2);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L64-68)
```csharp
            TotalSnapshotNumber = long.MaxValue,
            StartTimestamp = TimestampHelper.MinValue,
            EndTimestamp = TimestampHelper.MaxValue
        };
        State.VoteContract.Register.Send(votingRegisterInput);
```
