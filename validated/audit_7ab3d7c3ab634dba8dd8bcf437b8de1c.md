# Audit Report

## Title
Quadratic Voting Cost Progression Broken for Locked Token Voting

## Summary
The quadratic voting implementation in the Vote contract fails to enforce quadratic cost progression when both `IsQuadratic` and `IsLockToken` flags are true. Each vote transaction generates a unique `VoteId` based on the cumulative `VotesAmount`, causing the `QuadraticVotesCountMap` to reset to zero for every vote. This results in a constant cost of `TicketCost * 1` per vote instead of the intended quadratically increasing cost (`TicketCost * 1, 2, 3...`), completely defeating the vote-buying resistance mechanism of quadratic voting.

## Finding Description

The vulnerability exists in the `Vote` method's interaction with `AssertValidVoteInput` when processing quadratic locked token votes.

**Root Cause:**

When `IsLockToken` is true, the `VoteId` is generated dynamically based on the current cumulative `VotesAmount` [1](#0-0) . Since `VotesAmount` increases after each vote [2](#0-1) , every subsequent vote generates a different `VoteId`.

The quadratic cost calculation retrieves the count from `QuadraticVotesCountMap` using this `VoteId` as the key [3](#0-2) . Since each `VoteId` is unique, the map lookup always returns zero, resulting in `currentVotesCount = 1` for every vote.

**Execution Flow for a Voter Making 3 Votes:**

1. **First Vote**: `VotesAmount = 0` → `VoteId` = hash(0) → `QuadraticVotesCountMap[hash(0)] = 1` → Cost = `TicketCost * 1`
2. **Second Vote**: `VotesAmount = TicketCost` → `VoteId` = hash(TicketCost) → `QuadraticVotesCountMap[hash(TicketCost)] = 1` → Cost = `TicketCost * 1` ⚠️
3. **Third Vote**: `VotesAmount = 2*TicketCost` → `VoteId` = hash(2*TicketCost) → `QuadraticVotesCountMap[hash(2*TicketCost)] = 1` → Cost = `TicketCost * 1` ⚠️

**Why Protections Fail:**

The `Register` method accepts both `IsQuadratic` and `IsLockToken` flags without any validation preventing their combination [4](#0-3) . The validation method `AssertValidNewVotingItem` performs no checks on flag compatibility [5](#0-4) .

## Impact Explanation

**Severity: HIGH**

This vulnerability breaks the fundamental security guarantee of quadratic voting: preventing wealthy actors from cheaply dominating votes. The impacts include:

1. **Token Economics Manipulation**: Voters pay O(N) cost instead of O(N²) for N votes. For 100 votes with `TicketCost=1000`:
   - **Intended cost**: 1000 * (1+2+...+100) = **5,050,000 tokens**
   - **Actual cost**: 1000 * 100 = **100,000 tokens**
   - **Attacker savings**: 4,950,000 tokens (98% discount)

2. **Governance Integrity Compromise**: Any voting item created with both flags becomes vulnerable to cheap vote buying, nullifying the democratic properties quadratic voting is designed to provide.

3. **Protocol Design Violation**: The feature is explicitly labeled as "quadratic" [6](#0-5)  but provides no quadratic cost progression, misleading users and sponsors about the security properties.

**Affected Parties:**
- Honest voters who vote conservatively (few times) pay proportionally fair costs
- Vote sponsors who expect quadratic cost enforcement to prevent vote buying
- The overall governance system's integrity and fairness

## Likelihood Explanation

**Probability: VERY HIGH**

The vulnerability is immediately exploitable with no barriers:

1. **Public Access**: The `Register` method is public [7](#0-6)  and the `Vote` method is public [8](#0-7) . Any address can create vulnerable voting items and exploit them.

2. **Trivial Attack Complexity**: 
   - Step 1: Call `Register` with `IsQuadratic=true`, `IsLockToken=true`, and a low `TicketCost`
   - Step 2: Call `Vote` multiple times to acquire votes at constant cost
   
3. **No Preconditions**: The vulnerability works immediately with no special contract state or timing requirements.

4. **Low Detection Risk**: The exploit appears as normal voting activity. Without analyzing the `QuadraticVotesCountMap` entries for each unique `VoteId`, the constant costs are not apparent on-chain.

5. **Economic Incentive**: The cost savings are massive (up to 98% for large vote counts), providing strong motivation for exploitation.

## Recommendation

**Fix the VoteId Generation for Locked Token Voting:**

The `VoteId` for locked token voting should uniquely identify a voter-voting item pair, not be based on the cumulative `VotesAmount`. Modify line 397 in `AssertValidVoteInput`:

**Current (Vulnerable):**
```csharp
input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
```

**Recommended Fix:**
```csharp
input.VoteId = Context.GenerateId(Context.Self, 
    HashHelper.ConcatAndCompute(
        votingItem.VotingItemId, 
        HashHelper.ComputeFrom(Context.Sender)
    ).ToBytes());
```

This ensures each voter has a consistent `VoteId` for a given voting item, allowing `QuadraticVotesCountMap` to properly accumulate their vote count and enforce quadratic cost progression.

**Alternative: Add Validation to Prevent the Flag Combination:**

If quadratic voting with locked tokens is not intended to be supported, add validation in `AssertValidNewVotingItem` or `Register`:

```csharp
Assert(!(input.IsQuadratic && input.IsLockToken), 
    "Quadratic voting cannot be combined with locked token voting.");
```

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_LockedToken_ConstantCost_Vulnerability()
{
    // Register a quadratic voting item with locked tokens
    const long ticketCost = 1000_0000_0000; // 1000 ELF
    var startTime = TimestampHelper.GetUtcNow();
    var input = new VotingRegisterInput
    {
        TotalSnapshotNumber = 1,
        EndTimestamp = startTime.AddDays(10),
        StartTimestamp = startTime,
        Options = { "Option1", "Option2" },
        AcceptedCurrency = TestTokenSymbol,
        IsLockToken = true,
        IsQuadratic = true,
        TicketCost = ticketCost
    };
    
    await VoteContractStub.Register.SendAsync(input);
    input.Options.Clear();
    var votingItemId = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(input), 
        HashHelper.ComputeFrom(DefaultSender));
    
    var user = Accounts[1];
    var initialBalance = GetUserBalance(user.Address);
    
    // Vote 3 times - should cost 1000 + 2000 + 3000 = 6000 ELF (quadratic)
    // But actually costs 1000 + 1000 + 1000 = 3000 ELF (constant)
    var userStub = GetVoteContractTester(user.KeyPair);
    await userStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "Option1",
        Amount = 0 // Amount ignored for quadratic voting
    });
    
    await userStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "Option1",
        Amount = 0
    });
    
    await userStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItemId,
        Option = "Option1",
        Amount = 0
    });
    
    var finalBalance = GetUserBalance(user.Address);
    var totalCost = initialBalance - finalBalance;
    
    // Verify vulnerability: cost should be 6000 ELF but is only 3000 ELF
    var expectedQuadraticCost = ticketCost * 6; // 1+2+3 = 6
    var actualConstantCost = ticketCost * 3; // 1+1+1 = 3
    
    totalCost.ShouldBe(actualConstantCost); // Proves constant cost (vulnerable)
    totalCost.ShouldNotBe(expectedQuadraticCost); // Should be quadratic but isn't
    
    // Attacker saves 50% on 3 votes, up to 98% on 100 votes
}
```

## Notes

This vulnerability only affects voting items where **both** `IsQuadratic=true` **and** `IsLockToken=true`. Voting items with only one of these flags enabled do not exhibit this behavior:

- **IsQuadratic=false, IsLockToken=true**: Normal locked token voting works correctly (uses `Amount` parameter)
- **IsQuadratic=true, IsLockToken=false**: Delegated quadratic voting allows the sponsor to provide a consistent `VoteId`, though this still lacks proper per-voter tracking

The core issue is that the `VoteId` generation for locked token voting (line 397) uses a continuously changing value (`VotesAmount`) as the seed, when it should use a stable voter-specific identifier to enable proper vote count accumulation in the `QuadraticVotesCountMap`.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-20)
```csharp
    public override Empty Register(VotingRegisterInput input)
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L37-52)
```csharp
        var votingItem = new VotingItem
        {
            Sponsor = Context.Sender,
            VotingItemId = votingItemId,
            AcceptedCurrency = input.AcceptedCurrency,
            IsLockToken = input.IsLockToken,
            TotalSnapshotNumber = input.TotalSnapshotNumber,
            CurrentSnapshotNumber = 1,
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
            RegisterTimestamp = Context.CurrentBlockTime,
            Options = { input.Options },
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
        };
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-90)
```csharp
    public override Empty Vote(VoteInput input)
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L100-102)
```csharp
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L179-179)
```csharp
        votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L397-397)
```csharp
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
```

**File:** protobuf/vote_contract.proto (L100-103)
```text
    // Is quadratic voting.
    bool is_quadratic = 7;
    // Quadratic voting item ticket cost.
    int64 ticket_cost = 8;
```
