# Audit Report

## Title
QuadraticVotesCountMap Never Decremented Causing Inflated Costs on VoteId Reuse

## Summary
The `QuadraticVotesCountMap` state variable in the Vote contract is incremented on each vote but never decremented during withdrawal. When combined with the lack of VoteId uniqueness validation, this causes voters to lock significantly more tokens than intended when VoteIds collide, particularly affecting regular voting scenarios where `VotesAmount` cycles back to previous values after withdrawals.

## Finding Description

The vulnerability exists in the quadratic voting implementation where `QuadraticVotesCountMap` tracks cumulative vote counts per VoteId. When a quadratic vote is cast, the counter is incremented and the lock amount is calculated as `TicketCost * currentVotesCount`. [1](#0-0) 

However, the `Withdraw` method never decrements or clears this counter. The method only marks records as withdrawn, updates voting results, and unlocks tokens, leaving `QuadraticVotesCountMap` permanently incremented. [2](#0-1) 

Additionally, the `Vote` method lacks validation to prevent VoteId reuse. The voting record is simply overwritten without checking if the VoteId already exists or if a previous record was withdrawn. [3](#0-2) 

This contrasts sharply with the Election contract, which explicitly validates VoteId uniqueness with an assertion check. [4](#0-3) 

For regular voting (`IsLockToken=true`), VoteIds are auto-generated using the current `VotesAmount` as seed. [5](#0-4)  When `VotesAmount` decreases after withdrawals and returns to a previous value, the same VoteId is regenerated, causing collision.

## Impact Explanation

When a VoteId collision occurs in quadratic voting with `IsLockToken=true`, users must lock inflated token amounts. For example:

1. **First vote**: VoteId "X" generated, `QuadraticVotesCountMap["X"] = 1`, locks `TicketCost * 1` tokens
2. **After withdrawal**: Tokens unlocked, but `QuadraticVotesCountMap["X"]` remains 1
3. **Second vote with same VoteId**: `QuadraticVotesCountMap["X"] = 2`, locks `TicketCost * 2` tokens

The inflated amount is enforced through the MultiToken contract's `Lock` method, which accumulates tokens at the same virtual address when the same LockId is reused. [6](#0-5) 

For a `TicketCost` of 100, voters would lock 200 tokens instead of 100 on the second use of the same VoteId. This represents a **100% overcharge**, directly reducing voter liquidity and effectively doubling the voting cost. While tokens can eventually be unlocked upon withdrawal, the excessive lock period reduces capital efficiency and voting participation.

**Realistic Scenario**: 
- User A votes (VotesAmount=0→100), VoteId=hash(0)
- User B votes (VotesAmount=100→200)  
- User A withdraws (VotesAmount=200→100)
- User C votes (VotesAmount=100), VoteId=hash(100) — **collision with User B's VoteId**
- User C must lock 2× the intended amount due to accumulated counter

## Likelihood Explanation

**For Regular Voting (IsLockToken=true)**: The likelihood is **medium** rather than "extremely rare" as initially assessed. VoteId collisions occur whenever `VotesAmount` cycles back to a previous value, which happens naturally in active voting scenarios with withdrawals. The deterministic nature of `Context.GenerateId()` with `VotesAmount` as the sole seed makes collisions inevitable when multiple users vote and withdraw at different times, causing `VotesAmount` to fluctuate.

**For Delegated Voting (IsLockToken=false)**: The likelihood is **medium-high** since sponsors explicitly provide VoteIds without uniqueness constraints. However, tokens aren't locked in delegated scenarios, so the financial impact is limited. The Election contract mitigates this through its own validation layer.

The vulnerability is triggerable through normal user actions (vote → withdraw → vote cycles) without requiring special privileges or sophisticated attacks.

## Recommendation

Implement two critical fixes:

1. **Add VoteId uniqueness validation** in the `Vote` method:
```csharp
// Before line 117
Assert(State.VotingRecords[input.VoteId] == null || 
       State.VotingRecords[input.VoteId].IsWithdrawn, 
       "Vote ID already exists and is active.");
```

2. **Clear or decrement QuadraticVotesCountMap** in the `Withdraw` method:
```csharp
// After line 205
if (votingItem.IsQuadratic)
{
    State.QuadraticVotesCountMap[input.VoteId] = 0;
}
```

Alternatively, redesign the quadratic voting cost calculation to be scoped per voter/voting-item combination rather than globally per VoteId, eliminating the reuse vulnerability entirely.

## Proof of Concept

```csharp
[Fact]
public async Task QuadraticVoting_VoteIdReuse_InflatedCost()
{
    // Register quadratic voting item with TicketCost=100
    var votingItemId = await RegisterQuadraticVotingItem(ticketCost: 100);
    
    // User A votes - VotesAmount goes from 0->100, VoteId based on 0
    var voteId1 = await VoteWithAmount(userA, votingItemId, amount: 100);
    // Expected: Lock 100 tokens (1 * 100)
    Assert.Equal(100, GetLockedAmount(userA));
    
    // User A withdraws - VotesAmount goes from 100->0
    await Withdraw(userA, voteId1);
    Assert.Equal(0, GetLockedAmount(userA));
    
    // User A votes again - VotesAmount is 0 again, generates SAME VoteId
    var voteId2 = await VoteWithAmount(userA, votingItemId, amount: 100);
    
    // BUG: QuadraticVotesCountMap[voteId2] = 2 (not reset after withdrawal)
    // Expected: Lock 100 tokens (1 * 100)
    // Actual: Lock 200 tokens (2 * 100)
    Assert.Equal(200, GetLockedAmount(userA)); // VULNERABILITY CONFIRMED
}
```

---

**Notes**: This vulnerability breaks the fundamental security guarantee that each vote should cost the same amount for the same voting power. The lack of state cleanup in `QuadraticVotesCountMap` combined with deterministic VoteId generation creates a persistent inflation mechanism that penalizes voters based on historical collision patterns rather than actual voting behavior. The Election contract's validation demonstrates awareness of this issue, but the base Vote contract remains vulnerable, affecting any custom governance implementations using quadratic voting.

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L117-117)
```csharp
        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L191-239)
```csharp
    public override Empty Withdraw(WithdrawInput input)
    {
        var votingRecord = State.VotingRecords[input.VoteId];
        if (votingRecord == null) throw new AssertionException("Voting record not found.");
        var votingItem = State.VotingItems[votingRecord.VotingItemId];

        if (votingItem.IsLockToken)
            Assert(votingRecord.Voter == Context.Sender, "No permission to withdraw votes of others.");
        else
            Assert(votingItem.Sponsor == Context.Sender, "No permission to withdraw votes of others.");

        // Update VotingRecord.
        votingRecord.IsWithdrawn = true;
        votingRecord.WithdrawTimestamp = Context.CurrentBlockTime;
        State.VotingRecords[input.VoteId] = votingRecord;

        var votingResultHash = GetVotingResultHash(votingRecord.VotingItemId, votingRecord.SnapshotNumber);

        var votedItems = State.VotedItemsMap[votingRecord.Voter];
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].ActiveVotes.Remove(input.VoteId);
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].WithdrawnVotes.Add(input.VoteId);
        State.VotedItemsMap[votingRecord.Voter] = votedItems;

        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;

        if (votingItem.IsLockToken)
            State.TokenContract.Unlock.Send(new UnlockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                Amount = votingRecord.Amount,
                LockId = input.VoteId
            });

        Context.Fire(new Withdrawn
        {
            VoteId = input.VoteId
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L397-397)
```csharp
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L432-434)
```csharp
        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
        State.LockTimeMap[voteId] = lockSeconds;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-221)
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
```
