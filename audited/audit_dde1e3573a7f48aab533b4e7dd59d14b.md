### Title
Vote Weight Proportion Changes Create Unfair Profit Distribution Without Retroactive Updates

### Summary
The `SetVoteWeightProportion()` function allows governance to change the vote weight calculation parameters, but existing votes retain their original weight (shares in the profit scheme) while new votes use the updated proportion. This enables governance to manipulate timing of proportion changes to favor specific voters, creating unfair profit distribution where identical economic commitments (same token amount and lock duration) receive different rewards based solely on when the vote was cast.

### Finding Description

The vulnerability exists in the interaction between `SetVoteWeightProportion()` and the vote weight calculation system: [1](#0-0) 

When `SetVoteWeightProportion()` is called, it only updates the state variable without any retroactive recalculation mechanism.

The root cause is that vote weights are calculated once during voting and stored permanently as shares in the Profit contract: [2](#0-1) 

The calculated weight becomes fixed shares when added to the profit scheme: [3](#0-2) 

These shares are permanently stored in the Profit contract and used for all future profit distributions: [4](#0-3) 

The profit distribution uses these fixed shares in the calculation formula: [5](#0-4) 

Evidence that retroactive updates were intended but never implemented exists in the proto definition: [6](#0-5) 

However, no implementation of `FixTotalWeights` exists in the codebase, leaving the system vulnerable to manipulation.

### Impact Explanation

**Concrete Harm:**
When `VoteWeightProportion` changes, users voting with identical parameters (same token amount and lock duration) receive significantly different profit shares:

Example calculation with 100,000 tokens locked for 365 days:
- **Before change** (TimeProportion=2, AmountProportion=1): base weight component = 100,000 × 1/2 = 50,000 shares
- **After change** (TimeProportion=1, AmountProportion=1): base weight component = 100,000 × 1/1 = 100,000 shares

This 50,000 share difference means User B (voting after the change) receives approximately 2x the profit share compared to User A (voting before the change) for identical economic commitment, violating fundamental fairness principles.

**Who is Affected:**
- All voters who vote after a proportion change are affected relative to earlier voters
- The impact accumulates across all profit distributions over the vote's lifetime
- Voters with longer lock periods suffer greater total profit loss

**Severity Justification:**
Medium severity because while it doesn't enable direct fund theft, it creates systematic reward misallocation that can be intentionally exploited by governance to benefit specific parties at the expense of others.

### Likelihood Explanation

**Attacker Capabilities:**
The "attacker" is the governance system (Parliament contract by default), which can propose and execute `SetVoteWeightProportion()` changes: [7](#0-6) 

**Attack Complexity:**
LOW - Requires only a standard parliament proposal to change proportions. The execution path is straightforward:
1. Observe that favorable parties are about to vote (or coordinate timing)
2. Submit parliament proposal to change VoteWeightProportion
3. Execute proposal before target votes are cast
4. Target parties vote and receive more favorable shares
5. Optionally change proportions back afterward

**Feasibility:**
HIGH - Parliament proposals are a normal governance mechanism. While changes are visible on-chain, by the time the community reacts, votes have already been cast with the manipulated proportions and those shares are permanently fixed.

**Detection Constraints:**
The manipulation is partially visible (proportion changes are public) but the intent and targeting are difficult to prove since changes affect all subsequent votes, not just specific addresses.

**Probability:**
MEDIUM - Requires governance coordination and timing, but the incentive exists when governance members or allies are significant voters. The lack of retroactive correction mechanism makes the impact permanent.

### Recommendation

**Code-Level Mitigation:**

1. Implement the `FixTotalWeights` method that was defined in the proto but never implemented, allowing retroactive weight updates:

```csharp
public override Empty FixTotalWeights(FixTotalWeightsInput input)
{
    AssertPerformedByVoteWeightInterestController();
    
    foreach (var voteId in input.VoteIds)
    {
        var votingRecord = State.VoteContract.GetVotingRecord.Call(voteId);
        Assert(!votingRecord.IsWithdrawn, "Cannot fix withdrawn vote");
        
        var lockSeconds = State.LockTimeMap[voteId];
        var newWeight = GetVotesWeight(votingRecord.Amount, lockSeconds);
        
        // Update profit detail with new weight
        State.ProfitContract.FixProfitDetail.Send(new FixProfitDetailInput
        {
            SchemeId = State.WelfareHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = votingRecord.Voter,
                Shares = newWeight
            },
            ProfitDetailId = voteId
        });
        
        State.WeightsAlreadyFixedMap[voteId] = true;
    }
    
    return new Empty();
}
```

2. Add automatic weight recalculation trigger in `SetVoteWeightProportion()` or require calling `FixTotalWeights` for all active votes before the proportion change takes effect.

3. Add invariant check to ensure weight consistency:
```csharp
Assert(State.WeightsAlreadyFixedMap[voteId] || IsWeightConsistentWithCurrentSettings(voteId),
    "Vote weights must be updated before proportion changes take effect");
```

**Test Cases:**
- Test that changing proportions and calling FixTotalWeights updates existing vote shares correctly
- Test that identical votes before and after proportion changes receive equal shares after fixing
- Test that profit distribution uses updated weights correctly

### Proof of Concept

**Initial State:**
- VoteWeightProportion: TimeProportion=2, AmountProportion=1
- User A prepares to vote 100,000 tokens for 365 days
- User B prepares to vote 100,000 tokens for 365 days (identical to A)

**Attack Sequence:**

1. **User A votes** (before proportion change):
   - Calls `Vote()` with 100,000 tokens, 365-day lock
   - `GetVotesWeight()` calculates: weight = compound_interest + (100,000 × 1/2) = compound_interest + 50,000
   - User A receives approximately 50,000 base shares (plus compound interest component)

2. **Governance changes proportion** (via Parliament proposal):
   - Calls `SetVoteWeightProportion()` with TimeProportion=1, AmountProportion=1
   - State updates but no existing votes are recalculated

3. **User B votes** (after proportion change):
   - Calls `Vote()` with 100,000 tokens, 365-day lock (identical parameters to User A)
   - `GetVotesWeight()` now calculates: weight = compound_interest + (100,000 × 1/1) = compound_interest + 100,000
   - User B receives approximately 100,000 base shares (plus compound interest component)

4. **Profit Distribution occurs:**
   - Both users receive profits proportional to their shares
   - User B receives ~2x the profit share of User A for the base weight component, despite identical economic commitment

**Expected vs Actual:**
- **Expected:** Users A and B receive equal profit shares for equal economic commitment
- **Actual:** User B receives significantly more profit shares than User A due to proportion change timing

**Success Condition:**
Query both users' profit shares and verify User B has approximately 2x the base weight shares of User A despite identical vote parameters, demonstrating the unfair advantage created by governance timing manipulation.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L210-216)
```csharp
    public override Empty SetVoteWeightProportion(VoteWeightProportion input)
    {
        AssertPerformedByVoteWeightInterestController();
        Assert(input.TimeProportion > 0 && input.AmountProportion > 0, "invalid input");
        State.VoteWeightProportion.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L369-383)
```csharp
    private void AddBeneficiaryToVoter(long votesWeight, long lockSeconds, Hash voteId)
    {
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = votesWeight
            },
            EndPeriod = GetEndPeriod(lockSeconds),
            // one vote, one profit detail, so voteId equals to profitDetailId
            ProfitDetailId = voteId
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L385-391)
```csharp
    private void AssertPerformedByVoteWeightInterestController()
    {
        if (State.VoteWeightInterestController.Value == null)
            State.VoteWeightInterestController.Value = GetDefaultVoteWeightInterestController();

        Assert(Context.Sender == State.VoteWeightInterestController.Value.OwnerAddress, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L573-592)
```csharp
    private long GetVotesWeight(long votesAmount, long lockTime)
    {
        var lockDays = lockTime.Div(DaySec);
        var timeAndAmountProportion = GetVoteWeightProportion();
        if (State.VoteWeightInterestList.Value == null)
            State.VoteWeightInterestList.Value = GetDefaultVoteWeightInterest();
        foreach (var instMap in State.VoteWeightInterestList.Value.VoteWeightInterestInfos)
        {
            if (lockDays > instMap.Day)
                continue;
            var initBase = 1 + (decimal)instMap.Interest / instMap.Capital;
            return ((long)(Pow(initBase, (uint)lockDays) * votesAmount)).Add(votesAmount
                .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
        }

        var maxInterestInfo = State.VoteWeightInterestList.Value.VoteWeightInterestInfos.Last();
        var maxInterestBase = 1 + (decimal)maxInterestInfo.Interest / maxInterestInfo.Capital;
        return ((long)(Pow(maxInterestBase, (uint)lockDays) * votesAmount)).Add(votesAmount
            .Mul(timeAndAmountProportion.AmountProportion).Div(timeAndAmountProportion.TimeProportion));
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L186-192)
```csharp
        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L956-962)
```csharp
    private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
    {
        var decimalTotalAmount = (decimal)totalAmount;
        var decimalShares = (decimal)shares;
        var decimalTotalShares = (decimal)totalShares;
        return (long)(decimalTotalAmount * decimalShares / decimalTotalShares);
    }
```

**File:** protobuf/election_contract.proto (L530-533)
```text
message FixTotalWeightsInput {
    repeated aelf.Hash vote_ids = 1;
    
}
```
