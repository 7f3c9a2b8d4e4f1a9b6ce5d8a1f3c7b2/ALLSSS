### Title
Existing Votes Retain Outdated Weights When Interest Settings Change, Creating Unfair Profit Distribution

### Summary
When `SetVoteWeightInterest()` updates the vote weight interest parameters, existing active votes retain their weights calculated with old settings while new votes use updated settings. This creates permanent unfair advantages or disadvantages in profit distribution, as all voters compete for the same limited Citizen Welfare rewards pool based on their stored weight (shares).

### Finding Description

The vulnerability exists in the interaction between vote weight calculation and interest settings updates:

**Vote Weight Calculation at Creation:**
When users vote via `Vote()`, the weight is calculated once using `GetVotesWeight()` with the current `VoteWeightInterestList` settings. [1](#0-0) 

This calculated weight is stored as "Shares" in the Profit contract via `AddBeneficiaryToVoter()`. [2](#0-1) 

**Interest Settings Update:**
The `SetVoteWeightInterest()` function updates the global interest settings after validation and sorting. [3](#0-2) 

However, this update ONLY modifies the stored settings - it does NOT update the weights (shares) of existing active votes.

**Weight Calculation Logic:**
The `GetVotesWeight()` function iterates through the interest info list to find the applicable tier based on lock days, then calculates weight using that tier's Interest and Capital values. [4](#0-3) 

**No Update Mechanism:**
The Profit contract's `FixProfitDetail()` function can only update `StartPeriod` and `EndPeriod`, but does NOT update the Shares field. [5](#0-4) 

Even when `ChangeVotingOption()` is called with `IsResetVotingTime=true` and triggers `ExtendVoterWelfareProfits()`, the weight passed to `FixProfitDetail` is recalculated with current settings, but the function ignores this value and keeps the original shares. [6](#0-5) 

**View vs. State:**
While `TransferVotingRecordToElectionVotingRecord()` recalculates weights with current settings for display purposes, this is only a view function that doesn't modify stored state. [7](#0-6) 

### Impact Explanation

**Direct Financial Impact:**
Voters receive Citizen Welfare profits proportional to their shares (weights) in the profit scheme. When interest settings change:

- **If interest rates increase:** Early voters who locked tokens before the increase have permanently lower weights than later voters with identical amounts and lock times. They receive unfairly reduced profit distributions.
- **If interest rates decrease:** Early voters have permanently higher weights than later voters, receiving unfairly inflated profit distributions.

**Concrete Example:**
- User A votes 10,000 tokens for 365 days with Interest=1, Capital=1000
- Calculated weight: ~10,365 shares
- Governance increases to Interest=10, Capital=1000
- User B votes 10,000 tokens for 365 days with new settings
- Calculated weight: ~13,650 shares (32% higher)
- Both compete for same profit pool, User B receives 32% more rewards for identical contribution

**Affected Parties:**
- All active voters when interest settings change
- Creates arbitrary wealth transfer between early and late voters
- No way for disadvantaged voters to update their weights without withdrawing (waiting for lock period) and re-voting

**Severity Justification:**
Medium severity due to permanent unfair distribution of protocol rewards based on timing rather than contribution merit, though requires governance action to trigger.

### Likelihood Explanation

**Entry Point:**
`SetVoteWeightInterest()` is a legitimate governance function controlled by the VoteWeightInterestController (default: Parliament contract). [8](#0-7) 

**Preconditions:**
- Governance decides to adjust interest rates to respond to economic conditions, participation rates, or tokenomics optimization
- This is a reasonable operational activity over the protocol's lifetime
- No malicious intent required - the flaw manifests during normal governance operations

**Execution Practicality:**
- Standard governance proposal process
- No special attacker capabilities needed
- Existing active votes automatically retain old weights
- New votes automatically use new weights
- The unfairness emerges immediately and persists

**Feasibility:**
High probability that interest settings will be adjusted multiple times over the protocol's operational lifetime to optimize staking incentives and voter participation.

**Economic Rationality:**
No exploit cost - this is a design flaw that creates unfairness during routine governance operations.

### Recommendation

**Implement Weight Migration Mechanism:**

1. Add a batch update function to recalculate and update weights for existing active votes when interest settings change:

```csharp
public override Empty MigrateVoteWeights(MigrateVoteWeightsInput input) 
{
    AssertPerformedByVoteWeightInterestController();
    
    foreach (var voteId in input.VoteIds) 
    {
        var votingRecord = State.VoteContract.GetVotingRecord.Call(voteId);
        if (votingRecord.IsWithdrawn) continue;
        
        var lockSeconds = State.LockTimeMap[voteId];
        var newWeight = GetVotesWeight(votingRecord.Amount, lockSeconds);
        
        // Remove old beneficiary entry
        RemoveBeneficiaryOfVoter(votingRecord.Voter);
        
        // Re-add with new weight
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = votingRecord.Voter,
                Shares = newWeight
            },
            EndPeriod = GetEndPeriod(lockSeconds),
            ProfitDetailId = voteId
        });
    }
    return new Empty();
}
```

2. Automatically trigger migration or provide clear notification to voters when interest settings change.

3. Add invariant check: Verify that weight calculation for a given amount/locktime is consistent with current settings.

**Test Cases:**
- Verify weights are correctly recalculated after interest settings change
- Test that profit distribution is fair between votes before and after settings change
- Ensure migration handles edge cases (expired votes, partially claimed profits)

### Proof of Concept

**Initial State:**
- Default VoteWeightInterest: Day=365, Interest=1, Capital=1000
- Two users ready to vote with 10,000 tokens each for 365 days

**Transaction Sequence:**

1. **User A votes before settings change:**
   - Call `Vote(amount=10000, lockDays=365)`
   - Weight calculated: (1 + 1/1000)^365 * 10000 ≈ 14,396 shares
   - Stored in Profit contract with 14,396 shares

2. **Governance changes interest settings:**
   - Call `SetVoteWeightInterest(Day=365, Interest=10, Capital=1000)`
   - Settings updated globally
   - User A's stored weight: remains 14,396 shares (NOT updated)

3. **User B votes after settings change:**
   - Call `Vote(amount=10000, lockDays=365)`
   - Weight calculated: (1 + 10/1000)^365 * 10000 ≈ 236,736 shares
   - Stored in Profit contract with 236,736 shares

4. **Profit distribution:**
   - Total shares: 14,396 + 236,736 = 251,132
   - User A share: 14,396 / 251,132 = 5.7%
   - User B share: 236,736 / 251,132 = 94.3%
   - User B receives 16.4x more rewards despite identical contribution

**Expected Result:**
Both users should receive equal rewards for equal amounts and lock times.

**Actual Result:**
User B receives vastly disproportionate rewards due to timing, creating permanent unfairness.

**Success Condition:**
Demonstrate that User A's stored shares remain unchanged after `SetVoteWeightInterest()`, while User B's shares use new calculation, resulting in dramatically different profit distributions for identical voting behavior.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L144-154)
```csharp
            State.ProfitContract.FixProfitDetail.Send(new FixProfitDetailInput
            {
                SchemeId = State.WelfareHash.Value,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = electionVotingRecord.Voter,
                    Shares = electionVotingRecord.Weight
                },
                EndPeriod = endPeriod,
                ProfitDetailId = voteId
            });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L189-208)
```csharp
    public override Empty SetVoteWeightInterest(VoteWeightInterestList input)
    {
        AssertPerformedByVoteWeightInterestController();
        Assert(input.VoteWeightInterestInfos.Count > 0, "invalid input");
        // ReSharper disable once PossibleNullReferenceException
        foreach (var info in input.VoteWeightInterestInfos)
        {
            Assert(info.Capital > 0, "invalid input");
            Assert(info.Day > 0, "invalid input");
            Assert(info.Interest > 0, "invalid input");
        }

        Assert(input.VoteWeightInterestInfos.GroupBy(x => x.Day).Count() == input.VoteWeightInterestInfos.Count,
            "repeat day input");
        var orderList = input.VoteWeightInterestInfos.OrderBy(x => x.Day).ToArray();
        input.VoteWeightInterestInfos.Clear();
        input.VoteWeightInterestInfos.AddRange(orderList);
        State.VoteWeightInterestList.Value = input;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L443-443)
```csharp
        AddBeneficiaryToVoter(GetVotesWeight(input.Amount, lockSeconds), lockSeconds, voteId);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L296-303)
```csharp
        // Clone the old one to a new one, remove the old, and add the new.
        var newDetail = fixingDetail.Clone();
        // The startPeriod is 0, so use the original one.
        newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
        profitDetails.Details.Remove(fixingDetail);
        profitDetails.Details.Add(newDetail);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L337-355)
```csharp
    private ElectionVotingRecord TransferVotingRecordToElectionVotingRecord(VotingRecord votingRecord, Hash voteId)
    {
        var lockSeconds = State.LockTimeMap[voteId];
        return new ElectionVotingRecord
        {
            Voter = votingRecord.Voter,
            Candidate = GetNewestPubkey(votingRecord.Option),
            Amount = votingRecord.Amount,
            TermNumber = votingRecord.SnapshotNumber,
            VoteId = voteId,
            LockTime = lockSeconds,
            VoteTimestamp = votingRecord.VoteTimestamp,
            WithdrawTimestamp = votingRecord.WithdrawTimestamp,
            UnlockTimestamp = votingRecord.VoteTimestamp.AddSeconds(lockSeconds),
            IsWithdrawn = votingRecord.IsWithdrawn,
            Weight = GetVotesWeight(votingRecord.Amount, lockSeconds),
            IsChangeTarget = votingRecord.IsChangeTarget
        };
    }
```
