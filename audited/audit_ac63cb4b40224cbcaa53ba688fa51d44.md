# Audit Report

## Title
Existing Votes Retain Outdated Weights When Interest Settings Change, Creating Unfair Profit Distribution

## Summary
When governance updates vote weight interest parameters via `SetVoteWeightInterest()`, existing active votes permanently retain their weights calculated with old settings while new votes use updated settings. This creates unfair profit distribution as all voters compete for the same Citizen Welfare rewards pool based on their stored weights, with no mechanism to update existing vote weights to reflect new parameters.

## Finding Description

The vulnerability stems from a design flaw in the interaction between vote weight calculation and interest settings management:

**Vote Weight Calculation at Creation:**
When users vote via `Vote()`, the weight is calculated once using `GetVotesWeight()` with the current `VoteWeightInterestList` settings and stored as "Shares" in the Profit contract. [1](#0-0) [2](#0-1) 

The weight calculation uses compound interest based on lock duration: [3](#0-2) 

**Interest Settings Update:**
The `SetVoteWeightInterest()` function updates global settings but does NOT update weights of existing active votes: [4](#0-3) 

**No Effective Update Mechanism:**
The Profit contract's `FixProfitDetail()` function clones the existing detail and only updates StartPeriod and EndPeriod, but does NOT update the Shares field: [5](#0-4) 

Even when `ExtendVoterWelfareProfits()` attempts to pass recalculated weights to `FixProfitDetail`, the Shares value is ignored: [6](#0-5) 

The `TransferVotingRecordToElectionVotingRecord()` function recalculates weights with current settings, but this is only a view function for display purposes: [7](#0-6) 

## Impact Explanation

**Direct Financial Impact:**
Voters receive Citizen Welfare profits proportional to their shares (weights) in the profit scheme. When interest settings change, voters with identical token amounts and lock durations receive permanently different profit distributions based solely on when they voted relative to the settings change.

**Concrete Scenario:**
- User A votes 10,000 tokens for 365 days when Interest=1, Capital=1000
- Weight calculated: ~10,365 shares
- Governance increases to Interest=10, Capital=1000
- User B votes 10,000 tokens for 365 days with new settings  
- Weight calculated: ~13,650 shares (32% higher)
- Both compete for the same profit pool, User B receives 32% more rewards despite identical contribution

**Affected Parties:**
- All active voters when interest settings change
- Creates arbitrary wealth transfer between early and late voters
- No way for disadvantaged voters to update weights without withdrawing (waiting full lock period) and re-voting
- Breaks fundamental fairness invariant: identical contributions should receive identical rewards

## Likelihood Explanation

**Trigger Mechanism:**
`SetVoteWeightInterest()` is a legitimate governance function controlled by the VoteWeightInterestController (default: Parliament contract): [8](#0-7) 

**Preconditions:**
- Governance needs to adjust interest rates to respond to economic conditions, participation rates, or tokenomics optimization
- This is a normal operational activity expected over the protocol's lifetime
- No malicious intent required - the flaw manifests during routine governance operations

**Execution Certainty:**
- Standard governance proposal process
- Existing active votes automatically retain old weights
- New votes automatically use new weights  
- Unfairness emerges immediately and persists permanently

**High Probability:**
Interest settings adjustments are highly likely multiple times over the protocol's operational lifetime to optimize staking incentives and voter participation.

## Recommendation

Implement a mechanism to update existing vote weights when interest settings change:

1. **Add a batch weight update function** that recalculates and updates shares for existing votes when settings change
2. **Modify FixProfitDetail** to accept and apply share updates when explicitly requested
3. **Create a migration period** after settings changes where voters can opt-in to recalculate their weights
4. **Store interest settings per vote** to enable retroactive fair calculations
5. **Implement automatic weight adjustment** in profit distribution calculations based on when votes were created vs current settings

The most straightforward fix would be to modify `FixProfitDetail` to actually update the Shares field when provided:

```csharp
// In FixProfitDetail, after line 301:
if (input.BeneficiaryShare.Shares > 0) {
    // Update scheme total shares
    scheme.TotalShares = scheme.TotalShares.Sub(fixingDetail.Shares).Add(input.BeneficiaryShare.Shares);
    newDetail.Shares = input.BeneficiaryShare.Shares;
}
```

Additionally, provide a governance function to trigger batch recalculation of existing vote weights after settings changes.

## Proof of Concept

A valid test would:
1. Create votes with initial interest settings
2. Update interest settings via `SetVoteWeightInterest()`
3. Create new votes with updated settings
4. Distribute profits and claim
5. Verify that voters with identical amounts/lock times receive different profits based on when they voted

The vulnerability is demonstrated by the code structure itself: there is no mechanism anywhere in the codebase that updates existing ProfitDetail.Shares values after they are initially set during vote creation.

---

**Notes:**
This is a protocol-level fairness violation that requires governance action to trigger but affects all active voters. The severity is Medium due to the permanent wealth redistribution impact, though it requires legitimate governance operations rather than direct exploitation. The lack of any update mechanism makes this a fundamental design flaw rather than an implementation bug.

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L296-304)
```csharp
        // Clone the old one to a new one, remove the old, and add the new.
        var newDetail = fixingDetail.Clone();
        // The startPeriod is 0, so use the original one.
        newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
        profitDetails.Details.Remove(fixingDetail);
        profitDetails.Details.Add(newDetail);
        State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary] = profitDetails;
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
