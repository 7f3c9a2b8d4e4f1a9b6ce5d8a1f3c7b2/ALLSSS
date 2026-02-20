# Audit Report

## Title
Vote Target Change Denial of Service for Legacy Votes After Weight Settings Update

## Summary
Legacy votes created before the `ProfitDetailId` feature cannot change targets with extended profit periods (`IsResetVotingTime=true`) after governance updates vote weight calculation settings. The vulnerability occurs because weight recalculation using current settings breaks the shares-based fallback matching mechanism for legacy profit details, causing transaction failures that block legitimate voting operations.

## Finding Description

The vulnerability exists in the interaction between the Election contract's vote target change flow and the Profit contract's legacy vote handling mechanism.

**Vote Creation and Profit Detail Storage:**

When users create votes, `AddBeneficiaryToVoter()` registers them as beneficiaries in the CitizenWelfare profit scheme with shares equal to their vote weight calculated at creation time: [1](#0-0) 

The vote weight is calculated using `GetVotesWeight()` which applies formulas based on the current `VoteWeightInterestList` and `VoteWeightProportion` settings: [2](#0-1) 

**Governance Weight Settings Updates:**

Governance can legitimately update these weight calculation parameters through Parliament-controlled methods: [3](#0-2) 

**Vote Target Change with Extended Profit Period:**

When users change their vote target with `IsResetVotingTime=true` to extend their profit earning period, the system calls `ExtendVoterWelfareProfits()`: [4](#0-3) 

This function retrieves the election voting record, which **recalculates the weight using current settings** (not the original settings from vote creation): [5](#0-4) [6](#0-5) 

**Lookup Failure for Legacy Votes:**

The system attempts to find the existing profit detail using two strategies: [7](#0-6) 

For legacy votes created before the `ProfitDetailId` feature:
1. **ID matching fails** - stored profit details have `Id = null`, search looks for `voteId`
2. **Shares matching fails** - compares **recalculated weight** (using current settings) against **stored shares** (calculated with old settings)

If governance changed weight settings between vote creation and target change, these values will not match.

**Transaction Failure:**

When no profit detail is found, the transaction throws an exception and reverts: [8](#0-7) 

The same issue exists in the Profit contract's `FixProfitDetail` method with identical fallback logic: [9](#0-8) 

## Impact Explanation

**Affected Users:** All holders of legacy votes (created before `ProfitDetailId` feature) attempting to change vote targets after any governance weight settings update.

**Concrete Harm:**

1. **Denial of Service** - Users cannot change vote targets with `IsResetVotingTime=true`, losing the ability to extend their profit earning periods when switching candidates
2. **Economic Loss** - Users must choose between:
   - Keeping their current vote target (losing voting flexibility)
   - Changing target with `IsResetVotingTime=false` (losing remaining profit period extension)

**Quantification:** For a vote with 6 months remaining from a 12-month lock:
- With `IsResetVotingTime=true` (blocked): Would receive 12 additional months of CitizenWelfare distributions
- With `IsResetVotingTime=false` (forced): Only 6 months of distributions remain
- **Loss:** 12 months of profit scheme distributions per affected vote

**Scope:** Affects ALL legacy votes system-wide after a single weight settings update.

**Severity:** Medium - Protocol-level DoS of core voting functionality causing measurable economic loss to legitimate users.

## Likelihood Explanation

**Trigger Mechanism:** Legitimate governance actions, not malicious attacks.

**Preconditions:**
1. Legacy votes exist (explicitly supported by code comments and fallback mechanisms)
2. Governance updates weight settings via `SetVoteWeightInterest` or `SetVoteWeightProportion`

**Feasibility:** HIGH - Weight settings updates are:
- Parliament-authorized governance operations
- Economically rational (optimizing staking incentives, fixing suboptimal formulas)
- Explicitly tested in the test suite: [10](#0-9) 

**Probability:** MEDIUM-HIGH - Weight adjustments are expected during normal protocol operations to respond to economic conditions.

## Recommendation

Store the original weight calculation settings with each vote or profit detail to enable accurate matching during legacy vote operations. Alternatively, implement a migration mechanism to add `ProfitDetailId` to all existing legacy profit details.

**Suggested Fix:**

Modify `GetProfitDetailByElectionVotingRecord()` to use the stored lock time and vote amount to recalculate weight with the ORIGINAL settings stored at vote creation time, rather than current settings. This requires storing the active `VoteWeightInterestList` and `VoteWeightProportion` snapshots with each vote.

Alternatively, add a one-time migration function to populate `ProfitDetailId` for all legacy profit details by matching them to their corresponding vote IDs through other identifying information.

## Proof of Concept

A valid PoC would require:
1. Creating a vote under original weight settings
2. Updating weight settings via governance
3. Attempting to call `ChangeVotingOption` with `IsResetVotingTime=true`
4. Observing the transaction failure due to profit detail lookup mismatch

This can be demonstrated by extending the existing test suite with a scenario that changes weight settings between vote creation and vote target change operations.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L33-37)
```csharp
        if (input.IsResetVotingTime)
        {
            // true for extend EndPeroid of a Profit details, e.g. you vote for 12 months, and on the 6th month, you
            // change the vote, then there will be another 12 months from that time.
            ExtendVoterWelfareProfits(input.VoteId);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L126-129)
```csharp
    private void ExtendVoterWelfareProfits(Hash voteId)
    {
        var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
        var electionVotingRecord = GetElectionVotingRecordByVoteId(voteId);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L156-160)
```csharp
        else
        {
            throw new AssertionException($"Cannot find profit detail of given vote id {voteId}");
        }
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L168-185)
```csharp
    private ProfitDetail GetProfitDetailByElectionVotingRecord(ElectionVotingRecord electionVotingRecord)
    {
        var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = electionVotingRecord.Voter,
            SchemeId = State.WelfareHash.Value
        });

        // In new rules, profitDetail.Id equals to its vote id.
        ProfitDetail profitDetail = profitDetails.Details.FirstOrDefault(d => d.Id == electionVotingRecord.VoteId);
        // However, in the old world, profitDetail.Id is null, so use Shares.
        if (profitDetail == null)
        {
            profitDetail = profitDetails.Details.LastOrDefault(d => d.Shares == electionVotingRecord.Weight);
        }

        return profitDetail;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L189-216)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L275-294)
```csharp
        // Try to get profitDetails by Id
        var profitDetails = State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary];
        ProfitDetail fixingDetail = null;
        if (input.ProfitDetailId != null)
        {
            // In new rules, rofitDetail.Id equals to its vote id.
            fixingDetail = profitDetails.Details.SingleOrDefault(d => d.Id == input.ProfitDetailId);
        }

        if (fixingDetail == null)
        {
            // However, in the old time, profitDetail.Id is null, so use Shares.
            fixingDetail = profitDetails.Details.OrderBy(d => d.StartPeriod)
                .FirstOrDefault(d => d.Shares == input.BeneficiaryShare.Shares);
        }

        if (fixingDetail == null)
        {
            throw new AssertionException("Cannot find proper profit detail to fix.");
        }
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L1366-1381)
```csharp
    public async Task Election_VoteWeightInterestSetting_Test()
    {
        var defaultSetting = await ElectionContractStub.GetVoteWeightSetting.CallAsync(
            new Empty());
        defaultSetting.VoteWeightInterestInfos.Count.ShouldBe(3);
        defaultSetting.VoteWeightInterestInfos[0].Capital = 13200;
        defaultSetting.VoteWeightInterestInfos[0].Day = 50;

        await ExecuteProposalForParliamentTransaction(ElectionContractAddress,
            nameof(ElectionContractStub.SetVoteWeightInterest), defaultSetting);

        defaultSetting = await ElectionContractStub.GetVoteWeightSetting.CallAsync(
            new Empty());
        defaultSetting.VoteWeightInterestInfos[0].Capital.ShouldBe(13200);
        defaultSetting.VoteWeightInterestInfos[0].Day.ShouldBe(50);
    }
```
