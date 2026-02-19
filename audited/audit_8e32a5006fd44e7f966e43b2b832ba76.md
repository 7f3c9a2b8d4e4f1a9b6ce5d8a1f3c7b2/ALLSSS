### Title
Vote Target Change Denial of Service for Legacy Votes After Weight Settings Update

### Summary
Legacy votes created before the ProfitDetailId feature was implemented cannot change targets with extended profit periods (`IsResetVotingTime=true`) after governance updates the vote weight calculation settings. The `GetProfitDetailByElectionVotingRecord()` function recalculates weights using current settings but the original profit details were stored with shares calculated using old settings, causing a lookup mismatch that results in an `AssertionException`. [1](#0-0) 

### Finding Description

The vulnerability occurs in the vote target change flow when `IsResetVotingTime=true`:

1. **Root Cause**: Weight recalculation mismatch between vote creation time and target change time.

When a vote is created, `AddBeneficiaryToVoter()` creates a profit detail with shares calculated using the current `VoteWeightInterestList` and `VoteWeightProportion` settings: [2](#0-1) 

When changing vote targets with `IsResetVotingTime=true`, `ExtendVoterWelfareProfits()` is called: [3](#0-2) 

This function calls `GetElectionVotingRecordByVoteId()` which invokes `TransferVotingRecordToElectionVotingRecord()`: [4](#0-3) 

The critical issue is at line 352: the weight is **recalculated** using the **current** weight settings via `GetVotesWeight()`, not the original settings from when the vote was created.

2. **Lookup Failure**: `GetProfitDetailByElectionVotingRecord()` attempts two matching strategies:
   - First, match by profit detail ID (line 177) - works for new votes with ProfitDetailId set
   - Second, match by shares (line 181) - fallback for old votes without IDs [1](#0-0) 

For **legacy votes** (created before ProfitDetailId was implemented, as indicated by the comment "in the old world, profitDetail.Id is null"), the ID matching fails. The shares matching then compares the **recalculated** weight against stored shares calculated with **old** settings. If governance has changed the weight settings via `SetVoteWeightInterest` or `SetVoteWeightProportion`, these values will not match. [5](#0-4) [6](#0-5) 

3. **Transaction Failure**: When no profit detail is found, `ExtendVoterWelfareProfits()` throws an `AssertionException`: [7](#0-6) 

This prevents the entire `ChangeVotingOption` transaction from succeeding.

### Impact Explanation

**Who is affected**: All users with legacy votes (created before ProfitDetailId feature) attempting to change vote targets after governance updates weight settings.

**Harm**: 
- Denial of service on the legitimate vote target change feature with profit period extension
- Users are forced to either:
  - Keep their current vote target (losing flexibility)
  - Change target with `IsResetVotingTime=false`, which reduces their remaining profit period proportionally, resulting in economic loss of expected rewards

**Quantification**: 
- Affects ALL legacy votes system-wide after a single governance weight settings update
- Users lose the ability to extend their profit earning period when changing targets
- Economic loss equals the difference between full profit period extension and reduced period

**Severity**: Medium - While not a direct fund theft, it's a protocol-level DoS affecting a core voting feature that causes economic loss through reduced profit periods for legitimate users.

### Likelihood Explanation

**Attacker capabilities**: None required - this is triggered by legitimate governance actions.

**Preconditions**:
1. Legacy votes exist in the system (explicitly handled by the code as indicated by comments)
2. Governance changes `VoteWeightInterestList` or `VoteWeightProportion` through `SetVoteWeightInterest` or `SetVoteWeightProportion` [8](#0-7) 

**Feasibility**: HIGH
- Weight settings changes are legitimate governance actions (tested in the codebase)
- Test evidence shows this is an expected operation: [9](#0-8) 

**Operational constraints**: Once weight settings are updated, ALL legacy votes attempting to change targets with extended periods will fail until either:
- Users accept reduced profit periods (`IsResetVotingTime=false`)
- Votes expire naturally
- A contract upgrade fixes the issue

**Probability**: MEDIUM-HIGH - Governance weight adjustments are economically rational (adjusting incentives, fixing broken formulas, etc.) and will likely occur during the protocol's lifetime.

### Recommendation

**Code-level mitigation**:

1. Store the original vote weight at vote creation time in the `LockTimeMap` or a separate mapping:
```
public MappedState<Hash, long> VoteWeightMap { get; set; }
```

2. When creating profit details in `AddBeneficiaryToVoter()`, store the calculated weight for later lookup.

3. In `GetProfitDetailByElectionVotingRecord()`, use the stored original weight instead of recalculating:
```csharp
private ProfitDetail GetProfitDetailByElectionVotingRecord(ElectionVotingRecord electionVotingRecord)
{
    var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
    {
        Beneficiary = electionVotingRecord.Voter,
        SchemeId = State.WelfareHash.Value
    });

    // Try ID matching first
    ProfitDetail profitDetail = profitDetails.Details.FirstOrDefault(d => d.Id == electionVotingRecord.VoteId);
    
    // For legacy votes, use STORED original weight, not recalculated
    if (profitDetail == null)
    {
        var originalWeight = State.VoteWeightMap[electionVotingRecord.VoteId];
        if (originalWeight > 0)
        {
            profitDetail = profitDetails.Details.LastOrDefault(d => d.Shares == originalWeight);
        }
    }
    
    return profitDetail;
}
```

4. For existing legacy votes, implement a one-time migration function (governance-gated) that updates profit detail IDs to match vote IDs, allowing them to use the ID-based matching.

**Invariant checks**:
- Add assertion that stored weight matches profit detail shares at vote creation time
- Add event logging when profit detail lookup fails to detect issues early

**Test cases**:
1. Create vote with settings V1
2. Change weight settings to V2
3. Attempt to change vote target with `IsResetVotingTime=true`
4. Verify transaction succeeds (after fix)

### Proof of Concept

**Initial State**:
- VoteWeightInterestList set to defaults (Day=365, Interest=1, Capital=1000)
- User votes 1000 tokens for 365 days for Candidate A
- Profit detail created with Shares = W1 (calculated with default settings)
- For legacy vote: ProfitDetailId not set (Id = null)

**Transaction Sequence**:

1. **Governance changes weight settings**:
   - Call `SetVoteWeightInterest` with new values (Day=365, Interest=2, Capital=1000)
   - Transaction succeeds

2. **User attempts to change vote target**:
   - Call `ChangeVotingOption` with:
     - `CandidatePubkey` = Candidate B
     - `VoteId` = existing vote ID
     - `IsResetVotingTime` = true

**Expected Result**: Transaction succeeds, vote target changes to Candidate B, profit period extended

**Actual Result**: 
- `TransferVotingRecordToElectionVotingRecord` recalculates Weight = W2 (using new settings)
- `GetProfitDetailByElectionVotingRecord` tries to match by Id (fails for legacy vote)
- Falls back to matching by Shares = W2 (but actual shares are W1)
- Returns null
- `ExtendVoterWelfareProfits` throws: "Cannot find profit detail of given vote id {voteId}"
- Transaction fails with AssertionException

**Success Condition**: The vulnerability is confirmed when legitimate legacy votes cannot change targets after weight settings updates, forcing users to lose profit period extension benefits.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L23-38)
```csharp
    public override Empty ChangeVotingOption(ChangeVotingOptionInput input)
    {
        var targetInformation = State.CandidateInformationMap[input.CandidatePubkey];
        AssertValidCandidateInformation(targetInformation);
        var votingRecord = State.VoteContract.GetVotingRecord.Call(input.VoteId);
        Assert(Context.Sender == votingRecord.Voter, "No permission to change current vote's option.");
        var actualLockedSeconds = Context.CurrentBlockTime.Seconds.Sub(votingRecord.VoteTimestamp.Seconds);
        var claimedLockingSeconds = State.LockTimeMap[input.VoteId];
        Assert(actualLockedSeconds < claimedLockingSeconds, "This vote already expired.");

        if (input.IsResetVotingTime)
        {
            // true for extend EndPeroid of a Profit details, e.g. you vote for 12 months, and on the 6th month, you
            // change the vote, then there will be another 12 months from that time.
            ExtendVoterWelfareProfits(input.VoteId);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L140-160)
```csharp
        var extendingDetail = GetProfitDetailByElectionVotingRecord(electionVotingRecord);
        if (extendingDetail != null)
        {
            // The endPeriod is updated and startPeriod is 0, others stay still.
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
        }
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
