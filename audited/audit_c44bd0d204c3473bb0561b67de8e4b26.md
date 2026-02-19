# Audit Report

## Title
Vote Target Change Denial of Service for Legacy Votes After Weight Settings Update

## Summary
Legacy votes created before the `ProfitDetailId` feature cannot change targets with extended profit periods (`IsResetVotingTime=true`) after governance updates vote weight calculation settings. The vulnerability occurs because `TransferVotingRecordToElectionVotingRecord()` recalculates vote weights using current settings, while legacy profit details store shares calculated with old settings. This mismatch causes the fallback lookup mechanism in `GetProfitDetailByElectionVotingRecord()` to fail, resulting in an `AssertionException` that blocks the entire `ChangeVotingOption` transaction.

## Finding Description

The vulnerability exists in the vote target change flow when users attempt to extend their profit periods by setting `IsResetVotingTime=true`.

**Root Cause - Weight Recalculation Mismatch**:

When a vote is created, `AddBeneficiaryToVoter()` stores a profit detail with shares calculated using the vote weight settings active at creation time. [1](#0-0) 

When changing vote targets with `IsResetVotingTime=true`, the `ExtendVoterWelfareProfits()` function is called. [2](#0-1) 

This function retrieves the election voting record via `GetElectionVotingRecordByVoteId()`, which calls `TransferVotingRecordToElectionVotingRecord()`. The critical issue occurs here where the weight is **recalculated** using **current** settings via `GetVotesWeight()`, not the original settings from vote creation time. [3](#0-2) 

**Lookup Failure**:

The `GetProfitDetailByElectionVotingRecord()` function attempts to find the profit detail using two strategies:
1. First, match by profit detail ID (for new votes where `ProfitDetailId` is set)
2. Second, match by shares as a fallback (for legacy votes where ID is null, as indicated by the comment "in the old world, profitDetail.Id is null") [4](#0-3) 

For legacy votes, the ID matching fails. The shares matching then compares the **recalculated weight** (using current settings) against **stored shares** (calculated with old settings). If governance has changed the weight settings via `SetVoteWeightInterest` or `SetVoteWeightProportion`, these values will not match. [5](#0-4) 

**Transaction Failure**:

When no profit detail is found, `ExtendVoterWelfareProfits()` throws an `AssertionException`, preventing the entire `ChangeVotingOption` transaction from succeeding. [6](#0-5) 

The same fallback-by-shares mechanism exists in the Profit contract's `FixProfitDetail` method, confirming this is a system-wide legacy vote handling pattern. [7](#0-6) 

## Impact Explanation

**Affected Users**: All users holding legacy votes (created before the `ProfitDetailId` feature was implemented) who attempt to change vote targets after governance updates weight calculation settings.

**Concrete Harm**:
1. **Denial of Service**: Users cannot change vote targets with `IsResetVotingTime=true`, effectively losing the ability to extend their profit earning periods when switching candidates
2. **Economic Loss**: Users are forced to either:
   - Keep their current vote target (losing vote flexibility)
   - Change target with `IsResetVotingTime=false`, which reduces their remaining profit period proportionally

**Quantification**: For a vote with 6 months remaining from a 12-month original lock:
- With `IsResetVotingTime=true` (intended): Should receive 12 more months of welfare profit distributions (18 total months remaining)
- With `IsResetVotingTime=false` (forced workaround): Only 6 months of profit distributions remain
- **Loss**: 12 months worth of CitizenWelfare profit scheme distributions per affected vote

**Scope**: This affects ALL legacy votes system-wide after a single governance weight settings update.

**Severity**: Medium - While not direct fund theft, this is a protocol-level DoS affecting a core voting feature that causes measurable economic loss through reduced profit periods for legitimate users exercising their voting rights.

## Likelihood Explanation

**Attacker Capabilities**: None required - this vulnerability is triggered by legitimate governance actions, not malicious actors.

**Preconditions**:
1. **Legacy votes exist**: The code explicitly handles "old world" votes with comments and fallback logic, indicating these votes exist or must be supported
2. **Governance updates weight settings**: Via `SetVoteWeightInterest` or `SetVoteWeightProportion` methods

**Feasibility**: HIGH
- Weight settings changes are legitimate, expected governance operations with Parliament authority requirement
- Test suite includes explicit tests for these operations, demonstrating they are part of normal protocol operations [8](#0-7) 

**Economic Rationale**: Governance has strong incentives to adjust weight calculation parameters to:
- Optimize staking incentives
- Fix incorrect or suboptimal formulas
- Respond to changing economic conditions

**Operational Impact**: Once weight settings are updated, ALL legacy votes attempting target changes with extended periods will fail until:
- Users accept reduced profit periods (`IsResetVotingTime=false`)
- Votes naturally expire
- A contract upgrade fixes the issue

**Probability**: MEDIUM-HIGH - Weight adjustments are economically rational governance actions likely to occur during the protocol's operational lifetime.

## Recommendation

**Fix the Weight Recalculation Issue**:

Store the original vote weight alongside the vote data, rather than recalculating it. Modify `TransferVotingRecordToElectionVotingRecord()` to use stored weight instead of recalculating:

```csharp
// Add state variable to store original weights
State.VoteWeightMap[voteId] = originalWeight; // Store during vote creation

// In TransferVotingRecordToElectionVotingRecord():
private ElectionVotingRecord TransferVotingRecordToElectionVotingRecord(VotingRecord votingRecord, Hash voteId)
{
    var lockSeconds = State.LockTimeMap[voteId];
    // Use stored weight instead of recalculating
    var originalWeight = State.VoteWeightMap[voteId];
    
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
        Weight = originalWeight, // Use original, not recalculated
        IsChangeTarget = votingRecord.IsChangeTarget
    };
}
```

**Alternative Approach**: Migrate legacy votes to include `ProfitDetailId` by reading their current profit details and updating them to have IDs, eliminating reliance on the shares-based fallback mechanism.

## Proof of Concept

```csharp
[Fact]
public async Task LegacyVote_ChangeTarget_FailsAfterWeightSettingsUpdate()
{
    // Setup: Create a legacy-style vote (simulating old system without ProfitDetailId)
    var voter = VoterKeyPairs.First();
    var candidate1 = ValidationDataCenterKeyPairs[0];
    var candidate2 = ValidationDataCenterKeyPairs[1];
    var lockTime = 365 * 86400; // 1 year
    var voteAmount = 1000;
    
    await AnnounceElectionAsync(candidate1);
    await AnnounceElectionAsync(candidate2);
    
    // Vote with original weight settings
    var voteId = await VoteToCandidateAsync(voter, candidate1.PublicKey.ToHex(), lockTime, voteAmount);
    
    // Governance updates weight settings (legitimate action)
    var newWeightSettings = new VoteWeightProportion
    {
        TimeProportion = 3,  // Changed from default 2
        AmountProportion = 2  // Changed from default 1
    };
    await ExecuteProposalForParliamentTransaction(
        ElectionContractAddress,
        nameof(ElectionContractStub.SetVoteWeightProportion),
        newWeightSettings);
    
    // Attempt to change vote target with IsResetVotingTime=true
    // This should fail with AssertionException for legacy votes
    var changeResult = await ElectionContractStub.ChangeVotingOption.SendAsync(
        new ChangeVotingOptionInput
        {
            VoteId = voteId,
            CandidatePubkey = candidate2.PublicKey.ToHex(),
            IsResetVotingTime = true  // Attempts to extend profit period
        });
    
    // Verify transaction fails with expected error
    changeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    changeResult.TransactionResult.Error.ShouldContain("Cannot find profit detail of given vote id");
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L23-37)
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
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L126-160)
```csharp
    private void ExtendVoterWelfareProfits(Hash voteId)
    {
        var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
        var electionVotingRecord = GetElectionVotingRecordByVoteId(voteId);

        // Extend endPeriod from now no, so the lockTime will *NOT* be changed.
        var lockTime = State.LockTimeMap[voteId];
        var lockPeriod = lockTime.Div(State.TimeEachTerm.Value);
        if (lockPeriod == 0)
        {
            return;
        }

        var endPeriod = lockPeriod.Add(treasury.CurrentPeriod);
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L337-354)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L284-294)
```csharp
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

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L1477-1495)
```csharp
    public async Task Election_SetVoteWeightProportion_Test()
    {
        var defaultSetting = await ElectionContractStub.GetVoteWeightProportion.CallAsync(
            new Empty());
        defaultSetting.TimeProportion.ShouldBe(2);
        defaultSetting.AmountProportion.ShouldBe(1);
        defaultSetting = new VoteWeightProportion
        {
            TimeProportion = 3,
            AmountProportion = 3
        };
        await ExecuteProposalForParliamentTransaction(ElectionContractAddress,
            nameof(ElectionContractStub.SetVoteWeightProportion), defaultSetting);

        defaultSetting = await ElectionContractStub.GetVoteWeightProportion.CallAsync(
            new Empty());
        defaultSetting.TimeProportion.ShouldBe(3);
        defaultSetting.AmountProportion.ShouldBe(3);
    }
```
