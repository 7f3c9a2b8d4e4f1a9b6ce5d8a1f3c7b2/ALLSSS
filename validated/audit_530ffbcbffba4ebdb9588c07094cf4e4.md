# Audit Report

## Title
Vote Target Change Denial of Service for Legacy Votes After Weight Settings Update

## Summary
Legacy votes created before the ProfitDetailId feature cannot change targets with extended profit periods (`IsResetVotingTime=true`) after governance updates vote weight calculation settings. The profit detail lookup fails because weight recalculation uses current settings while stored profit details use old settings, causing a mismatch that results in transaction failure.

## Finding Description

The vulnerability exists in the vote target change flow when users set `IsResetVotingTime=true` to extend their profit earning period.

**Root Cause - Weight Recalculation:**

When changing vote targets with `IsResetVotingTime=true`, the `ExtendVoterWelfareProfits` method is invoked. [1](#0-0) 

This method retrieves the election voting record via `GetElectionVotingRecordByVoteId`, which internally calls `TransferVotingRecordToElectionVotingRecord`. [2](#0-1) 

The critical issue occurs in `TransferVotingRecordToElectionVotingRecord` where the vote weight is **recalculated** using the **current** `VoteWeightInterestList` and `VoteWeightProportion` settings. [3](#0-2) 

**Profit Detail Lookup Failure:**

The `GetProfitDetailByElectionVotingRecord` method attempts to find the voter's profit detail using two strategies:
1. Match by profit detail ID (works for new votes)
2. Match by shares as fallback (for legacy votes where "in the old world, profitDetail.Id is null") [4](#0-3) 

For legacy votes without IDs, the shares-based matching compares the **recalculated weight** against the **original shares** that were calculated with old weight settings. After governance changes weight settings via `SetVoteWeightInterest` or `SetVoteWeightProportion`, these values no longer match. [5](#0-4) 

**Transaction Failure:**

When no matching profit detail is found, the method throws an `AssertionException` that prevents the entire transaction from succeeding. [6](#0-5) 

The vulnerability breaks the protocol invariant that users with valid, non-expired votes should be able to change their vote targets with profit period extension - a core feature of the voting system.

## Impact Explanation

**Affected Users:** All holders of legacy votes (created before ProfitDetailId feature or under previous weight settings) who attempt to change vote targets after governance updates weight calculation parameters.

**Impact Severity: MEDIUM**

The vulnerability causes:
1. **Denial of Service** - Users cannot execute the legitimate `ChangeVotingOption` operation with `IsResetVotingTime=true`
2. **Economic Loss** - Users lose the ability to extend their profit earning period when changing targets, forcing them to either:
   - Keep their current vote target (losing voting flexibility)
   - Change target with `IsResetVotingTime=false`, accepting a proportionally reduced profit period and forfeiting expected future rewards
3. **System-Wide Effect** - ALL legacy votes are affected after a single governance weight settings update
4. **No Direct Fund Theft** - While economically harmful, funds remain safe and accessible

The economic loss equals the difference between profits earned over a full extended period versus a reduced period, which could be substantial for long-term locked votes.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Preconditions:**
1. Legacy votes exist in the system (explicitly acknowledged in code comments as "old world" votes)
2. Governance executes `SetVoteWeightInterest` or `SetVoteWeightProportion` to update weight calculation parameters

**Feasibility: HIGH**
- Weight settings changes are legitimate governance operations that require parliament authorization [7](#0-6) 
- Test suite confirms this is an expected operation executable via parliament proposals [8](#0-7) 
- Such adjustments are economically rational (tuning incentives, fixing formulas, adapting to changing economic conditions)

**No Attacker Required:** This vulnerability is triggered by legitimate governance actions, not malicious actors.

**Probability:** Governance will likely adjust vote weight parameters during the protocol's operational lifetime for economic optimization purposes.

## Recommendation

**Solution:** Store the original weight calculation parameters with each vote or store the calculated weight itself when the profit detail is created, rather than recalculating it during vote target changes.

**Option 1 - Store Original Weight:**
When creating votes, store the calculated weight in the vote record. During profit detail lookup for legacy votes, use the stored weight instead of recalculating it.

**Option 2 - Upgrade Legacy Votes:**
Implement a migration function that updates all legacy votes to set their `ProfitDetailId` to match their `VoteId`, eliminating dependence on shares-based matching.

**Option 3 - Fallback Handling:**
If profit detail lookup by shares fails, attempt to find any profit detail for the beneficiary in the welfare scheme and update it, rather than throwing an exception.

The recommended approach is Option 1 combined with Option 2, as it provides both immediate resolution for new votes and a migration path for existing ones.

## Proof of Concept

```csharp
[Fact]
public async Task VoteTargetChange_DoS_After_WeightSettings_Update()
{
    // Setup: Announce candidate and create a vote
    var candidate = ValidationDataCenterKeyPairs.First();
    await AnnounceElectionAsync(candidate);
    
    var voter = VoterKeyPairs.First();
    const long amount = 1000;
    const int lockTime = 365 * 24 * 60 * 60; // 365 days
    
    // Create vote with current weight settings
    var voteResult = await VoteToCandidateAsync(voter, candidate.PublicKey.ToHex(), lockTime, amount);
    var voteId = Hash.Parser.ParseFrom(voteResult.ReturnValue);
    
    // Verify vote was created successfully
    var voteRecord = await ElectionContractStub.GetElectorVoteWithRecords.CallAsync(
        new StringValue { Value = voter.PublicKey.ToHex() });
    voteRecord.ActiveVotingRecords.Count.ShouldBe(1);
    
    // Governance updates vote weight settings
    var newWeightSettings = new VoteWeightInterestList
    {
        VoteWeightInterestInfos = {
            new VoteWeightInterest { Day = 365, Interest = 2, Capital = 1000 }, // Changed from default
            new VoteWeightInterest { Day = 730, Interest = 20, Capital = 10000 },
            new VoteWeightInterest { Day = 1095, Interest = 3, Capital = 1000 }
        }
    };
    await ExecuteProposalForParliamentTransaction(ElectionContractAddress,
        nameof(ElectionContractStub.SetVoteWeightInterest), newWeightSettings);
    
    // Setup second candidate for vote target change
    var newCandidate = ValidationDataCenterKeyPairs.Skip(1).First();
    await AnnounceElectionAsync(newCandidate);
    
    // Attempt to change vote target with extended profit period
    var electionStub = GetElectionContractTester(voter);
    var changeResult = await electionStub.ChangeVotingOption.SendWithExceptionAsync(
        new ChangeVotingOptionInput
        {
            VoteId = voteId,
            CandidatePubkey = newCandidate.PublicKey.ToHex(),
            IsResetVotingTime = true // Request profit period extension
        });
    
    // Verify transaction fails with AssertionException
    changeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    changeResult.TransactionResult.Error.ShouldContain("Cannot find profit detail");
}
```

## Notes

This vulnerability specifically affects the interaction between three contract features:
1. Legacy profit details created without ProfitDetailId set
2. Dynamic vote weight calculation based on configurable parameters
3. Vote target change with profit period extension

The code explicitly acknowledges legacy votes through comments ("in the old world, profitDetail.Id is null"), indicating this backward compatibility case was considered but the implementation is incomplete. When weight settings change, the shares-based fallback matching mechanism breaks down because it assumes weights are immutable, which is not the case after governance parameter updates.

The vulnerability demonstrates a protocol-level design issue where state migration strategies were not fully implemented for configuration parameter changes affecting historical data lookups.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L33-38)
```csharp
        if (input.IsResetVotingTime)
        {
            // true for extend EndPeroid of a Profit details, e.g. you vote for 12 months, and on the 6th month, you
            // change the vote, then there will be another 12 months from that time.
            ExtendVoterWelfareProfits(input.VoteId);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L156-160)
```csharp
        else
        {
            throw new AssertionException($"Cannot find profit detail of given vote id {voteId}");
        }
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L162-166)
```csharp
    private ElectionVotingRecord GetElectionVotingRecordByVoteId(Hash voteId)
    {
        var votingRecord = State.VoteContract.GetVotingRecord.Call(voteId);
        return TransferVotingRecordToElectionVotingRecord(votingRecord, voteId);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L385-391)
```csharp
    private void AssertPerformedByVoteWeightInterestController()
    {
        if (State.VoteWeightInterestController.Value == null)
            State.VoteWeightInterestController.Value = GetDefaultVoteWeightInterestController();

        Assert(Context.Sender == State.VoteWeightInterestController.Value.OwnerAddress, "No permission.");
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
