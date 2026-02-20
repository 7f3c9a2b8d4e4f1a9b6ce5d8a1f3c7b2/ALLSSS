# Audit Report

## Title
Vote Target Change Denial of Service for Legacy Votes After Weight Settings Update

## Summary
Legacy votes created before the `ProfitDetailId` feature cannot change targets with extended profit periods (`IsResetVotingTime=true`) after governance updates vote weight calculation settings. The vulnerability occurs because weight recalculation uses current settings while legacy profit details store shares calculated with old settings, causing lookup failure and transaction revert.

## Finding Description

The vulnerability exists in the vote target change flow when users attempt to extend their profit periods by setting `IsResetVotingTime=true`.

**Root Cause - Weight Recalculation Mismatch:**

When a vote is created, `AddBeneficiaryToVoter()` stores a profit detail with shares calculated using the vote weight settings active at creation time. [1](#0-0) 

When changing vote targets with `IsResetVotingTime=true`, the `ChangeVotingOption` method calls `ExtendVoterWelfareProfits()`. [2](#0-1) 

This function retrieves the election voting record via `GetElectionVotingRecordByVoteId()`, which calls `TransferVotingRecordToElectionVotingRecord()`. The critical issue occurs here where the weight is **recalculated** using **current** settings via `GetVotesWeight()`, not the original settings from vote creation time. [3](#0-2) 

The `GetVotesWeight()` method uses current state values from `State.VoteWeightInterestList.Value` and `GetVoteWeightProportion()` to calculate weight. [4](#0-3) 

**Lookup Failure:**

The `GetProfitDetailByElectionVotingRecord()` function attempts to find the profit detail using two strategies:
1. First, match by profit detail ID (for new votes where `ProfitDetailId` is set)
2. Second, match by shares as a fallback (for legacy votes where ID is null, as indicated by the comment "However, in the old world, profitDetail.Id is null, so use Shares") [5](#0-4) 

For legacy votes, the ID matching fails. The shares matching then compares the **recalculated weight** (using current settings) against **stored shares** (calculated with old settings). If governance has changed the weight settings via `SetVoteWeightInterest` or `SetVoteWeightProportion`, these values will not match.

**Transaction Failure:**

When no profit detail is found, `ExtendVoterWelfareProfits()` throws an `AssertionException`, preventing the entire `ChangeVotingOption` transaction from succeeding. [6](#0-5) 

The same fallback-by-shares mechanism exists in the Profit contract's `FixProfitDetail` method, confirming this is a system-wide legacy vote handling pattern. [7](#0-6) 

## Impact Explanation

**Affected Users:** All users holding legacy votes (created before the `ProfitDetailId` feature was implemented) who attempt to change vote targets after governance updates weight calculation settings.

**Concrete Harm:**
1. **Denial of Service:** Users cannot change vote targets with `IsResetVotingTime=true`, effectively losing the ability to extend their profit earning periods when switching candidates
2. **Economic Loss:** Users are forced to either keep their current vote target (losing vote flexibility) or change target with `IsResetVotingTime=false`, which reduces their remaining profit period proportionally

**Quantification:** For a vote with 6 months remaining from a 12-month original lock:
- With `IsResetVotingTime=true` (intended): Should receive 12 more months of welfare profit distributions (18 total months remaining)
- With `IsResetVotingTime=false` (forced workaround): Only 6 months of profit distributions remain
- **Loss:** 12 months worth of CitizenWelfare profit scheme distributions per affected vote

**Scope:** This affects ALL legacy votes system-wide after a single governance weight settings update.

**Severity:** Medium - While not direct fund theft, this is a protocol-level DoS affecting a core voting feature that causes measurable economic loss through reduced profit periods for legitimate users exercising their voting rights.

## Likelihood Explanation

**Attacker Capabilities:** None required - this vulnerability is triggered by legitimate governance actions, not malicious actors.

**Preconditions:**
1. **Legacy votes exist:** The code explicitly handles "old world" votes with comments and fallback logic, indicating these votes exist or must be supported
2. **Governance updates weight settings:** Via `SetVoteWeightInterest` or `SetVoteWeightProportion` methods

**Feasibility:** HIGH
- Weight settings changes are legitimate, expected governance operations with Parliament authority requirement [8](#0-7) 
- Test suite includes explicit tests for these operations, demonstrating they are part of normal protocol operations [9](#0-8) 

**Economic Rationale:** Governance has strong incentives to adjust weight calculation parameters to optimize staking incentives, fix incorrect or suboptimal formulas, and respond to changing economic conditions.

**Operational Impact:** Once weight settings are updated, ALL legacy votes attempting target changes with extended periods will fail until users accept reduced profit periods (`IsResetVotingTime=false`), votes naturally expire, or a contract upgrade fixes the issue.

**Probability:** MEDIUM-HIGH - Weight adjustments are economically rational governance actions likely to occur during the protocol's operational lifetime.

## Recommendation

Store the original weight calculation settings with each vote, or store the calculated weight value itself when creating the vote. When recalculating for lookup purposes, use the stored settings/weight rather than current settings.

**Specific Fix Options:**

1. **Option A:** Store original weight settings with each vote in `State.LockTimeMap` or a similar state mapping, and use those settings when recalculating weight in `TransferVotingRecordToElectionVotingRecord()`.

2. **Option B:** For legacy votes without IDs, retrieve the profit detail first using the beneficiary address, then match by comparing other immutable fields (voter address, start period) instead of shares which may change due to weight recalculation.

3. **Option C:** Add a migration mechanism that updates all legacy profit details to include their vote IDs, eliminating reliance on the shares-based fallback mechanism.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Create a vote with initial weight settings (e.g., VoteWeightProportion TimeProportion=2, AmountProportion=1)
2. Store the profit detail with shares calculated using these settings
3. Governance updates weight settings via Parliament (e.g., VoteWeightProportion TimeProportion=3, AmountProportion=3)
4. User attempts to change vote target with `IsResetVotingTime=true`
5. `TransferVotingRecordToElectionVotingRecord()` recalculates weight using new settings (TimeProportion=3, AmountProportion=3)
6. `GetProfitDetailByElectionVotingRecord()` fails to find profit detail because:
   - ID matching fails (legacy vote has null ProfitDetailId)
   - Shares matching fails (recalculated weight ≠ stored shares due to different settings)
7. `AssertionException` is thrown, transaction reverts

The test would need to simulate a legacy vote (created without ProfitDetailId), update weight settings through Parliament governance, then attempt `ChangeVotingOption` with `IsResetVotingTime=true` to observe the transaction failure.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L385-400)
```csharp
    private void AssertPerformedByVoteWeightInterestController()
    {
        if (State.VoteWeightInterestController.Value == null)
            State.VoteWeightInterestController.Value = GetDefaultVoteWeightInterestController();

        Assert(Context.Sender == State.VoteWeightInterestController.Value.OwnerAddress, "No permission.");
    }

    private AuthorityInfo GetDefaultVoteWeightInterestController()
    {
        return new AuthorityInfo
        {
            ContractAddress = Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName),
            OwnerAddress = GetParliamentDefaultAddress()
        };
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L265-294)
```csharp
    public override Empty FixProfitDetail(FixProfitDetailInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        var scheme = State.SchemeInfos[input.SchemeId];
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
        }

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
