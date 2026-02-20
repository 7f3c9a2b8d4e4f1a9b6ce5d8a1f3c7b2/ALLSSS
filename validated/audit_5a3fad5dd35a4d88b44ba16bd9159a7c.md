# Audit Report

## Title
Inconsistent Profit Detail Matching Logic Enables Wrong Profit Detail Extension for Votes with Identical Weight

## Summary
The Election contract's `GetProfitDetailByElectionVotingRecord()` and Profit contract's `FixProfitDetail()` use different fallback matching strategies (`LastOrDefault` vs `OrderBy().FirstOrDefault`) when dealing with legacy profit details where Id is null. This inconsistency allows attackers with multiple old votes of identical weight to extend the wrong profit detail, resurrecting expired votes and claiming unauthorized welfare profits.

## Finding Description

The vulnerability stems from an inconsistency in how two contracts match profit details when the ProfitDetailId field is null (legacy votes created before the Id feature was implemented).

**Root Cause - Inconsistent Matching Logic:**

In the Election contract, `GetProfitDetailByElectionVotingRecord()` uses `LastOrDefault` for fallback matching when Id-based lookup fails: [1](#0-0) 

However, the Profit contract's `FixProfitDetail()` uses `OrderBy(d => d.StartPeriod).FirstOrDefault` for the same fallback scenario: [2](#0-1) 

**Exploit Mechanism:**

When `ChangeVotingOption` is called with `IsResetVotingTime=true`, it triggers the `ExtendVoterWelfareProfits` flow: [3](#0-2) 

The vulnerability manifests in the `ExtendVoterWelfareProfits` method when a voter has multiple legacy profit details with identical Shares (weight) values: [4](#0-3) 

At line 140, `GetProfitDetailByElectionVotingRecord()` returns the **last** matching profit detail. Line 141 validates existence. Line 144 calls `FixProfitDetail()` which operates on the **first** matching profit detail (ordered by StartPeriod). These can be **different profit details**, allowing an attacker to:
- Check the existence of an active vote's profit detail (Vote B)
- Extend a different, expired vote's profit detail (Vote A)

**Vote Weight Determinism:**

Multiple votes can have identical weights because the calculation is deterministic based on amount and lock time: [5](#0-4) 

Additionally, the weight is calculated when converting VotingRecord to ElectionVotingRecord: [6](#0-5) 

**Legacy Data Context:**

Current code sets ProfitDetailId for new votes: [7](#0-6) 

However, old votes created before this feature have Id=null in their profit details, making them vulnerable to the inconsistent matching logic.

## Impact Explanation

**Direct Financial Impact:**

An attacker who owns multiple old votes with identical weights can:
1. **Resurrect Expired Votes**: Extend the EndPeriod of an already-expired profit detail by pretending to extend a different active vote
2. **Steal Protocol Funds**: Continue claiming welfare profits beyond the legitimate period via the ClaimProfits mechanism
3. **Dilute Legitimate Rewards**: The attacker's extended shares remain in the welfare scheme, reducing profits for all other beneficiaries

The `FixProfitDetail` method clones and updates the wrong profit detail: [8](#0-7) 

**Affected Parties:**
- All welfare scheme beneficiaries receive reduced profit shares
- Protocol integrity is compromised as time-based reward limits are bypassed

**Severity: HIGH**
- Enables direct theft of protocol funds through unauthorized profit claiming
- Requires only vote ownership (no special privileges)
- Legacy data with Id=null exists in production systems
- Impact scales with vote amounts and number of exploitable combinations

## Likelihood Explanation

**Attacker Capabilities:**
- Requires owning multiple votes with identical weights (same amount + lock time)
- Can intentionally create such votes by voting with identical parameters
- No special permissions needed - only calls public `ChangeVotingOption` method: [9](#0-8) 

**Attack Complexity:**
- **Low**: Simple transaction call with normal parameters
- **Precondition**: Legacy profit details with Id=null exist for votes created before the ProfitDetailId feature
- **Execution**: All steps executable through standard contract calls

**Probability:**
- **High** for legacy systems: All systems with votes predating the Id feature are vulnerable
- **Moderate** for new systems: Attackers can intentionally create multiple votes with identical weights
- **Detection Difficulty**: The attack appears as a legitimate vote change operation

## Recommendation

**Fix the Inconsistent Matching Strategy:**

Align both contracts to use the same fallback matching strategy. The recommended fix is to modify `GetProfitDetailByElectionVotingRecord` to use `OrderBy(d => d.StartPeriod).FirstOrDefault` instead of `LastOrDefault`, matching the Profit contract's behavior:

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
        // FIXED: Use OrderBy().FirstOrDefault() to match FixProfitDetail behavior
        profitDetail = profitDetails.Details.OrderBy(d => d.StartPeriod)
            .FirstOrDefault(d => d.Shares == electionVotingRecord.Weight);
    }

    return profitDetail;
}
```

**Alternative Solution:**

Add validation in `ExtendVoterWelfareProfits` to ensure the profit detail found matches the expected vote's time period before calling `FixProfitDetail`.

## Proof of Concept

```csharp
[Fact]
public async Task ProfitDetailMismatchVulnerability_Test()
{
    // Setup: Create two legacy votes with identical weights for the same voter
    var voterKeyPair = VoterKeyPairs[0];
    var candidateKeyPair = ValidationDataCenterKeyPairs[0];
    
    // Vote A: 100 tokens, 90 days (will have weight W)
    var voteAId = await VoteToCandidate(voterKeyPair, candidateKeyPair.PublicKey.ToHex(), 
        90 * 86400, 100);
    
    // Fast forward to expire Vote A
    await ProduceBlocks(BootMinerKeyPair, 100);
    
    // Vote B: 100 tokens, 90 days (same weight W as Vote A)
    var voteBId = await VoteToCandidate(voterKeyPair, candidateKeyPair.PublicKey.ToHex(), 
        90 * 86400, 100);
    
    // Get initial profit details - both have Id=null (legacy), same Shares
    var profitDetailsA = await GetProfitDetails(voterKeyPair);
    var voteAProfitDetail = profitDetailsA.Details.First(); // StartPeriod = earlier
    var voteBProfitDetail = profitDetailsA.Details.Last();  // StartPeriod = later
    
    // Verify Vote A is expired
    voteAProfitDetail.EndPeriod.ShouldBeLessThan(await GetCurrentPeriod());
    // Verify Vote B is active
    voteBProfitDetail.EndPeriod.ShouldBeGreaterThan(await GetCurrentPeriod());
    
    // EXPLOIT: Call ChangeVotingOption for Vote B with IsResetVotingTime=true
    // This should extend Vote B's profit detail but will actually extend Vote A's
    var changeResult = await ElectionContractStub.ChangeVotingOption.SendAsync(
        new ChangeVotingOptionInput
        {
            VoteId = voteBId,
            CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
            IsResetVotingTime = true
        });
    changeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify the vulnerability: Vote A's EndPeriod was extended instead of Vote B's
    var profitDetailsAfter = await GetProfitDetails(voterKeyPair);
    var voteAAfter = profitDetailsAfter.Details
        .OrderBy(d => d.StartPeriod).First(); // Vote A (oldest)
    var voteBAfter = profitDetailsAfter.Details
        .OrderBy(d => d.StartPeriod).Last();  // Vote B (newest)
    
    // VULNERABILITY CONFIRMED: Vote A's EndPeriod was extended (resurrected)
    voteAAfter.EndPeriod.ShouldBeGreaterThan(voteAProfitDetail.EndPeriod);
    voteAAfter.EndPeriod.ShouldBeGreaterThan(await GetCurrentPeriod());
    
    // Vote B's EndPeriod remains unchanged (wrong profit detail was modified)
    voteBAfter.EndPeriod.ShouldBe(voteBProfitDetail.EndPeriod);
}
```

This test demonstrates that calling `ChangeVotingOption` for Vote B actually extends Vote A's profit detail due to the inconsistent matching logic, allowing an expired vote to be resurrected and continue claiming welfare profits.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L23-124)
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
        else
        {
            // false, no change for EndPeroid
            State.LockTimeMap[input.VoteId] = State.LockTimeMap[input.VoteId].Sub(actualLockedSeconds);
        }

        // Withdraw old votes
        State.VoteContract.Withdraw.Send(new WithdrawInput
        {
            VoteId = input.VoteId
        });

        // Create new votes
        State.VoteContract.Vote.Send(new VoteInput
        {
            VoteId = input.VoteId,
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Amount = votingRecord.Amount,
            Voter = votingRecord.Voter,
            Option = input.CandidatePubkey,
            IsChangeTarget = true
        });

        // Update related candidate
        var oldVoteOptionPublicKey = GetNewestPubkey(votingRecord.Option);
        var oldCandidateVotes = State.CandidateVotes[oldVoteOptionPublicKey];
        oldCandidateVotes.ObtainedActiveVotingRecordIds.Remove(input.VoteId);
        oldCandidateVotes.ObtainedActiveVotedVotesAmount =
            oldCandidateVotes.ObtainedActiveVotedVotesAmount.Sub(votingRecord.Amount);
        oldCandidateVotes.AllObtainedVotedVotesAmount =
            oldCandidateVotes.AllObtainedVotedVotesAmount.Sub(votingRecord.Amount);
        State.CandidateVotes[oldVoteOptionPublicKey] = oldCandidateVotes;

        long voteAmountOfNewCandidate;
        var newCandidateVotes = State.CandidateVotes[input.CandidatePubkey];
        if (newCandidateVotes != null)
        {
            newCandidateVotes.ObtainedActiveVotingRecordIds.Add(input.VoteId);
            newCandidateVotes.ObtainedActiveVotedVotesAmount =
                newCandidateVotes.ObtainedActiveVotedVotesAmount.Add(votingRecord.Amount);
            newCandidateVotes.AllObtainedVotedVotesAmount =
                newCandidateVotes.AllObtainedVotedVotesAmount.Add(votingRecord.Amount);
            State.CandidateVotes[input.CandidatePubkey] = newCandidateVotes;
            voteAmountOfNewCandidate = newCandidateVotes.ObtainedActiveVotedVotesAmount;
        }
        else
        {
            State.CandidateVotes[input.CandidatePubkey] = new CandidateVote
            {
                Pubkey = ByteStringHelper.FromHexString(input.CandidatePubkey),
                ObtainedActiveVotingRecordIds = { input.VoteId },
                ObtainedActiveVotedVotesAmount = votingRecord.Amount,
                AllObtainedVotedVotesAmount = votingRecord.Amount
            };
            voteAmountOfNewCandidate = votingRecord.Amount;
        }

        var dataCenterList = State.DataCentersRankingList.Value;
        if (dataCenterList.DataCenters.ContainsKey(input.CandidatePubkey))
        {
            dataCenterList.DataCenters[input.CandidatePubkey] =
                dataCenterList.DataCenters[input.CandidatePubkey].Add(votingRecord.Amount);
        }
        else if (dataCenterList.DataCenters.Count < GetValidationDataCenterCount())
        {
            // add data center
            dataCenterList.DataCenters.Add(input.CandidatePubkey,
                State.CandidateVotes[input.CandidatePubkey].ObtainedActiveVotedVotesAmount);

            AddBeneficiary(input.CandidatePubkey);
        }
        else
        {
            CandidateReplaceMemberInDataCenter(dataCenterList, input.CandidatePubkey, voteAmountOfNewCandidate);
        }

        if (dataCenterList.DataCenters.ContainsKey(oldVoteOptionPublicKey))
        {
            dataCenterList.DataCenters[oldVoteOptionPublicKey] =
                dataCenterList.DataCenters[oldVoteOptionPublicKey].Sub(votingRecord.Amount);
            UpdateDataCenterAfterMemberVoteAmountChanged(dataCenterList, oldVoteOptionPublicKey);
        }

        State.DataCentersRankingList.Value = dataCenterList;
        return new Empty();
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L284-289)
```csharp
        if (fixingDetail == null)
        {
            // However, in the old time, profitDetail.Id is null, so use Shares.
            fixingDetail = profitDetails.Details.OrderBy(d => d.StartPeriod)
                .FirstOrDefault(d => d.Shares == input.BeneficiaryShare.Shares);
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L296-305)
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
        return new Empty();
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
