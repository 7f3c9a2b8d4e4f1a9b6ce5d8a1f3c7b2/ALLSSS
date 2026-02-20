# Audit Report

## Title
Inconsistent Profit Detail Matching Logic Causes Welfare Misattribution in Multi-Vote Scenarios

## Summary
The Election contract's `ChangeVotingOption` function with `IsResetVotingTime=true` uses inconsistent profit detail matching logic when handling old-style profit details (where `Id` is null). The validation step uses `LastOrDefault` while the extension step uses `FirstOrDefault(OrderBy StartPeriod)`, causing the wrong profit detail to be extended when a voter has multiple votes with identical weight.

## Finding Description

The Election contract maintains backwards compatibility for old-style profit details where the `Id` field is null. When a voter calls `ChangeVotingOption` with `IsResetVotingTime=true`, the system performs two distinct operations with inconsistent matching logic:

**Validation Phase:** The `GetProfitDetailByElectionVotingRecord` method validates that a profit detail exists. For old-style details (where `Id` is null), it uses `LastOrDefault` to match by shares with no ordering applied. [1](#0-0) 

**Extension Phase:** The `FixProfitDetail` method in the Profit contract attempts to locate the profit detail to modify. When the `ProfitDetailId` doesn't match (because old-style details have null `Id`), it falls back to matching by shares using `OrderBy(d => d.StartPeriod).FirstOrDefault`. [2](#0-1) 

**Execution Flow:**

When `ChangeVotingOption` is invoked with `IsResetVotingTime=true`, the `ExtendVoterWelfareProfits` method executes: [3](#0-2) 

The null check at line 141 only validates that SOME profit detail with matching shares exists, but doesn't ensure the SAME detail will be used by `FixProfitDetail`. The `ProfitDetailId` parameter passed as `voteId` fails to match old-style details (they have null `Id`), causing `FixProfitDetail` to fall back to shares-based matching with different ordering logic.

**Security Guarantee Broken:**

The invariant "when extending a vote's welfare profit period, the profit detail corresponding to that specific vote should be extended" is violated. For a voter with Vote A (StartPeriod=5, Shares=100) and Vote B (StartPeriod=10, Shares=100), changing Vote B's option will validate Vote B exists but extend Vote A's EndPeriod instead.

## Impact Explanation

**Financial Harm:**
- The voter loses welfare profit claiming rights on the intended vote for multiple periods
- The voter gains unintended welfare profit entitlement on the wrong vote
- This represents misallocation of Treasury welfare funds, affecting the accuracy of the citizen welfare distribution scheme

**Affected Parties:**
- Any voter with multiple old-style profit details having identical weight (same token amount and lock duration)
- The welfare profit scheme experiences incorrect share distribution across periods

**Concrete Example:**
If Vote B should extend from period 24→32 (8 periods of welfare profit), but Vote A extends from period 22→32 (10 periods) instead:
- Vote B loses 8 periods of welfare profit claiming rights
- Vote A gains 10 periods it shouldn't have
- The voter's entitled welfare token distribution per period is misattributed

**Severity: Medium** - Direct financial impact on welfare distribution with concrete misallocation, but limited to the voter's own profit details (not theft from others) and requires specific preconditions.

## Likelihood Explanation

**Attacker Capabilities:**
Any voter can trigger this by calling the public `ChangeVotingOption` method. No special privileges required.

**Preconditions:**
1. Old-style profit details must exist (from pre-upgrade system where `ProfitDetailId` was not set)
2. Voter must have multiple active votes with identical weight (shares)
3. Voter calls `ChangeVotingOption` with `IsResetVotingTime=true`

**Feasibility:**
The code explicitly includes backwards compatibility for "the old world" / "old time", indicating old-style profit details were expected to exist in production following system upgrades. The comments at lines 178 and 286 confirm this design intention. [4](#0-3) [5](#0-4) 

Multiple votes with same weight are realistic - a voter can stake the same amount for the same duration multiple times to different candidates.

**Detection:**
Test coverage creates multiple votes with identical parameters but uses new-style profit details (with `Id` set), not validating the old-style multi-vote scenario. [6](#0-5) 

**Probability: Medium** - If the system was upgraded and had existing votes, old-style details would exist. The bug is deterministic once preconditions are met.

## Recommendation

Ensure consistent selection logic across both validation and extension phases. The recommended fix is to use the same ordering logic in both methods:

**Option 1:** Modify `GetProfitDetailByElectionVotingRecord` to use `OrderBy(d => d.StartPeriod).FirstOrDefault` instead of `LastOrDefault` when matching by shares.

**Option 2:** Store and pass the validated profit detail's `StartPeriod` to `FixProfitDetail` to ensure the same detail is selected, or enhance the matching criteria to include additional identifying fields beyond just shares.

**Option 3:** Implement a migration mechanism to assign proper `Id` values to all old-style profit details, eliminating the need for shares-based matching entirely.

The first option provides the quickest fix with minimal changes, while Option 3 is the most robust long-term solution.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability with old-style profit details
[Fact]
public async Task ChangeVotingOption_OldStyleMultiVote_ExtendsWrongDetail()
{
    // Setup: Create voter with two old-style profit details having identical shares
    var voter = VoterKeyPairs[0];
    
    // Vote A: 15 days, 10 tokens (earlier StartPeriod)
    var voteIdA = await VoteToCandidateAsync(voter, Candidate1, 15 * 86400, 10_00000000);
    var profitDetailA = await GetCitizenWelfareProfitDetails(voter.Address);
    var startPeriodA = profitDetailA.Details[0].StartPeriod;
    var endPeriodA = profitDetailA.Details[0].EndPeriod;
    
    // Simulate old-style: Set Id to null (representing pre-upgrade data)
    // In production this would exist from system upgrade
    profitDetailA.Details[0].Id = null;
    
    await ProduceBlocks(5); // Advance time
    
    // Vote B: 15 days, 10 tokens (later StartPeriod, identical shares)
    var voteIdB = await VoteToCandidateAsync(voter, Candidate2, 15 * 86400, 10_00000000);
    var profitDetailB = await GetCitizenWelfareProfitDetails(voter.Address);
    var startPeriodB = profitDetailB.Details[1].StartPeriod;
    var endPeriodB = profitDetailB.Details[1].EndPeriod;
    
    // Simulate old-style for Vote B as well
    profitDetailB.Details[1].Id = null;
    
    // Both votes have identical shares since same amount and duration
    profitDetailA.Details[0].Shares.ShouldBe(profitDetailB.Details[1].Shares);
    
    // Change Vote B's option with IsResetVotingTime=true
    await ChangeVotingOption(voter, Candidate3, voteIdB, true);
    
    // Verify: Due to inconsistent matching logic
    // GetProfitDetailByElectionVotingRecord would use LastOrDefault (finds Vote B)
    // But FixProfitDetail uses OrderBy StartPeriod + FirstOrDefault (finds Vote A)
    var finalDetails = await GetCitizenWelfareProfitDetails(voter.Address);
    
    // BUG: Vote A's EndPeriod was extended instead of Vote B's
    finalDetails.Details[0].EndPeriod.ShouldBeGreaterThan(endPeriodA); // Vote A incorrectly extended
    finalDetails.Details[1].EndPeriod.ShouldBe(endPeriodB); // Vote B unchanged (BUG)
}
```

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L265-306)
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
    }
```

**File:** test/AElf.Contracts.Election.Tests/Full/CitizenWelfareTests.cs (L428-503)
```csharp
    private async Task Term1Async_4Voters()
    {
        //Voter1
        var voter = VoterKeyPairs[0];
        await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 15 * 86400,
            10_00000000);
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[0].Id.ShouldNotBeNull();
            profitDetail.Details[0].StartPeriod.ShouldBe(2);
            profitDetail.Details[0].EndPeriod.ShouldBe(3);
            _profitShare.AddShares(2, 3, voter.PublicKey.ToHex(), profitDetail.Details[0].Shares);
        }

        //Voter2
        voter = VoterKeyPairs[1];
        await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 15 * 86400,
            10_00000000);
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[0].Id.ShouldNotBeNull();
            profitDetail.Details[0].StartPeriod.ShouldBe(2);
            profitDetail.Details[0].EndPeriod.ShouldBe(3);
            _profitShare.AddShares(2, 3, voter.PublicKey.ToHex(), profitDetail.Details[0].Shares);
        }

        //Voter3
        voter = VoterKeyPairs[2];
        await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 50 * 86400,
            10_00000000);
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[0].Id.ShouldNotBeNull();
            profitDetail.Details[0].StartPeriod.ShouldBe(2);
            profitDetail.Details[0].EndPeriod.ShouldBe(8);
            _profitShare.AddShares(2, 8, voter.PublicKey.ToHex(), profitDetail.Details[0].Shares);
        }

        //Voter4
        voter = VoterKeyPairs[3];
        await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 50 * 86400,
            10_00000000);
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[0].Id.ShouldNotBeNull();
            profitDetail.Details[0].StartPeriod.ShouldBe(2);
            profitDetail.Details[0].EndPeriod.ShouldBe(8);
            _profitShare.AddShares(2, 8, voter.PublicKey.ToHex(), profitDetail.Details[0].Shares);
        }

        await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 15 * 86400,
            10_00000000);
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[1].Id.ShouldNotBeNull();
            profitDetail.Details[1].StartPeriod.ShouldBe(2);
            profitDetail.Details[1].EndPeriod.ShouldBe(3);
            _profitShare.AddShares(2, 3, voter.PublicKey.ToHex(), profitDetail.Details[1].Shares);
        }

        await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 15 * 86400,
            10_00000000);
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[2].Id.ShouldNotBeNull();
            profitDetail.Details[2].StartPeriod.ShouldBe(2);
            profitDetail.Details[2].EndPeriod.ShouldBe(3);
            _profitShare.AddShares(2, 3, voter.PublicKey.ToHex(), profitDetail.Details[2].Shares);
        }
    }
```
