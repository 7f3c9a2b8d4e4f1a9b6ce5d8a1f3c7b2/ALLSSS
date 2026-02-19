### Title
Profit Detail Misidentification Due to Inconsistent Selection Logic for Legacy Votes with Identical Shares

### Summary
The Election contract's `GetProfitDetailByElectionVotingRecord()` function uses `LastOrDefault` to find legacy profit details by Shares value, while the Profit contract's `FixProfitDetail()` uses `OrderBy(StartPeriod).FirstOrDefault` with the same criteria. This mismatch causes the wrong profit detail to be extended when a voter has multiple legacy votes with identical weight values, resulting in incorrect welfare profit distributions.

### Finding Description

The vulnerability exists in the handling of legacy profit details (those created before the ProfitDetailId feature was implemented, where `profitDetail.Id` is null). [1](#0-0) 

In the Election contract, when retrieving a profit detail for legacy votes, the code falls back to matching by Shares value using `LastOrDefault`. [2](#0-1) 

However, the Profit contract's `FixProfitDetail` function uses a different selection strategy for the same scenario - it orders by StartPeriod and uses `FirstOrDefault`. [3](#0-2) 

This inconsistency creates a critical mismatch:
- **Validation phase** (Election contract): Returns the LAST profit detail with matching Shares
- **Execution phase** (Profit contract): Modifies the FIRST profit detail (by StartPeriod) with matching Shares

Multiple votes can have identical Shares values due to the weight calculation's rounding behavior when converting from decimal to long. [4](#0-3) 

The vote weight calculation involves complex exponential operations and integer casting that can produce collisions for different (amount, lockTime) combinations.

The vulnerable execution path occurs in `ExtendVoterWelfareProfits`, which is called when a voter changes their voting target with `IsResetVotingTime = true`. [5](#0-4) 

### Impact Explanation

**Direct Fund Impact - Reward Misallocation:**
- When a voter attempts to extend Vote B's profit period, Vote A's profit detail gets extended instead
- The intended vote (B) does not receive extended welfare profit benefits
- An unintended vote (A) continues receiving welfare profits beyond its intended period
- This violates the critical invariant for "Profit/Treasury/TokenHolder share calculations, dividend distribution and settlement accuracy"

**Affected Parties:**
- Voters with multiple legacy votes having identical weights suffer incorrect profit allocations
- The overall welfare profit scheme distributes rewards incorrectly
- Protocol integrity is compromised as profit extension operations do not match user intentions

**Severity Justification:**
This is HIGH severity because it directly causes incorrect financial distributions in the welfare profit system, affecting voter rewards and potentially allowing unintended profit extensions that could drain the welfare pool incorrectly.

### Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is triggered through the public `ChangeVotingOption` function, callable by any voter. [6](#0-5) 

**Feasible Preconditions:**
1. Legacy profit details exist from before ProfitDetailId implementation (confirmed by code comments indicating "old world" data)
2. A voter has multiple legacy votes with identical calculated weights
3. Weight collisions are realistic due to rounding in the exponential calculation: `(long)(Pow(initBase, (uint)lockDays) * votesAmount)`

**Execution Practicality:**
- No special privileges required - any voter can call `ChangeVotingOption`
- No complex state manipulation needed
- Simple transaction execution under normal AElf contract semantics

**Economic Rationality:**
- Standard gas costs for vote operations
- No economic barriers to exploitation
- Occurs naturally when voters have multiple votes with similar parameters

**Detection Constraints:**
The mismatch is silent - the transaction succeeds but modifies the wrong profit detail. No on-chain events would indicate the error occurred.

### Recommendation

**Immediate Fix:**
Align the selection logic between both contracts. In `GetProfitDetailByElectionVotingRecord`, change the fallback selection to match the Profit contract's ordering:

```csharp
if (profitDetail == null)
{
    profitDetail = profitDetails.Details.OrderBy(d => d.StartPeriod)
        .FirstOrDefault(d => d.Shares == electionVotingRecord.Weight);
}
```

**Invariant Checks:**
Add validation in `ExtendVoterWelfareProfits` to verify that the returned profit detail, when found by Shares, actually corresponds to the intended voteId by comparing other attributes (Amount, VoteTimestamp, or beneficiary context).

**Additional Safeguards:**
Consider implementing a migration to populate null ProfitDetailIds in legacy profit details with their corresponding voteIds to eliminate reliance on Shares-based lookups entirely.

**Test Cases:**
1. Create two legacy votes with identical weights but different StartPeriods
2. Attempt to extend the vote with the later StartPeriod
3. Verify that the correct profit detail (not the one with earlier StartPeriod) gets extended
4. Assert that profit period extensions match the voteId being modified

### Proof of Concept

**Initial State:**
- Voter has two legacy profit details (ProfitDetailId = null):
  - Detail A: StartPeriod=100, EndPeriod=200, Shares=5000 (Vote A created first)
  - Detail B: StartPeriod=150, EndPeriod=250, Shares=5000 (Vote B created later, same weight)

**Attack Steps:**
1. Voter calls `ChangeVotingOption` for Vote B with `IsResetVotingTime = true`
2. `ExtendVoterWelfareProfits(voteId_B)` executes
3. `GetProfitDetailByElectionVotingRecord` searches for Shares=5000
4. Returns Detail B via `LastOrDefault` (validation passes)
5. Calls `FixProfitDetail` with ProfitDetailId=voteId_B, Shares=5000
6. `FixProfitDetail` searches for Shares=5000 with OrderBy(StartPeriod)
7. Returns Detail A (StartPeriod=100 < 150)
8. Extends Detail A's EndPeriod instead of Detail B's

**Expected Result:**
Vote B's profit detail should have its EndPeriod extended to CurrentPeriod + (lockTime/termTime)

**Actual Result:**
Vote A's profit detail has its EndPeriod extended, while Vote B's remains unchanged

**Success Condition:**
Query profit details after the operation - Detail A's EndPeriod is modified (incorrect), Detail B's EndPeriod is unchanged (incorrect).

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L23-39)
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
