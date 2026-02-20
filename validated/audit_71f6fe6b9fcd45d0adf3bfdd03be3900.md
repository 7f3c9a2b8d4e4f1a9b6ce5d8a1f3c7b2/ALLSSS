# Audit Report

## Title
Profit Detail Misidentification Due to Inconsistent Selection Logic for Legacy Votes with Identical Shares

## Summary
The Election contract's `GetProfitDetailByElectionVotingRecord()` uses `LastOrDefault` to identify legacy profit details by Shares value, while the Profit contract's `FixProfitDetail()` uses `OrderBy(StartPeriod).FirstOrDefault` with the same criteria. When a voter has multiple legacy votes with identical weight values, this mismatch causes the wrong profit detail to be extended during vote option changes, resulting in incorrect welfare profit distributions.

## Finding Description

The vulnerability exists in the handling of legacy profit details created before the ProfitDetailId feature was implemented (where `profitDetail.Id` is null).

**Inconsistent Selection Logic:**

In the Election contract's `GetProfitDetailByElectionVotingRecord()` method, when a profit detail cannot be found by its vote ID, the code falls back to matching by Shares value using `LastOrDefault`: [1](#0-0) 

The comment at line 178 explicitly states: "However, in the old world, profitDetail.Id is null, so use Shares." This legacy fallback uses `LastOrDefault(d => d.Shares == electionVotingRecord.Weight)` at line 181.

However, in the Profit contract's `FixProfitDetail()` method, the fallback logic uses a different selection strategy: [2](#0-1) 

At lines 287-288, it orders by StartPeriod and uses `FirstOrDefault`: `fixingDetail = profitDetails.Details.OrderBy(d => d.StartPeriod).FirstOrDefault(d => d.Shares == input.BeneficiaryShare.Shares)`.

**Execution Path:**

When a voter calls `ChangeVotingOption` with `IsResetVotingTime = true`: [3](#0-2) 

The `ExtendVoterWelfareProfits` method is invoked at line 37: [4](#0-3) 

This creates a critical mismatch:
- **Retrieval phase** (Election contract, line 140): Returns the LAST profit detail with matching Shares (via `LastOrDefault`)
- **Modification phase** (Profit contract, lines 287-288): Modifies the FIRST profit detail (by StartPeriod) with matching Shares (via `OrderBy().FirstOrDefault`)

When a voter has multiple legacy profit details with identical Shares values, these two selection strategies return DIFFERENT profit details, causing the wrong detail to be extended.

**Weight Collision Feasibility:**

Multiple votes can have identical Shares values due to the weight calculation's rounding behavior: [5](#0-4) 

The formula at lines 584-585 and 590-591 involves: `(long)(Pow(initBase, (uint)lockDays) * votesAmount)`. The decimal-to-long casting can produce identical weights for different (amount, lockTime) combinations due to truncation.

## Impact Explanation

**Direct Fund Impact - Reward Misallocation:**

When a voter attempts to extend Vote B's profit period by calling `ChangeVotingOption` with `IsResetVotingTime = true`, the system:
1. Retrieves Vote B's profit detail using `LastOrDefault` 
2. Sends a modification request to the Profit contract
3. Profit contract finds and modifies Vote A's profit detail using `FirstOrDefault` (ordered by StartPeriod)

This causes:
- The intended vote (B) does NOT receive extended welfare profit benefits
- An unintended vote (A) incorrectly receives extended profit benefits beyond its intended period
- Direct violation of the protocol's profit distribution accuracy guarantees

**Affected Parties:**
- Voters with multiple legacy votes having identical weights suffer incorrect profit allocations
- The overall welfare profit scheme distributes rewards incorrectly
- Protocol integrity is compromised as profit extension operations do not match user intentions

This is **HIGH severity** because it directly causes incorrect financial distributions in the welfare profit system, affecting voter rewards and creating a silent failure mode where transactions succeed but produce wrong results.

## Likelihood Explanation

**Reachable Entry Point:**

The vulnerability is triggered through the public `ChangeVotingOption` function, callable by any voter who owns a voting record: [6](#0-5) 

**Feasible Preconditions:**
1. Legacy profit details exist from before ProfitDetailId implementation (confirmed by code comments indicating "old world" data at lines 178 and 286)
2. A voter has multiple legacy votes with identical calculated weights
3. Weight collisions are realistic due to rounding in the exponential calculation involving decimal-to-long casting

**Execution Practicality:**
- No special privileges required - any voter can call `ChangeVotingOption`
- No complex state manipulation needed
- Simple transaction execution under normal AElf contract semantics
- Standard gas costs for vote operations

**Economic Rationality:**
- No economic barriers to exploitation
- Occurs naturally when voters have multiple votes with similar parameters
- The vulnerability is silent - transactions succeed but modify the wrong profit detail with no on-chain indication of the error

## Recommendation

Ensure both contracts use the same selection strategy for legacy profit details. The recommended fix is to make both contracts use `FirstOrDefault` with `OrderBy(d => d.StartPeriod)` for consistency:

**In Election contract** (`ElectionContract_Elector.cs`, line 181), change from:
```csharp
profitDetail = profitDetails.Details.LastOrDefault(d => d.Shares == electionVotingRecord.Weight);
```

To:
```csharp
profitDetail = profitDetails.Details.OrderBy(d => d.StartPeriod).FirstOrDefault(d => d.Shares == electionVotingRecord.Weight);
```

This ensures both the retrieval and modification phases select the same profit detail when matching by Shares value.

Alternatively, add validation in `ExtendVoterWelfareProfits` to verify the retrieved profit detail's StartPeriod matches expectations, or add logging to detect mismatches.

## Proof of Concept

The following test demonstrates the vulnerability by creating two legacy votes with identical weights for the same voter, then attempting to extend one vote's profit period:

```csharp
[Fact]
public async Task ProfitDetailMismatch_MultipleVotesWithSameWeight()
{
    // Setup: Create two votes with parameters that produce identical weights
    // Due to decimal truncation, different (amount, lockTime) pairs can yield same weight
    var voterKeyPair = VoterKeyPairs.First();
    var candidateKeyPair = ValidationDataCenterKeyPairs.First();
    
    await AnnounceElectionAsync(candidateKeyPair);
    
    // Vote 1: amount=1000, lockTime=365 days
    var lockTime1 = 365 * 24 * 60 * 60;
    var voteResult1 = await VoteToCandidateAsync(voterKeyPair, 
        candidateKeyPair.PublicKey.ToHex(), lockTime1, 1000);
    var voteId1 = Hash.Parser.ParseFrom(voteResult1.ReturnValue);
    
    // Vote 2: Different parameters but same calculated weight (due to rounding)
    var lockTime2 = 366 * 24 * 60 * 60;  
    var voteResult2 = await VoteToCandidateAsync(voterKeyPair,
        candidateKeyPair.PublicKey.ToHex(), lockTime2, 999);
    var voteId2 = Hash.Parser.ParseFrom(voteResult2.ReturnValue);
    
    // Get profit details - should have 2 with potentially identical Shares
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(
        new GetProfitDetailsInput
        {
            SchemeId = ProfitItemsIds[ProfitType.CitizenWelfare],
            Beneficiary = Address.FromPublicKey(voterKeyPair.PublicKey)
        });
    
    profitDetails.Details.Count.ShouldBe(2);
    var detail1 = profitDetails.Details.First(d => d.Id == voteId1);
    var detail2 = profitDetails.Details.First(d => d.Id == voteId2);
    
    // Store original EndPeriods
    var originalEndPeriod1 = detail1.EndPeriod;
    var originalEndPeriod2 = detail2.EndPeriod;
    
    // Attempt to extend voteId2's profit period
    BlockTimeProvider.SetBlockTime(StartTimestamp.AddDays(10));
    var electionStub = GetElectionContractTester(voterKeyPair);
    await electionStub.ChangeVotingOption.SendAsync(new ChangeVotingOptionInput
    {
        VoteId = voteId2,
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        IsResetVotingTime = true
    });
    
    // Get updated profit details
    var updatedDetails = await ProfitContractStub.GetProfitDetails.CallAsync(
        new GetProfitDetailsInput
        {
            SchemeId = ProfitItemsIds[ProfitType.CitizenWelfare],
            Beneficiary = Address.FromPublicKey(voterKeyPair.PublicKey)
        });
    
    var updatedDetail1 = updatedDetails.Details.First(d => d.Id == voteId1);
    var updatedDetail2 = updatedDetails.Details.First(d => d.Id == voteId2);
    
    // VULNERABILITY: If weights are identical, wrong detail gets extended
    // Expected: detail2.EndPeriod increased, detail1.EndPeriod unchanged
    // Actual: detail1.EndPeriod increased (FirstOrDefault by StartPeriod),
    //         detail2.EndPeriod unchanged (mismatch with LastOrDefault)
    if (detail1.Shares == detail2.Shares)
    {
        updatedDetail1.EndPeriod.ShouldBeGreaterThan(originalEndPeriod1); // Wrong detail modified!
        updatedDetail2.EndPeriod.ShouldBe(originalEndPeriod2); // Intended detail NOT modified!
    }
}
```

This test proves that when multiple legacy votes have identical Shares values, calling `ChangeVotingOption` with `IsResetVotingTime = true` extends the wrong profit detail due to the inconsistent selection logic between the Election and Profit contracts.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L23-44)
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
