# Audit Report

## Title
Retroactive Vote Weight Inequality - Early Voters Maintain Inflated Weights After Interest Rate Changes

## Summary
The `SetVoteWeightInterest()` function modifies interest rates affecting vote weight calculations for new votes, but existing votes permanently retain their original weights stored in the profit contract. This creates unfair reward distribution where voters with identical parameters (amount, duration) receive different shares based solely on when they voted relative to interest rate changes.

## Finding Description

When governance calls `SetVoteWeightInterest()` to adjust interest rates, the function only updates the state variable without any mechanism to recalculate existing vote weights: [1](#0-0) 

Vote weights are calculated exactly once at vote creation using `GetVotesWeight()` with the current interest rates: [2](#0-1) 

During voting, this calculated weight is passed as shares to the CitizenWelfare profit scheme: [3](#0-2) [4](#0-3) 

Even when votes are extended via `ExtendVoterWelfareProfits()` during `ChangeVotingOption`, although the method recalculates the weight, the `FixProfitDetail()` method in the Profit contract only clones the existing detail and updates period information without modifying shares: [5](#0-4) [6](#0-5) 

The cloned profit detail preserves the original shares value - the `Clone()` operation maintains all fields including shares, and only `StartPeriod` and `EndPeriod` are explicitly updated.

Profit distribution directly uses these frozen shares to calculate each voter's reward portion: [7](#0-6) [8](#0-7) 

## Impact Explanation

This vulnerability breaks the fundamental fairness invariant that equal voting parameters should yield equal voting power and rewards. The concrete impact includes:

**Direct Economic Harm:**
- User A votes 100 tokens for 365 days at high interest rates → receives weight of 200 shares
- Governance lowers interest rates via `SetVoteWeightInterest`
- User B votes 100 tokens for 365 days at new rates → receives weight of 150 shares
- User A permanently receives 200/(200+150) = 57.1% of rewards
- User B receives only 150/(200+150) = 42.9% of rewards
- **User A gets 33% more rewards despite identical voting parameters**

This disparity persists for the entire lock period (up to `MaximumLockTime`, potentially years). The only way to update weights is to withdraw after expiry and re-vote, losing the voting position.

The vulnerability systematically disadvantages new participants and violates protocol fairness guarantees.

## Likelihood Explanation

This vulnerability has high likelihood because:

**Triggering Conditions:**
- Requires only a legitimate governance action (`SetVoteWeightInterest`) which is expected for normal economic adjustments
- No special attacker capabilities needed beyond standard voting rights
- Works with any interest rate change (increase or decrease creates asymmetry)

**Exploit Scenarios:**

1. **Malicious Governance:** Insiders vote early to lock high rates, then lower rates to disadvantage competitors
2. **Front-Running:** Sophisticated voters monitor governance proposals and vote before rate decreases execute
3. **Natural Occurrence:** Legitimate rate adjustments automatically create unfair advantages for existing voters without any malicious intent

The weight disparity is not easily visible on-chain, making detection by affected users unlikely.

## Recommendation

Implement a mechanism to recalculate and update shares for existing votes when interest rates change. Two approaches:

**Option 1: Recalculate on Interest Rate Change**
When `SetVoteWeightInterest()` is called, iterate through active votes and update their shares proportionally in the Profit contract. This requires tracking all active vote IDs.

**Option 2: Snapshot-Based System**
Instead of storing absolute shares, store the voting parameters (amount, lock time) and interest rate snapshot ID. Calculate shares dynamically during profit distribution based on these parameters. This avoids needing to update existing records but requires more computation during distribution.

**Option 3: Update FixProfitDetail**
Modify `FixProfitDetail()` to accept and apply a new shares value instead of cloning the old one:

```csharp
// In FixProfitDetail, add logic to update shares if provided
if (input.BeneficiaryShare.Shares > 0)
{
    newDetail.Shares = input.BeneficiaryShare.Shares;
    // Also update scheme's TotalShares accordingly
}
```

Then modify `ExtendVoterWelfareProfits()` to recalculate weight with current interest rates and pass it to update shares.

## Proof of Concept

```csharp
[Fact]
public async Task Vote_Weight_Inequality_After_Interest_Rate_Change_Test()
{
    // Initial setup with high interest rates (default)
    var initialInterest = await ElectionContractStub.GetVoteWeightSetting.CallAsync(new Empty());
    
    // User A votes with 100 tokens for 365 days
    var userAKeyPair = ValidationDataCenterKeyPairs[0];
    var candidateKeyPair = ValidationDataCenterKeyPairs[1];
    await AnnounceElectionAsync(candidateKeyPair);
    
    var voteAmount = 100_00000000;
    var lockTime = 365 * 86400; // 365 days
    
    var userAVoteResult = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        Amount = voteAmount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime)
    });
    var voteIdA = Hash.Parser.ParseFrom(userAVoteResult.TransactionResult.ReturnValue);
    
    // Get User A's weight
    var recordA = await ElectionContractStub.GetElectorVoteWithRecords.CallAsync(
        new StringValue { Value = userAKeyPair.PublicKey.ToHex() });
    var weightA = recordA.ActiveVotingRecords[0].Weight;
    
    // Governance lowers interest rates
    var newInterestList = new VoteWeightInterestList
    {
        VoteWeightInterestInfos =
        {
            new VoteWeightInterest { Day = 365, Interest = 1, Capital = 1000 },
            new VoteWeightInterest { Day = 730, Interest = 15, Capital = 10000 },
            new VoteWeightInterest { Day = 1095, Interest = 2, Capital = 1000 }
        }
    };
    await ExecuteProposalForParliamentTransaction(ElectionContractAddress,
        nameof(ElectionContractStub.SetVoteWeightInterest), newInterestList);
    
    // User B votes with identical parameters after rate change
    var userBKeyPair = ValidationDataCenterKeyPairs[2];
    var userBVoteResult = await GetElectionContractStub(userBKeyPair).Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        Amount = voteAmount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime)
    });
    
    // Get User B's weight
    var recordB = await GetElectionContractStub(userBKeyPair).GetElectorVoteWithRecords.CallAsync(
        new StringValue { Value = userBKeyPair.PublicKey.ToHex() });
    var weightB = recordB.ActiveVotingRecords[0].Weight;
    
    // Verify: Despite identical voting parameters, weights are different
    weightA.ShouldNotBe(weightB);
    
    // Get profit shares to confirm frozen inequality
    var profitDetailsA = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = State.WelfareHash.Value,
        Beneficiary = Address.FromPublicKey(userAKeyPair.PublicKey)
    });
    var profitDetailsB = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = State.WelfareHash.Value,
        Beneficiary = Address.FromPublicKey(userBKeyPair.PublicKey)
    });
    
    var sharesA = profitDetailsA.Details[0].Shares;
    var sharesB = profitDetailsB.Details[0].Shares;
    
    // Shares are permanently different, causing unfair reward distribution
    sharesA.ShouldNotBe(sharesB);
    sharesA.ShouldBeGreaterThan(sharesB);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L189-207)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L265-305)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L843-876)
```csharp
    }

    private Dictionary<string, long> ProfitAllPeriods(Scheme scheme, ProfitDetail profitDetail, Address beneficiary, long maxProfitReceivingPeriodCount,
        bool isView = false, string targetSymbol = null)
    {
        var profitsMap = new Dictionary<string, long>();
        var lastProfitPeriod = profitDetail.LastProfitPeriod;

        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };

        foreach (var symbol in symbols)
        {
            var totalAmount = 0L;
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
            {
                var periodToPrint = period;
                var detailToPrint = profitDetail;
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;

                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);

                if (!isView)
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L956-962)
```csharp
    private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
    {
        var decimalTotalAmount = (decimal)totalAmount;
        var decimalShares = (decimal)shares;
        var decimalTotalShares = (decimal)totalShares;
        return (long)(decimalTotalAmount * decimalShares / decimalTotalShares);
    }
```
