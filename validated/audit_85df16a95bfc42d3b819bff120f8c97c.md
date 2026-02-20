# Audit Report

## Title
Retroactive Vote Weight Inequality - Early Voters Maintain Inflated Weights After Interest Rate Changes

## Summary
The `SetVoteWeightInterest()` function modifies interest rates that affect vote weight calculations for new votes, but existing votes permanently retain their original weights calculated at creation time. This creates unfair reward distribution where early voters who locked in higher interest rates maintain inflated profit shares indefinitely, while later voters voting with identical parameters receive reduced shares after rate decreases.

## Finding Description

**Root Cause:**

When `SetVoteWeightInterest()` updates interest rates, it only modifies the state variable without recalculating existing vote weights stored in the profit contract: [1](#0-0) 

Vote weights are calculated once at vote creation using the current interest rates and then permanently stored as "shares" in the profit scheme. The `Vote()` method calculates weight at vote creation time: [2](#0-1) 

The weight calculation uses the current `State.VoteWeightInterestList.Value`: [3](#0-2) 

These shares are then permanently stored in the profit contract: [4](#0-3) 

The weight is also calculated in view methods by reading the stored lock time and computing weight with current rates: [5](#0-4) 

**Why Weights Are Never Updated:**

Even when votes are extended via `ExtendVoterWelfareProfits()`, the existing weight is reused, not recalculated: [6](#0-5) 

The `FixProfitDetail` method clones the profit detail, preserving the original shares value: [7](#0-6) 

**Reward Distribution Impact:**

Profit distribution uses a proportional formula based on shares. The calculation multiplies beneficiary shares by the distributed amount and divides by total shares: [8](#0-7) [9](#0-8) 

Voters with higher shares receive proportionally more rewards, even after rate changes should have equalized their weights.

## Impact Explanation

**Direct Reward Misallocation:**
- Early voters who locked in higher interest rates maintain permanently inflated profit shares
- Later voters with identical voting parameters (amount, duration) receive reduced shares and rewards
- The disparity persists for entire lock periods (up to `MaximumLockTime`, potentially years)

**Quantified Example:**
1. User A votes 100 tokens for 365 days when interest rate produces weight = 200
2. Governance lowers interest rates via `SetVoteWeightInterest`
3. User B votes 100 tokens for 365 days, now receives weight = 150
4. When profits are distributed:
   - User A receives: `(200 / 350) * distributed_profits = 57.1%`
   - User B receives: `(150 / 350) * distributed_profits = 42.9%`
   - **User A gets 33% more rewards despite identical voting parameters**

**Affected Parties:**
- All voters participating in election governance rewards via the CitizenWelfare scheme
- New voters are systematically disadvantaged after rate decreases
- Protocol fairness and economic incentive alignment compromised

**Severity Justification:**
This violates the core principle that identical voting parameters (amount and duration) should receive identical rewards. The vulnerability creates permanent economic asymmetries in governance participation, undermining the fairness of the reward distribution system.

## Likelihood Explanation

**Highly Practical Occurrence:**
- **Entry Point**: Public voting methods accessible to all users
- **Trigger**: Governance-controlled `SetVoteWeightInterest()` (legitimate governance action)
- **Attacker Capabilities**: None required beyond normal voting rights
- **No Special Preconditions**: Works with any interest rate decrease

**Realistic Scenarios:**

*Scenario 1 - Front-Running:*
When governance proposes a legitimate rate decrease, sophisticated voters can front-run the proposal execution to lock in higher weights before regular users vote after the rate change.

*Scenario 2 - Natural Occurrence:*
Even without malicious intent, when governance legitimately adjusts rates for economic reasons, early voters accidentally maintain advantageous weights while new users unknowingly receive worse terms.

**Detection Difficulty:**
The weight disparity is not easily visible on-chain without comparing historical interest rates to current vote weights, making it unlikely regular users detect the unfairness until they compare their reward distributions.

**Economic Rationality:**
There is zero cost and pure upside for voters who happen to vote before rate decreases, creating a natural incentive to vote before anticipated rate adjustments.

## Recommendation

Implement a mechanism to recalculate existing vote weights when interest rates change, or clearly document that locked-in rates are intentional design. Options include:

1. **Retroactive Recalculation**: Add a function to recalculate all active vote weights when `SetVoteWeightInterest()` is called, updating the shares in the profit contract accordingly.

2. **Proportional Adjustment**: Store a global multiplier that adjusts all shares proportionally when rates change, maintaining relative weights while allowing global adjustments.

3. **Migration Period**: When rates change, allow voters to opt-in to recalculate their weights within a grace period, making the disparity temporary rather than permanent.

4. **Explicit Documentation**: If this is intended behavior (similar to locked-in interest rates in traditional finance), add clear documentation stating that vote weights are permanently locked at creation time and unaffected by subsequent rate changes.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task VoteWeightInequality_AfterInterestRateChange()
{
    // Setup: Initial high interest rates
    var highInterestRates = new VoteWeightInterestList
    {
        VoteWeightInterestInfos =
        {
            new VoteWeightInterest { Day = 365, Interest = 10, Capital = 100 }
        }
    };
    await ElectionContractStub.SetVoteWeightInterest.SendAsync(highInterestRates);
    
    // User A votes with high interest rates
    var userAVoteId = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = CandidatePubkey,
        Amount = 100_00000000,
        EndTimestamp = TimestampHelper.GetUtcNow().AddDays(365)
    });
    var userAWeight = (await ElectionContractStub.GetElectorVoteWithRecords.CallAsync(
        new StringValue { Value = UserAAddress.ToBase58() })).ActiveVotingRecords[0].Weight;
    
    // Governance lowers interest rates
    var lowInterestRates = new VoteWeightInterestList
    {
        VoteWeightInterestInfos =
        {
            new VoteWeightInterest { Day = 365, Interest = 5, Capital = 100 }
        }
    };
    await ElectionContractStub.SetVoteWeightInterest.SendAsync(lowInterestRates);
    
    // User B votes with same parameters but after rate change
    var userBVoteId = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = CandidatePubkey,
        Amount = 100_00000000,
        EndTimestamp = TimestampHelper.GetUtcNow().AddDays(365)
    });
    var userBWeight = (await ElectionContractStub.GetElectorVoteWithRecords.CallAsync(
        new StringValue { Value = UserBAddress.ToBase58() })).ActiveVotingRecords[0].Weight;
    
    // Assert: User A has higher weight despite identical voting parameters
    Assert.True(userAWeight > userBWeight);
    
    // When profits are distributed, User A receives proportionally more
    // despite having identical voting parameters as User B
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L189-208)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L845-920)
```csharp
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
                {
                    Context.LogDebug(() =>
                        $"{beneficiary} is profiting {amount} {symbol} tokens from {scheme.SchemeId.ToHex()} in period {periodToPrint}." +
                        $"Sender's Shares: {detailToPrint.Shares}, total Shares: {distributedProfitsInformation.TotalShares}");
                    if (distributedProfitsInformation.IsReleased && amount > 0)
                    {
                        if (State.TokenContract.Value == null)
                            State.TokenContract.Value =
                                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());

                        Context.Fire(new ProfitsClaimed
                        {
                            Beneficiary = beneficiary,
                            Symbol = symbol,
                            Amount = amount,
                            ClaimerShares = detailToPrint.Shares,
                            TotalShares = distributedProfitsInformation.TotalShares,
                            Period = periodToPrint
                        });
                    }

                    lastProfitPeriod = period + 1;
                }

                totalAmount = totalAmount.Add(amount);
            }

            profitsMap.Add(symbol, totalAmount);
        }

        profitDetail.LastProfitPeriod = lastProfitPeriod;

        return profitsMap;
    }
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
