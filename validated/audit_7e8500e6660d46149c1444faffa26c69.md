# Audit Report

## Title
Legitimate Vote Target Changes Blocked by Missing Profit Details Due to Integer Division Rounding

## Summary
When voters attempt to change their voting target with `IsResetVotingTime = true`, the operation fails for legitimate active votes due to a timing mismatch between profit detail expiration and actual vote lock expiration. The root cause is integer division in `GetEndPeriod` that rounds down, creating a gap where profit details can be removed before votes expire, causing `ExtendVoterWelfareProfits` to throw an `AssertionException`.

## Finding Description

**Root Cause - Integer Division:**

The `GetEndPeriod` method calculates the profit detail's end period using integer division of `lockTime` by `TimeEachTerm`, which rounds down. [1](#0-0) 

The `TimeEachTerm` value is initialized to `PeriodSeconds` from consensus configuration, which defaults to 604,800 seconds (7 days). [2](#0-1) 

For a 90-day lock (7,776,000 seconds):
- Calculated periods: 7,776,000 / 604,800 = 12 periods (integer division)
- Actual coverage: 12 × 604,800 = 7,257,600 seconds = 84 days
- Gap: 90 - 84 = 6 days

**Profit Detail Removal:**

When `ClaimProfits` is called, it processes periods and updates `LastProfitPeriod`. [3](#0-2) 

After claiming all periods up to `EndPeriod`, `LastProfitPeriod` is set to `period + 1` at line 908. When `LastProfitPeriod > EndPeriod`, the detail is removed from state. [4](#0-3) 

**Vote Change Failure:**

When changing votes, the expiration check uses the actual `lockTime`. [5](#0-4) 

This passes because only 84 days have elapsed (< 90 days). However, when `IsResetVotingTime = true`, the contract calls `ExtendVoterWelfareProfits`. [6](#0-5) 

The `ExtendVoterWelfareProfits` method attempts to retrieve the profit detail. [7](#0-6) 

Since the detail was removed, both lookups (by ID and by Shares) return null. [8](#0-7) 

The operation fails with `AssertionException("Cannot find profit detail of given vote id {voteId}")` even though the vote is legitimate and active.

## Impact Explanation

**Denial of Service on Core Functionality:**
Voters cannot change their voting targets with `IsResetVotingTime = true` during the gap period (6 days in the 90-day example), forcing them to either:
1. Change without reset (`IsResetVotingTime = false`), losing extended profit participation benefits
2. Wait until full vote expiration, then withdraw and re-vote, incurring additional transaction costs

**Who is Affected:**
Any voter whose `lockTime` is not perfectly divisible by `TimeEachTerm` (7 days = 604,800 seconds). Common lock periods (30, 60, 90, 180, 365 days) are not divisible by 7, affecting a significant user population.

**Protocol Damage:**
- Operational disruption of core voting functionality
- Degraded user experience with cryptic error messages
- Reduced flexibility in voting strategy adjustments
- No direct fund loss (tokens remain locked and recoverable)

**Severity: Medium** - Operational DoS affecting core governance functionality with high likelihood, but no fund theft or permanent loss.

## Likelihood Explanation

**Trigger Conditions:**
1. User votes with lock time not perfectly divisible by `TimeEachTerm` (e.g., 90 days)
2. Time elapses past the rounded-down `EndPeriod` (84 days)
3. `ClaimProfits` is called (routine operation by user or anyone)
4. User attempts to change vote with `IsResetVotingTime = true`
5. Operation fails with `AssertionException`

**Probability: High**
- Most common lock times create gaps (30, 60, 90, 180, 365 days not divisible by 7)
- Profit claiming is regular user behavior for reward realization
- Vote changes are common as users optimize their strategies
- No special privileges or edge conditions required
- Timing window exists for multiple days in each scenario

## Recommendation

**Fix the `GetEndPeriod` calculation to use ceiling division instead of floor division:**

```csharp
private long GetEndPeriod(long lockTime)
{
    var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
    // Use ceiling division to ensure full coverage
    var periods = (lockTime + State.TimeEachTerm.Value - 1).Div(State.TimeEachTerm.Value);
    return periods.Add(treasury.CurrentPeriod);
}
```

This ensures the profit detail's `EndPeriod` covers the entire lock duration.

**Alternative: Add a null check and graceful handling in `ExtendVoterWelfareProfits`:**

```csharp
var extendingDetail = GetProfitDetailByElectionVotingRecord(electionVotingRecord);
if (extendingDetail == null)
{
    // Re-add beneficiary with new EndPeriod instead of extending
    State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
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
    return;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task VoteChangeWithResetFailsAfterProfitDetailRemoval()
{
    // Setup: Announce candidates
    var candidatesKeyPairs = ValidationDataCenterKeyPairs.Take(2).ToList();
    await AnnounceElectionAsync(candidatesKeyPairs[0]);
    await AnnounceElectionAsync(candidatesKeyPairs[1]);

    // Vote with 90-day lock (7,776,000 seconds)
    var voterKeyPair = VoterKeyPairs.First();
    const long lockTime = 90 * 24 * 60 * 60; // 90 days
    const long amount = 1000;
    
    var voteResult = await VoteToCandidateAsync(
        voterKeyPair, 
        candidatesKeyPairs[0].PublicKey.ToHex(),
        lockTime, 
        amount
    );
    var voteId = Hash.Parser.ParseFrom(voteResult.ReturnValue);

    // Advance time by 12 periods (84 days) and proceed to next term
    for (int i = 0; i < 12; i++)
    {
        await NextTerm(InitialCoreDataCenterKeyPairs[0]);
    }

    // Claim profits - this removes the profit detail
    await ClaimProfitsAsync(voterKeyPair);

    // Verify profit detail is removed
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(
        new GetProfitDetailsInput
        {
            Beneficiary = Address.FromPublicKey(voterKeyPair.PublicKey),
            SchemeId = ProfitItemsIds[ProfitType.CitizenWelfare]
        }
    );
    profitDetails.Details.Count.ShouldBe(0); // Detail removed

    // Try to change vote with IsResetVotingTime = true
    // This should fail with AssertionException
    var changeResult = await ChangeVotingOption(
        voterKeyPair,
        candidatesKeyPairs[1].PublicKey.ToHex(),
        voteId,
        isResetVotingTime: true
    );
    
    // Expected: Transaction fails with "Cannot find profit detail" error
    changeResult.Status.ShouldBe(TransactionResultStatus.Failed);
    changeResult.Error.ShouldContain("Cannot find profit detail");
}
```

## Notes

This vulnerability demonstrates a classic off-by-one error in duration calculations where integer division creates unintended gaps. The issue is exacerbated by the separation of concerns between the Election contract (which tracks vote expiration) and the Profit contract (which tracks reward periods), with no synchronization mechanism to ensure consistency.

The recommended fix using ceiling division ensures mathematical correctness: if a voter locks tokens for 90 days, their profit eligibility should extend for the full 90 days, not just 84 days. This aligns user expectations with system behavior and eliminates the DoS window.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L29-31)
```csharp
        var actualLockedSeconds = Context.CurrentBlockTime.Seconds.Sub(votingRecord.VoteTimestamp.Seconds);
        var claimedLockingSeconds = State.LockTimeMap[input.VoteId];
        Assert(actualLockedSeconds < claimedLockingSeconds, "This vote already expired.");
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L612-616)
```csharp
    private long GetEndPeriod(long lockTime)
    {
        var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
        return lockTime.Div(State.TimeEachTerm.Value).Add(treasury.CurrentPeriod);
    }
```

**File:** src/AElf.GovernmentSystem/ElectionContractInitializationProvider.cs (L40-40)
```csharp
                    TimeEachTerm = _consensusOptions.PeriodSeconds,
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-806)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;

        foreach (var profitDetail in profitDetailsToRemove)
        {
            availableDetails.Remove(profitDetail);
        }

        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };
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
