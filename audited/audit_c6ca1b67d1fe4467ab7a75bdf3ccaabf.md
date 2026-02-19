# Audit Report

## Title
Legitimate Vote Target Changes Blocked by Missing Profit Details Due to Integer Division Rounding

## Summary
When voters attempt to change their voting target with `IsResetVotingTime = true`, the operation fails for legitimate active votes due to a timing mismatch between profit detail expiration and actual vote lock expiration. The root cause is integer division in `GetEndPeriod` that rounds down, creating a gap where profit details can be removed before votes expire, causing `ExtendVoterWelfareProfits` to throw an `AssertionException`.

## Finding Description

**Root Cause - Integer Division:**

The `GetEndPeriod` method calculates the profit detail's end period using integer division of `lockTime` by `TimeEachTerm`, which rounds down: [1](#0-0) 

For example, with a 90-day lock (7,776,000 seconds) and 7-day periods (604,800 seconds):
- Calculated periods: 7,776,000 / 604,800 = 12 periods (integer division)
- Actual coverage: 12 × 604,800 = 7,257,600 seconds = 84 days
- Gap: 90 - 84 = 6 days

**Profit Detail Removal:**

When `ClaimProfits` is called, it processes periods and updates `LastProfitPeriod`: [2](#0-1) 

After claiming all periods up to `EndPeriod`, `LastProfitPeriod` becomes `EndPeriod + 1`. This triggers removal: [3](#0-2) 

**Vote Change Failure:**

When changing votes, the expiration check uses the actual `lockTime`: [4](#0-3) 

This passes because only 84 days have elapsed (< 90 days). However, when `IsResetVotingTime = true`: [5](#0-4) 

The `ExtendVoterWelfareProfits` method attempts to retrieve the profit detail: [6](#0-5) 

Since the detail was removed, both lookups (by ID and by Shares) return null: [7](#0-6) 

The operation fails with `AssertionException` even though the vote is legitimate and active.

## Impact Explanation

**Denial of Service on Core Functionality:**
Voters cannot change their voting targets with `IsResetVotingTime = true` during the gap period (6 days in the 90-day example), forcing them to either:
1. Change without reset (`IsResetVotingTime = false`), losing extended profit participation benefits
2. Wait until full vote expiration, then withdraw and re-vote, incurring additional transaction costs

**Who is Affected:**
Any voter whose `lockTime` is not perfectly divisible by `TimeEachTerm` (7 days = 604,800 seconds). Given the default configuration: [8](#0-7) 

Common lock periods (30, 60, 90, 180, 365 days) are not divisible by 7, affecting a significant user population.

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

**Solution:** Align profit detail `EndPeriod` with actual vote lock expiration by using ceiling division or storing the actual end timestamp:

```csharp
private long GetEndPeriod(long lockTime)
{
    var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
    // Use ceiling division to cover the full lock time
    var periods = lockTime.Add(State.TimeEachTerm.Value).Sub(1).Div(State.TimeEachTerm.Value);
    return periods.Add(treasury.CurrentPeriod);
}
```

Or alternatively, add a grace period check in `ExtendVoterWelfareProfits`:

```csharp
private void ExtendVoterWelfareProfits(Hash voteId)
{
    var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
    var electionVotingRecord = GetElectionVotingRecordByVoteId(voteId);
    var lockTime = State.LockTimeMap[voteId];
    var lockPeriod = lockTime.Div(State.TimeEachTerm.Value);
    if (lockPeriod == 0)
    {
        return;
    }

    var endPeriod = lockPeriod.Add(treasury.CurrentPeriod);
    var extendingDetail = GetProfitDetailByElectionVotingRecord(electionVotingRecord);
    
    // If detail is missing, re-add it instead of throwing
    if (extendingDetail == null)
    {
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
    }
    else
    {
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
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Test_ChangeVotingOption_FailsAfterProfitDetailRemoved()
{
    // Setup: Initialize contracts and announce candidate
    await InitializeContracts();
    var candidateKeyPair = CoreDataCenterKeyPairs[0];
    await AnnounceElectionAsync(candidateKeyPair);
    
    // Step 1: User votes with 90-day lock (not divisible by 7-day periods)
    var voterKeyPair = VoterKeyPairs[0];
    var lockTime = 90 * 86400; // 90 days in seconds
    var voteAmount = 1000_00000000;
    
    var voteId = await VoteToCandidateAsync(voterKeyPair, 
        candidateKeyPair.PublicKey.ToHex(), 
        lockTime, 
        voteAmount);
    
    // Step 2: Advance time to 84 days (EndPeriod with integer division: 90 days / 7 days = 12 periods = 84 days)
    await AdvanceTime(84 * 86400);
    
    // Step 3: Claim profits (this removes the profit detail because LastProfitPeriod > EndPeriod)
    await ClaimProfitsAsync(voterKeyPair);
    
    // Step 4: Verify profit detail is removed
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(
        new GetProfitDetailsInput
        {
            Beneficiary = Address.FromPublicKey(voterKeyPair.PublicKey),
            SchemeId = WelfareSchemeId
        });
    profitDetails.Details.ShouldNotContain(d => d.Id == voteId);
    
    // Step 5: Attempt to change vote with IsResetVotingTime = true
    // This should fail because profit detail is missing but vote is still active (84 days < 90 days)
    var result = await GetElectionContractTester(voterKeyPair)
        .ChangeVotingOption.SendWithExceptionAsync(new ChangeVotingOptionInput
        {
            CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
            VoteId = voteId,
            IsResetVotingTime = true
        });
    
    // Verify: Operation fails with AssertionException about missing profit detail
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Cannot find profit detail of given vote id");
}
```

## Notes

This vulnerability demonstrates a critical mismatch between two independent time-tracking mechanisms: the profit detail's `EndPeriod` (calculated via integer division) and the vote's actual `lockTime` (stored as-is). The integer division creates a systematic timing gap that becomes exploitable through normal protocol operations, resulting in denial of service on legitimate vote changing functionality. The issue affects a substantial user population given that common lock periods (multiples of 30 days) do not align with the 7-day period duration.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L29-31)
```csharp
        var actualLockedSeconds = Context.CurrentBlockTime.Seconds.Sub(votingRecord.VoteTimestamp.Seconds);
        var claimedLockingSeconds = State.LockTimeMap[input.VoteId];
        Assert(actualLockedSeconds < claimedLockingSeconds, "This vote already expired.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L33-37)
```csharp
        if (input.IsResetVotingTime)
        {
            // true for extend EndPeroid of a Profit details, e.g. you vote for 12 months, and on the 6th month, you
            // change the vote, then there will be another 12 months from that time.
            ExtendVoterWelfareProfits(input.VoteId);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L156-159)
```csharp
        else
        {
            throw new AssertionException($"Cannot find profit detail of given vote id {voteId}");
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L908-908)
```csharp
                    lastProfitPeriod = period + 1;
```

**File:** src/AElf.OS.Core/EconomicOptions.cs (L15-16)
```csharp
    public long MaximumLockTime { get; set; } = 1080 * 86400;
    public long MinimumLockTime { get; set; } = 90 * 86400;
```
