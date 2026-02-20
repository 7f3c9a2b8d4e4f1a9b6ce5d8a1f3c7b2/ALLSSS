# Audit Report

## Title
Legitimate Vote Target Changes Blocked by Missing Profit Details Due to Integer Division Rounding

## Summary
When voters attempt to change their voting target with `IsResetVotingTime = true`, the operation can fail for legitimate active votes due to missing profit details. This occurs because profit detail `EndPeriod` is calculated using integer division that rounds down, creating a timing gap where profit details can be removed via `ClaimProfits` before the vote lock expires, causing `ExtendVoterWelfareProfits` to throw an `AssertionException` and blocking the vote change operation.

## Finding Description

**Root Cause - Integer Division Rounding:**

The vulnerability originates in the `GetEndPeriod` calculation where `lockTime` (in seconds) is divided by `TimeEachTerm` (period duration in seconds) using integer division. [1](#0-0)  When `lockTime` is not perfectly divisible by `TimeEachTerm`, the result rounds down. For example, with the default `TimeEachTerm` of 604,800 seconds (7 days), a 30-day lock (2,592,000 seconds) results in `EndPeriod = currentPeriod + 4` (representing only 28 days), while the actual vote lock lasts the full 30 days.

**Profit Detail Removal:**

When `ClaimProfits` is called on the welfare scheme, it processes all claimable periods through `ProfitAllPeriods`. [2](#0-1)  The `ProfitAllPeriods` method updates `LastProfitPeriod` to `period + 1` after claiming each period. [3](#0-2)  This value is persisted to the profit detail. [4](#0-3) 

After claiming up to the `EndPeriod`, `LastProfitPeriod` becomes `EndPeriod + 1`. Subsequently, the profit detail is identified for removal because `LastProfitPeriod > EndPeriod`. [5](#0-4)  The detail is then completely removed from the beneficiary's profit details list. [6](#0-5) 

**Vote Change Failure:**

When a voter attempts to change their voting target, the function first validates that the vote hasn't expired. [7](#0-6)  This check passes because the actual lock time (e.g., 30 days) hasn't elapsed yet, even though the profit detail's `EndPeriod` (representing only 28 days due to rounding) has passed.

If `IsResetVotingTime = true`, the function calls `ExtendVoterWelfareProfits`. [8](#0-7)  This function attempts to locate the profit detail using `GetProfitDetailByElectionVotingRecord`, which tries two lookups - first by ID, then by Shares. [9](#0-8) 

Since the profit detail was completely removed from the list, both lookups fail and the function returns `null`. This causes `ExtendVoterWelfareProfits` to throw an `AssertionException`. [10](#0-9)  This blocks the vote change operation even though the vote is legitimate and active.

## Impact Explanation

**Harm Occurrence:**
Voters are unable to change their voting targets when `IsResetVotingTime = true`, resulting in denial of service on a core election functionality. Users are forced to either:
1. Change targets without resetting voting time (`IsResetVotingTime = false`), losing the benefit of extended profit participation
2. Wait until the vote fully expires, then withdraw and create a new vote, incurring additional transaction costs and potentially missing voting opportunities

**Who is Affected:**
Any voter whose `lockTime` is not perfectly divisible by `TimeEachTerm` and who (or whose beneficiaries) claims profits after the rounded-down `EndPeriod` passes but before the actual vote lock expires. This affects a significant portion of users since:
- Common lock periods often don't align with the typical 7-day period duration
- Profit claiming is routine user behavior to realize rewards
- The timing window exists in every such scenario (e.g., 2 days for 30-day locks, 4 days for 60-day locks, 6 days for 90-day locks)

**Protocol Damage:**
- **Operational Disruption**: Core voting functionality becomes unreliable during the timing gap
- **User Experience Degradation**: Legitimate operations fail with cryptic error messages
- **Reduced Flexibility**: Users cannot dynamically adjust their voting strategies during active lock periods
- **No Direct Fund Loss**: Tokens remain locked and recoverable after expiration

**Severity Justification:**
Medium severity is appropriate because:
- **Impact**: Operational denial of service affecting core functionality but no fund theft or permanent loss
- **Likelihood**: High - fractional periods are common in real-world usage with typical configurations
- **Scope**: Affects significant user population with realistic timing conditions

## Likelihood Explanation

**Attacker Capabilities:**
No attacker needed - this is a logic flaw affecting legitimate users. Any voter or third-party profit claimer can inadvertently trigger the condition through normal protocol usage.

**Attack Complexity:**
Minimal complexity:
1. User votes with non-perfectly-divisible lock time (common scenario)
2. Time elapses past the rounded-down `EndPeriod`
3. Anyone calls `ClaimProfits` on the welfare scheme (routine maintenance operation)
4. User attempts to change voting target with reset time
5. Operation fails with `AssertionException`

**Feasibility Conditions:**
Highly feasible and occurs naturally:
- **Fractional Periods**: Lock times like 30 days with 7-day periods create 2-day gaps; 60 days creates 4-day gaps; 90 days creates 6-day gaps
- **Profit Claiming**: Regular operation performed by users or automated systems to realize welfare rewards
- **Timing Window**: Exists from when `EndPeriod` passes until vote expiration (2-6 days in typical scenarios)
- **User Intent**: Legitimate users routinely change voting targets to optimize rewards based on candidate performance

**Probability Reasoning:**
High probability of occurrence:
- Integer division rounding affects the majority of lock time choices (any lock period not perfectly divisible by 7 days)
- Profit claiming happens regularly (weekly, monthly) for reward realization
- Vote changes are common as candidates' performance and rewards vary
- No special privileges or edge conditions required - occurs through normal protocol usage

## Recommendation

**Fix Option 1: Recalculate EndPeriod Instead of Asserting**
Modify `ExtendVoterWelfareProfits` to recreate the profit detail when it's missing instead of throwing an exception:

```csharp
private void ExtendVoterWelfareProfits(Hash voteId)
{
    var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
    var electionVotingRecord = GetElectionVotingRecordByVoteId(voteId);
    var lockTime = State.LockTimeMap[voteId];
    var lockPeriod = lockTime.Div(State.TimeEachTerm.Value);
    if (lockPeriod == 0) return;
    
    var endPeriod = lockPeriod.Add(treasury.CurrentPeriod);
    var extendingDetail = GetProfitDetailByElectionVotingRecord(electionVotingRecord);
    
    if (extendingDetail != null)
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
    else
    {
        // Recreate the profit detail if it was removed
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
}
```

**Fix Option 2: Use Ceiling Division**
Change `GetEndPeriod` to use ceiling division to prevent rounding down:

```csharp
private long GetEndPeriod(long lockTime)
{
    var treasury = State.ProfitContract.GetScheme.Call(State.TreasuryHash.Value);
    var timeEachTerm = State.TimeEachTerm.Value;
    var periods = (lockTime + timeEachTerm - 1).Div(timeEachTerm); // Ceiling division
    return periods.Add(treasury.CurrentPeriod);
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ChangeVotingOption_FailsAfterProfitDetailRemoval_Test()
{
    // Setup: Announce candidate
    await AnnounceElectionAsync(CoreDataCenterKeyPairs[0]);
    
    // Vote with 30-day lock (not perfectly divisible by 7-day periods)
    const long thirtyDaysInSeconds = 30 * 86400; // 2,592,000 seconds
    var voteResult = await VoteToCandidateAsync(
        VoterKeyPairs[0], 
        CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 
        thirtyDaysInSeconds, 
        100);
    
    var voteId = Hash.Parser.ParseFrom(voteResult.ReturnValue);
    
    // Advance time past 28 days (4 periods of 7 days each)
    // This is past the rounded-down EndPeriod but before the actual 30-day lock expires
    await ProduceBlocks(BootMinerKeyPair, 100);
    for (int i = 0; i < 4; i++)
    {
        await NextTerm(BootMinerKeyPair);
    }
    
    // Claim profits - this will remove the profit detail
    await ClaimProfitsAsync(VoterKeyPairs[0]);
    
    // Attempt to change voting option with IsResetVotingTime = true
    // This should fail with "Cannot find profit detail of given vote id"
    var changeResult = await ChangeVotingOption(
        VoterKeyPairs[0], 
        CoreDataCenterKeyPairs[1].PublicKey.ToHex(), 
        voteId, 
        true);
    
    changeResult.Status.ShouldBe(TransactionResultStatus.Failed);
    changeResult.Error.ShouldContain("Cannot find profit detail of given vote id");
}
```

## Notes

The vulnerability is rooted in the mismatch between the actual vote lock duration (stored in `LockTimeMap`) and the profit distribution period (`EndPeriod`). The integer division in `GetEndPeriod` causes the profit system to consider votes "ended" before they actually expire, leading to premature removal of profit details that are still needed for legitimate operations like vote target changes with time reset.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L31-31)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L784-784)
```csharp
            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-789)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L801-806)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L917-917)
```csharp
        profitDetail.LastProfitPeriod = lastProfitPeriod;
```
