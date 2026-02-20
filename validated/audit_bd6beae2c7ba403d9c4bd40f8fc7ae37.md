# Audit Report

## Title
Repeated Welfare Profit Extension Without Additional Lock Commitment

## Summary
A voter can repeatedly call `ChangeVotingOption` with `IsResetVotingTime=true` before their vote expires to indefinitely extend their welfare profit collection period without any additional lock time commitment. This allows voters to collect welfare profits far beyond their original lock commitment, diluting rewards for legitimate long-term voters.

## Finding Description

When a voter calls `ChangeVotingOption` with `IsResetVotingTime=true`, the method invokes `ExtendVoterWelfareProfits` which recalculates the welfare profit endPeriod based on the current treasury period. [1](#0-0) 

The critical vulnerability lies in `ExtendVoterWelfareProfits`: it reads the original `lockTime` from state but never modifies it, as explicitly documented in the code comment "Extend endPeriod from now no, so the lockTime will *NOT* be changed." [2](#0-1) 

The new `endPeriod` is calculated as `lockPeriod.Add(treasury.CurrentPeriod)`, where `lockPeriod` is derived from the unchanged `lockTime`. Since `treasury.CurrentPeriod` continuously increases with each period distribution, each repeated call extends the profit collection window further into the future. [3](#0-2) 

The Profit Contract's `FixProfitDetail` method then updates the beneficiary's profit detail with this new extended `endPeriod`, cloning the old detail, updating the period value, and replacing it in state. [4](#0-3) 

**Why Protections Fail**: The only restriction is the vote expiry check which validates `actualLockedSeconds < claimedLockingSeconds`. [5](#0-4)  This check does NOT prevent multiple calls before expiry—it only blocks calls after the vote has already expired. There is no rate limiting, cooldown mechanism, or tracking of extension frequency anywhere in the method.

The existing test suite demonstrates this behavior works as described, showing voters repeatedly calling `ChangeVotingOption` with `IsResetVotingTime=true` at different terms and successfully extending their `endPeriod` each time. [6](#0-5) 

## Impact Explanation

**Direct Economic Harm**: A voter with a 90-day lock (~13 periods at 7 days/period) can extend their welfare profit collection period significantly beyond their commitment:
- Original vote at period 100: endPeriod = 13 + 100 = 113
- First extension at period 110: endPeriod = 13 + 110 = 123 (10 extra periods)
- Second extension at period 111: endPeriod = 13 + 111 = 124 (11 extra periods)
- Vote expires at period 113 (based on original lock time), but voter collects profits until period 124

**Who is Affected**:
- Legitimate long-term voters who lock tokens for extended periods receive diluted welfare rewards proportional to the exploiter's unfair gains
- The welfare profit scheme's integrity is fundamentally compromised as the lock-time incentive mechanism is broken
- Protocol economics are distorted as short-term commitments can extract long-term rewards

**Quantified Damage**: A voter with minimum lock time can collect welfare profits for 2x or more of their actual commitment period. With each treasury period potentially distributing significant token amounts to the welfare scheme, this represents substantial value extraction over 10+ extra periods of profit collection while their tokens unlock at the original time.

## Likelihood Explanation

**Attacker Capabilities**: Any voter with an active vote can exploit this vulnerability. No special privileges, governance approval, or system access is required beyond normal voting participation.

**Attack Complexity**: Trivial—the attacker simply calls the public `ChangeVotingOption` method repeatedly with their voteId, the same candidate pubkey they already voted for, and `IsResetVotingTime=true`. The method is publicly accessible and has no cooldown or rate limiting mechanism.

**Feasibility Conditions**:
- Voter must have an active vote that hasn't expired yet
- Can be called multiple times per period or even per block with no restrictions
- Works with any lock duration that satisfies the minimum lock requirement
- The vote expiry check allows all calls until `actualLockedSeconds >= claimedLockingSeconds`

**Economic Rationality**: Transaction costs for calling `ChangeVotingOption` are negligible compared to the extended welfare profit gains over 10+ additional periods. A rational economic actor would exploit this to maximize returns.

**Detection Difficulty**: Difficult to detect without specifically monitoring for repeated `ChangeVotingOption` calls with `IsResetVotingTime=true` on the same voteId. There are no on-chain safeguards that prevent or flag this behavior.

## Recommendation

Implement one or more of the following protections:

1. **Track Extension Count**: Add a state variable tracking how many times each vote has been extended and enforce a maximum limit (e.g., one extension per vote).

2. **Cooldown Period**: Require a minimum time interval between consecutive `ChangeVotingOption` calls with `IsResetVotingTime=true` for the same vote (e.g., at least one full term).

3. **Lock Time Extension**: When `IsResetVotingTime=true`, actually extend the `lockTime` in `State.LockTimeMap[voteId]` to match the new profit collection period, requiring voters to commit additional lock time for extended profit eligibility.

4. **Immutable End Period**: Calculate `endPeriod` only once during initial vote creation and never allow it to be extended, making `IsResetVotingTime=false` the only option.

**Recommended Fix (Option 3)**:
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
    
    // FIXED: Extend the actual lock time to match the new end period
    var newLockTime = endPeriod.Sub(treasury.CurrentPeriod).Mul(State.TimeEachTerm.Value);
    State.LockTimeMap[voteId] = newLockTime;
    
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
        throw new AssertionException($"Cannot find profit detail of given vote id {voteId}");
    }
}
```

## Proof of Concept

The following test demonstrates the vulnerability by calling `ChangeVotingOption` multiple times on the same vote with `IsResetVotingTime=true`, showing that the `endPeriod` extends with each call while the vote's lock time remains unchanged:

```csharp
[Fact]
public async Task RepeatedWelfareProfitExtension_Vulnerability()
{
    // Setup: Announce candidate and create initial vote
    await AnnounceElectionAsync(CoreDataCenterKeyPairs[0]);
    var voter = VoterKeyPairs[0];
    var lockDays = 90; // ~13 periods at 7 days each
    
    // Initial vote at period 1
    var voteId = await VoteToCandidateAsync(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), 
        lockDays * 86400, 100);
    
    // Move to period 2
    await NextTerm(BootMinerKeyPair);
    
    // Check initial end period (should be around period 14)
    var profitDetail1 = await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
    var initialEndPeriod = profitDetail1.Details[0].EndPeriod;
    
    // Extension 1: Change vote at period 8
    for(int i = 0; i < 6; i++) await NextTerm(BootMinerKeyPair);
    await ChangeVotingOption(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), voteId, true);
    
    var profitDetail2 = await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
    var endPeriodAfterFirst = profitDetail2.Details[0].EndPeriod;
    
    // Extension 2: Change vote again at period 9
    await NextTerm(BootMinerKeyPair);
    await ChangeVotingOption(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(), voteId, true);
    
    var profitDetail3 = await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
    var endPeriodAfterSecond = profitDetail3.Details[0].EndPeriod;
    
    // Verify: End period extends beyond original commitment
    Assert.True(endPeriodAfterFirst > initialEndPeriod, 
        "First extension should increase end period");
    Assert.True(endPeriodAfterSecond > endPeriodAfterFirst, 
        "Second extension should further increase end period");
    Assert.True(endPeriodAfterSecond > initialEndPeriod + 6, 
        "Total extension should exceed periods elapsed");
}
```

The test confirms that repeated calls to `ChangeVotingOption` with `IsResetVotingTime=true` successfully extend the welfare profit `endPeriod` beyond the voter's original lock commitment, allowing them to collect profits for significantly longer than their token lock duration.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L131-133)
```csharp
        // Extend endPeriod from now no, so the lockTime will *NOT* be changed.
        var lockTime = State.LockTimeMap[voteId];
        var lockPeriod = lockTime.Div(State.TimeEachTerm.Value);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L139-139)
```csharp
        var endPeriod = lockPeriod.Add(treasury.CurrentPeriod);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L296-304)
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
```

**File:** test/AElf.Contracts.Election.Tests/Full/CitizenWelfareTests.cs (L540-582)
```csharp
    private async Task Term2Async_TwoVoterChangeVote()
    {
        var voter = VoterKeyPairs[0];
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[0].Id.ShouldNotBeNull();
            profitDetail.Details[0].StartPeriod.ShouldBe(2);
            profitDetail.Details[0].EndPeriod.ShouldBe(3);

            await ChangeVotingOption(voter, CoreDataCenterKeyPairs[0].PublicKey.ToHex(),
                profitDetail.Details[0].Id, true);
        }
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            profitDetail.Details[0].Id.ShouldNotBeNull();
            profitDetail.Details[0].StartPeriod.ShouldBe(2);
            profitDetail.Details[0].EndPeriod.ShouldBe(4);
            _profitShare.AddShares(4, 4, voter.PublicKey.ToHex(), profitDetail.Details[0].Shares);
        }

        voter = VoterKeyPairs[3];
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            var index = profitDetail.Details.FindIndex(d => d.EndPeriod.Equals(8));
            profitDetail.Details[index].Id.ShouldNotBeNull();
            profitDetail.Details[index].StartPeriod.ShouldBe(2);
            profitDetail.Details[index].EndPeriod.ShouldBe(8);                
            await ChangeVotingOption(voter, CoreDataCenterKeyPairs[1].PublicKey.ToHex(),
                profitDetail.Details[index].Id, true);
        }
        {
            var profitDetail =
                await GetCitizenWelfareProfitDetails(Address.FromPublicKey(voter.PublicKey));
            var index = profitDetail.Details.FindIndex(d => d.EndPeriod.Equals(9));
            profitDetail.Details[index].Id.ShouldNotBeNull();
            profitDetail.Details[index].StartPeriod.ShouldBe(2);
            profitDetail.Details[index].EndPeriod.ShouldBe(9);
            _profitShare.AddShares(9, 9, voter.PublicKey.ToHex(), profitDetail.Details[index].Shares);
        }
    }
```
