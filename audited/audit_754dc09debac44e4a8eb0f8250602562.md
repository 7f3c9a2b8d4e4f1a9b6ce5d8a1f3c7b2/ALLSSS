### Title
Expired ProfitDetails Accumulate Indefinitely for Non-Claiming Beneficiaries Due to Ineffective Cleanup Logic

### Summary
The `AddBeneficiary` cleanup mechanism in the Profit contract only removes old `ProfitDetails` entries if beneficiaries have already claimed their profits (`LastProfitPeriod >= EndPeriod`). Beneficiaries who never claim their profits—such as inactive voters in the Election contract's welfare scheme—will have their expired `ProfitDetails` persist indefinitely in `ProfitDetailsMap`, causing unbounded storage growth despite the `ProfitReceivingDuePeriodCount` grace period.

### Finding Description

The Profit contract maintains `ProfitDetailsMap[schemeId][beneficiary]` to track beneficiary shares and profit claiming status. [1](#0-0) 

There are three cleanup mechanisms for old `ProfitDetails`:

**1. AddBeneficiary Cleanup (Ineffective for Non-Claimers):**
The cleanup logic removes details only when ALL three conditions are met:
- `EndPeriod != long.MaxValue` (not permanent)
- `LastProfitPeriod >= EndPeriod` (already claimed everything) ← **FAILS for non-claimers**
- `EndPeriod + ProfitReceivingDuePeriodCount < CurrentPeriod` (grace period expired) [2](#0-1) 

**2. ClaimProfits Cleanup (Never Executes for Non-Claimers):**
This removes details where `LastProfitPeriod > EndPeriod` after claiming, but only fires if beneficiaries actually call `ClaimProfits`. [3](#0-2) 

**3. RemoveBeneficiary (Manual Only):**
Requires explicit action by scheme manager or TokenHolder contract. [4](#0-3) 

**Root Cause:**
For beneficiaries who never claim profits, `LastProfitPeriod` remains at 0 or `StartPeriod`, which is always less than `EndPeriod`. The condition `LastProfitPeriod >= EndPeriod` in the AddBeneficiary cleanup never becomes true, making the `ProfitReceivingDuePeriodCount` grace period ineffective.

**Real-World Scenario:**
In the Election contract, when users vote, they are added as beneficiaries to the welfare profit scheme with a calculated `EndPeriod` based on lock time: [5](#0-4) 

If voters become inactive and never:
- Withdraw their vote (which would call `RemoveBeneficiaryOfVoter` at line 667), OR
- Claim welfare profits

Their `ProfitDetails` persist forever in storage, even after `EndPeriod + ProfitReceivingDuePeriodCount < CurrentPeriod`.

### Impact Explanation

**Storage Bloat:**
Over multiple election periods with thousands of voters, inactive voters accumulate in `ProfitDetailsMap[WelfareHash][VoterAddress]`. Each `ProfitDetail` entry consumes storage for:
- Shares (int64)
- StartPeriod, EndPeriod, LastProfitPeriod (int64 each)
- Id (Hash)
- IsWeightRemoved (bool)

**Quantified Impact:**
- With 10,000 inactive voters per year and 5-year operation = 50,000 stale entries
- Conservative estimate: ~100 bytes per ProfitDetail = 5MB of unnecessary state growth
- Larger deployments with more active voting could see 10x-100x this amount

**Affected Parties:**
- Node operators: Increased state storage costs
- Network: Slower state synchronization for new nodes
- Contract performance: Larger state reads when enumerating beneficiaries

**Severity Justification:**
Medium severity because:
- Impact is gradual, not immediate
- Does not directly affect funds or protocol security
- Eventually causes operational degradation
- No easy mitigation for already-accumulated entries without manual intervention

### Likelihood Explanation

**High Likelihood in Normal Operation:**

This vulnerability manifests through normal user behavior, not malicious activity:

1. **Common Pattern:** Users vote in elections, receive profit shares, then become inactive (change wallets, lose keys, lose interest)
2. **No Incentive to Clean Up:** Inactive users have no reason to call `Withdraw` or `ClaimProfits`
3. **Continuous Accumulation:** Each election period adds new beneficiaries, some percentage become inactive
4. **No Automatic Cleanup:** The grace period cleanup requires prior claiming activity

**Feasibility:**
- No attack required—this is emergent behavior
- Already happening in any deployment with inactive voters
- Accumulation rate proportional to voter participation and churn rate
- Cannot be prevented without contract upgrades

**Detection:**
Storage bloat manifests gradually and may go unnoticed until significant accumulation occurs.

### Recommendation

**Immediate Fix:**
Modify the cleanup logic in `AddBeneficiary` to remove expired details regardless of claiming status:

```csharp
// Remove details too old - FIXED VERSION
var oldProfitDetails = currentProfitDetails.Details.Where(
    d => d.EndPeriod != long.MaxValue && 
         d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
```

Remove the `d.LastProfitPeriod >= d.EndPeriod` condition from line 205. [6](#0-5) 

**Additional Safeguards:**
1. Add a periodic maintenance function callable by scheme managers to batch-remove expired details
2. Emit events when details are cleaned up for monitoring
3. Add governance-controlled parameter to limit maximum detail retention beyond EndPeriod

**Test Cases:**
1. Add beneficiary with EndPeriod = 100
2. Advance to period 100 + ProfitReceivingDuePeriodCount + 1
3. Add another beneficiary for same address (triggers cleanup)
4. Verify old detail removed WITHOUT requiring prior ClaimProfits call

### Proof of Concept

**Initial State:**
- Scheme created with `ProfitReceivingDuePeriodCount = 10` (default)
- CurrentPeriod = 1

**Step 1 - Voter Participates:**
```
VoterA calls Vote(amount=1000, lockSeconds=90days)
→ AddBeneficiaryToVoter called
→ EndPeriod = GetEndPeriod(90days) = ~90
→ ProfitDetails[WelfareHash][VoterA] = {StartPeriod=1, EndPeriod=90, Shares=X, LastProfitPeriod=0}
```

**Step 2 - Time Passes (No Claiming):**
```
DistributeProfits called for periods 2..110
→ CurrentPeriod advances to 111
→ VoterA never calls ClaimProfits
→ LastProfitPeriod remains 0
```

**Step 3 - Grace Period Expires:**
```
CurrentPeriod = 111 > EndPeriod(90) + ProfitReceivingDuePeriodCount(10) = 100
→ Detail should be cleaned up per design intent
```

**Step 4 - Verify No Cleanup:**
```
GetProfitDetails(WelfareHash, VoterA)
→ Returns ProfitDetails with Details.Count = 1 (should be 0)
→ Detail persists because LastProfitPeriod(0) < EndPeriod(90)
```

**Expected vs Actual:**
- **Expected:** Detail removed when CurrentPeriod > EndPeriod + ProfitReceivingDuePeriodCount
- **Actual:** Detail persists indefinitely if beneficiary never claimed

**Success Condition for Exploit:**
Storage bloat confirmed by querying `GetProfitDetails` for inactive voters after grace period expiration and observing non-zero `Details.Count`.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L13-13)
```csharp
    public MappedState<Hash, Address, ProfitDetails> ProfitDetailsMap { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L203-207)
```csharp
        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-263)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();

        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");

        var removedDetails = RemoveProfitDetails(scheme, input.Beneficiary, input.ProfitDetailId);

        foreach (var (removedMinPeriod, removedShares) in removedDetails.Where(d => d.Key != 0))
        {
            if (scheme.DelayDistributePeriodCount > 0)
            {
                for (var removedPeriod = removedMinPeriod;
                     removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
                     removedPeriod++)
                {
                    if (scheme.CachedDelayTotalShares.ContainsKey(removedPeriod))
                    {
                        scheme.CachedDelayTotalShares[removedPeriod] =
                            scheme.CachedDelayTotalShares[removedPeriod].Sub(removedShares);
                    }
                }
            }
        }

        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());

        return new Empty();
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
