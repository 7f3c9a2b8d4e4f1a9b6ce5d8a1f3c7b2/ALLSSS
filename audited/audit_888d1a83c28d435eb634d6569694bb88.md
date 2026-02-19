### Title
Unbounded Profit Detail Accumulation Causes Gas Griefing and Operational DoS

### Summary
The `ClaimProfits` function limits processing to 10 profit details per transaction, but there is no upper bound on how many details can be accumulated for a single beneficiary. This forces users with many details (whether from malicious manager actions or legitimate repeated voting) to make numerous transactions to claim all profits, resulting in excessive gas costs and poor user experience.

### Finding Description

The vulnerability exists in the profit claiming mechanism: [1](#0-0) 

This constant is defined as 10: [2](#0-1) 

The root cause is that `AddBeneficiary` can be called multiple times for the same beneficiary, with each call adding a new `ProfitDetail` to the list without any limit: [3](#0-2) 

Authorization check shows only the scheme manager or TokenHolder contract can add beneficiaries: [4](#0-3) 

**Two Attack Paths:**

**Path 1 - Malicious Manager**: A malicious scheme manager repeatedly calls `AddBeneficiary` with small shares for a victim address, creating thousands of details.

**Path 2 - Normal Usage (Election)**: The Election contract creates one profit detail per vote. Each vote calls: [5](#0-4) 

Which invokes: [6](#0-5) 

An active voter making 1,000 small votes will accumulate 1,000 profit details. Test evidence confirms multiple details per beneficiary: [7](#0-6) 

When claiming, only 10 details are processed per transaction: [8](#0-7) 

The cleanup logic only removes details after they're fully claimed, not preventing new accumulation: [9](#0-8) 

### Impact Explanation

**Gas Griefing**: A user with 1,000 profit details must call `ClaimProfits` 100 times (1,000 ÷ 10), paying transaction fees for each call. If transaction costs are 0.01 ELF, the victim wastes 1 ELF just to claim their profits.

**Operational DoS**: Making 100 separate transactions creates severe UX friction. If there are per-block transaction limits or if profits expire after a certain period, users may be unable to claim all their profits before expiration.

**Real-World Scenario**: Active participants in the Election system who frequently vote (a legitimate and encouraged behavior) will naturally accumulate hundreds or thousands of profit details over time, making profit claiming extremely burdensome.

**Affected Users**: 
- Active voters in the Election system (normal usage)
- Beneficiaries in schemes where managers become malicious or compromised
- Any beneficiary added multiple times to a profit scheme

**Severity**: Medium - While funds aren't directly stolen, operational disruption and gas waste are significant, especially for active ecosystem participants.

### Likelihood Explanation

**Attacker Capabilities**: 
- Malicious scenario: Requires being a scheme manager or compromising a manager account
- Normal scenario: No attacker needed - occurs naturally through legitimate Election participation

**Attack Complexity**: Low - Simply call `AddBeneficiary` multiple times or accumulate votes over time.

**Feasibility Conditions**:
- Malicious: Attacker controls or compromises a scheme manager role
- Normal: User participates actively in voting (encouraged behavior)

**Detection/Constraints**: 
- The issue is detectable but by design there's no prevention mechanism
- While Election/Consensus scheme managers are trusted system contracts (reducing malicious risk), the normal usage path still creates the problem
- No limit enforced on details per beneficiary

**Probability**: MEDIUM to HIGH
- Normal usage in Election creates this scenario naturally for active voters
- Malicious exploitation requires manager role but is straightforward once obtained
- The issue compounds over time as details accumulate

### Recommendation

**Immediate Mitigation**:
Add a maximum profit details limit per beneficiary in `AddBeneficiary`:

```solidity
Assert(currentProfitDetails.Details.Count < MAX_DETAILS_PER_BENEFICIARY, 
    "Too many profit details for beneficiary.");
```

**Better Solution - Detail Consolidation**:
Modify `AddBeneficiary` to consolidate existing details with overlapping periods instead of always creating new ones. When adding a beneficiary that already exists:
1. Check for details with overlapping periods
2. Merge shares for overlapping periods
3. Only create new detail if periods don't overlap

**TokenHolder Pattern Extension**:
The TokenHolder contract already consolidates details (removes and re-adds with combined shares). Apply similar logic in the base Profit contract: [10](#0-9) 

**Add Batch Claim**:
Implement `ClaimProfitsAll` that processes all details across multiple internal iterations (with gas checks) in a single user transaction.

**Test Cases**:
- Test that a beneficiary cannot exceed maximum detail count
- Test that consolidation properly merges overlapping period details
- Test that active voters in Election don't accumulate excessive details
- Test batch claiming with 100+ details completes successfully

### Proof of Concept

**Initial State**:
- Attacker is manager of scheme S
- Victim V has address 0xVICTIM

**Attack Sequence**:

**Malicious Scenario**:
```
1. For i = 1 to 1000:
   - Attacker calls AddBeneficiary(schemeId=S, beneficiary=0xVICTIM, shares=1)
   - Each call creates a new ProfitDetail entry
2. Scheme distributes profits
3. Victim calls ClaimProfits(schemeId=S)
   - Only 10 details processed
   - Victim receives 1/100th of total claimable profits
4. Victim must repeat step 3 another 99 times to claim all profits
   - Total: 100 transactions and 100x transaction fees
```

**Normal Usage Scenario (Election)**:
```
1. User U makes 1000 small votes over 1 year:
   - Vote(candidate1, amount=10, lockTime=90days) - creates detail 1
   - Vote(candidate2, amount=15, lockTime=60days) - creates detail 2
   - ... (998 more votes)
   - Vote(candidateN, amount=20, lockTime=120days) - creates detail 1000
2. User U calls ClaimProfits(WelfareScheme)
   - Only 10 oldest details processed
3. User must call ClaimProfits 100 times total
   - Poor UX, excessive gas costs
```

**Expected vs Actual**:
- Expected: Users can claim all profits in 1-2 transactions regardless of detail count
- Actual: Users need N/10 transactions where N is detail count, unbounded above

**Success Condition**: 
Victim forced to make 100 transactions where 1 should suffice, wasting 99x transaction fees and experiencing severe operational friction.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L194-201)
```csharp
        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L772-773)
```csharp
        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L777-785)
```csharp
        for (var i = 0; i < profitableDetailCount; i++)
        {
            var profitDetail = profitableDetails[i];
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
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

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L5-5)
```csharp
    public const int ProfitReceivingLimitForEachTime = 10;
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

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L1084-1084)
```csharp
        originProfitDetail.Details.Count.ShouldBe(2);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L46-56)
```csharp
        if (detail.Details.Any())
        {
            // Only keep one detail.

            State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                Beneficiary = input.Beneficiary
            });
            shares.Add(detail.Details.Single().Shares);
        }
```
