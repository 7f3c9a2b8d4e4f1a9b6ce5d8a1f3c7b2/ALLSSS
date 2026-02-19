### Title
Period Boundary Validation Bypass Causes Permanent Share Dilution in Profit Distribution

### Summary
The `AddBeneficiary` method in the Profit contract fails to validate that `EndPeriod >= StartPeriod`, allowing profit details to be created with inverted period boundaries. When schemes have a non-zero `DelayDistributePeriodCount`, beneficiaries can be added with `EndPeriod < (CurrentPeriod + DelayDistributePeriodCount)`, resulting in `StartPeriod > EndPeriod`. These malformed details have their shares added to `TotalShares` but are permanently filtered out during profit claims, causing all legitimate beneficiaries to receive diluted profits indefinitely.

### Finding Description

The root cause is in the `AddBeneficiary` method where period boundaries are set and validated: [1](#0-0) 

The `StartPeriod` is calculated as `scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount)` [2](#0-1) , while `EndPeriod` comes from user input. The only validation on `EndPeriod` is: [3](#0-2) 

**There is no validation that `EndPeriod >= StartPeriod`.**

When a beneficiary with `StartPeriod > EndPeriod` attempts to claim profits, the detail is filtered out in the `availableDetails` check: [4](#0-3) 

When `LastProfitPeriod == 0`, the condition `d.EndPeriod >= d.StartPeriod` fails, excluding the detail from `availableDetails`. These filtered-out details are removed from storage: [5](#0-4) 

However, share cleanup only occurs for details in `profitDetailsToRemove`, which come from `profitableDetails`, which are derived from `availableDetails`: [6](#0-5) 

Since the malformed detail never makes it into `availableDetails`, it's never in `profitDetailsToRemove`, and its shares remain in `TotalShares` permanently. The shares were added during `AddBeneficiary`: [7](#0-6) 

The `FixProfitDetail` method also lacks validation and can be used to create the same condition: [8](#0-7) 

### Impact Explanation

**Direct Fund Impact - Permanent Profit Dilution:**

When orphaned shares remain in `TotalShares`, all future profit distributions are calculated using the inflated denominator. For example:
- Scheme has legitimate beneficiary Alice with 1,000 shares
- Manager adds beneficiary Bob with 9,000 shares where `StartPeriod > EndPeriod`
- `TotalShares = 10,000` but only Alice can claim profits
- When 100,000 tokens are distributed, calculation uses: `Alice's share = (1,000 / 10,000) * 100,000 = 10,000`
- Alice receives only 10% instead of 100% of profits
- The remaining 90,000 tokens stay locked in the scheme's period virtual addresses indefinitely

**Affected Parties:**
- All legitimate beneficiaries of schemes with `DelayDistributePeriodCount > 0`
- Treasury and Welfare schemes in the Election contract use delayed distribution [9](#0-8) 
- The unclaimed portion remains permanently locked in period-specific virtual addresses

**Severity Justification:**
This is a **HIGH** severity issue because it causes permanent, irreversible dilution of profit distributions affecting core economic mechanisms (Treasury, citizen welfare). The impact compounds over time as more distributions occur with the inflated `TotalShares`.

### Likelihood Explanation

**Attack Vectors:**

1. **Unintentional Misconfiguration:** A scheme manager legitimately adding beneficiaries without realizing the `DelayDistributePeriodCount` constraint. For example, if a scheme has `CurrentPeriod = 100` and `DelayDistributePeriodCount = 50`, attempting to add a beneficiary with `EndPeriod = 120` results in `StartPeriod = 150 > EndPeriod = 120`.

2. **Deliberate Exploitation via AddBeneficiary:** A malicious manager can intentionally add beneficiaries with invalid periods to dilute other beneficiaries' shares.

3. **Deliberate Exploitation via FixProfitDetail:** A malicious manager can use `FixProfitDetail` to modify existing valid profit details to have `StartPeriod > EndPeriod` after they've been partially claimed (when `LastProfitPeriod > 0`), bypassing the initial `availableDetails` filter.

**Feasibility:**
- Entry point: `AddBeneficiary` and `FixProfitDetail` are public methods callable by scheme managers
- Preconditions: Scheme must have `DelayDistributePeriodCount > 0` (common in Treasury/Welfare schemes)
- Execution: Single transaction to add beneficiary or fix profit detail
- Detection: Difficult to detect without analyzing `ProfitDetailsMap` entries before claiming

**Probability:** High for schemes with delayed distribution, as managers may not understand the interaction between `DelayDistributePeriodCount` and `EndPeriod` constraints.

### Recommendation

**Immediate Fix:**

Add validation in `AddBeneficiary` to ensure period boundaries are valid:

```csharp
var startPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount);
Assert(input.EndPeriod >= startPeriod, 
    $"Invalid period range. EndPeriod ({input.EndPeriod}) must be >= StartPeriod ({startPeriod}).");
```

Insert this check at line 188 in `ProfitContract.cs` before creating the `ProfitDetail`.

Add similar validation in `FixProfitDetail`:

```csharp
var finalStartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
var finalEndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
Assert(finalEndPeriod >= finalStartPeriod,
    $"Invalid period range. EndPeriod ({finalEndPeriod}) must be >= StartPeriod ({finalStartPeriod}).");
```

**Additional Safeguards:**

1. Add a cleanup mechanism in `ClaimProfits` to remove orphaned shares for details filtered out of `availableDetails`:

```csharp
var invalidDetails = profitDetails.Details.Where(d => 
    d.LastProfitPeriod == 0 && d.EndPeriod < d.StartPeriod).ToList();
var invalidShares = invalidDetails.Sum(d => d.Shares);
scheme.TotalShares = scheme.TotalShares.Sub(invalidShares);
```

2. Add regression tests verifying that `StartPeriod > EndPeriod` scenarios are properly rejected or cleaned up.

### Proof of Concept

**Initial State:**
- Scheme created with `DelayDistributePeriodCount = 100`, `CurrentPeriod = 10`, `TotalShares = 0`
- Legitimate beneficiary Alice exists with 1,000 shares

**Exploitation Steps:**

1. **Manager calls AddBeneficiary:**
   - Input: `SchemeId = scheme_id`, `BeneficiaryShare = {Beneficiary: Bob, Shares: 9000}`, `EndPeriod = 50`
   - Validation passes: `50 >= 10` (CurrentPeriod check succeeds)
   - `StartPeriod` calculated: `10 + 100 = 110`
   - Result: `ProfitDetail {StartPeriod: 110, EndPeriod: 50, Shares: 9000, LastProfitPeriod: 0}`
   - `TotalShares` updated: `0 + 1000 + 9000 = 10,000`

2. **Profit Distribution occurs:**
   - `DistributeProfits` called with 100,000 tokens for period 10
   - Distribution uses `TotalShares = 10,000`

3. **Bob attempts ClaimProfits:**
   - `availableDetails` filter checks: `LastProfitPeriod == 0 ? EndPeriod >= StartPeriod : ...`
   - Evaluates: `50 >= 110 = false`
   - Bob's detail filtered out, removed from storage
   - **Bob's 9,000 shares remain in `TotalShares`**

4. **Alice calls ClaimProfits:**
   - Alice receives: `(1,000 / 10,000) * 100,000 = 10,000 tokens`
   - **Expected: 100,000 tokens (since only Alice is legitimate)**
   - **Actual: 10,000 tokens (90% dilution)**

5. **90,000 tokens remain locked** in the scheme's period-10 virtual address indefinitely.

**Success Condition:** 
- `TotalShares = 10,000` but only 1,000 shares are claimable
- 90% of distributed profits permanently locked
- All future distributions similarly diluted

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-215)
```csharp
    public override Empty AddBeneficiary(AddBeneficiaryInput input)
    {
        AssertValidInput(input);
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;

        var schemeId = input.SchemeId;
        var scheme = State.SchemeInfos[schemeId];

        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");

        Context.LogDebug(() =>
            $"{input.SchemeId}.\n End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        Assert(input.EndPeriod >= scheme.CurrentPeriod,
            $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);

        State.SchemeInfos[schemeId] = scheme;

        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };

        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);

        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);

        State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary] = currentProfitDetails;

        Context.LogDebug(() =>
            $"Added {input.BeneficiaryShare.Shares} weights to scheme {input.SchemeId.ToHex()}: {profitDetail}");

        return new Empty();
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-766)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-797)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L806-806)
```csharp
        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };
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
