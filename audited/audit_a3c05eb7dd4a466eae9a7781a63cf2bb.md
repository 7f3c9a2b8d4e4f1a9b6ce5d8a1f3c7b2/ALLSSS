# Audit Report

## Title
Share Accounting Divergence via FixProfitDetail and AddBeneficiary Cleanup

## Summary
A critical accounting vulnerability in the Profit Contract allows `TotalShares` to become permanently inflated when `FixProfitDetail` sets `EndPeriod` to be less than or equal to `LastProfitPeriod`, followed by automatic cleanup in `AddBeneficiary` that removes the detail from `ProfitDetailsMap` without decrementing `TotalShares`. This causes all future profit distributions to be calculated with an inflated denominator, permanently diluting profits for all legitimate beneficiaries.

## Finding Description

The vulnerability exists due to an inconsistency between two cleanup mechanisms in the Profit Contract:

**Mechanism 1: AddBeneficiary Cleanup (Missing TotalShares Decrement)**

The cleanup logic in `AddBeneficiary` removes expired profit details but does NOT decrement `TotalShares`: [1](#0-0) 

This cleanup triggers when all three conditions are met:
1. `EndPeriod != long.MaxValue`
2. `LastProfitPeriod >= EndPeriod` (greater than or equal)
3. `EndPeriod + ProfitReceivingDuePeriodCount < CurrentPeriod`

**Mechanism 2: ClaimProfits Cleanup (Proper TotalShares Decrement)**

In contrast, `ClaimProfits` properly decrements `TotalShares` when removing expired details: [2](#0-1) 

However, it only removes details where `LastProfitPeriod > EndPeriod` (strictly greater than, not equal).

**The Problematic Entry Point: FixProfitDetail**

The `FixProfitDetail` method allows modifying `EndPeriod` without any validation or `TotalShares` adjustment: [3](#0-2) 

This method has authorization checks but no validation preventing `EndPeriod` from being set to values less than or equal to `LastProfitPeriod`: [4](#0-3) 

**The Edge Case Exploit Path:**

1. A beneficiary has a profit detail with `LastProfitPeriod = 10`, `EndPeriod = 20`, `Shares = 100`
2. Scheme manager or TokenHolder contract calls `FixProfitDetail` to set `EndPeriod = 5` (less than `LastProfitPeriod`)
3. Now the detail has `LastProfitPeriod = 10`, `EndPeriod = 5`
4. The detail becomes **unclaimable** because `ClaimProfits` checks `EndPeriod >= LastProfitPeriod` to determine availability: [5](#0-4) 

5. Since `5 >= 10` is FALSE, the detail is never added to `availableDetails` and cannot be claimed
6. After the due period expires (`ProfitReceivingDuePeriodCount` periods, default 10): [6](#0-5) 

7. Any subsequent `AddBeneficiary` call triggers the cleanup, which removes the detail from `ProfitDetailsMap` because `LastProfitPeriod (10) >= EndPeriod (5)` is TRUE and the time condition is met
8. The detail's shares (100) remain in `TotalShares`, causing permanent inflation

**Additional Issue: Missing IsWeightRemoved Check**

The `AddBeneficiary` cleanup also fails to check the `IsWeightRemoved` flag, which is used elsewhere to prevent double-counting: [7](#0-6) 

## Impact Explanation

**Direct Fund Impact - Permanent Profit Dilution:**

When `TotalShares` is inflated while the actual sum of shares in `ProfitDetailsMap` is correct, all future profit distributions are calculated incorrectly. The profit calculation uses the stored `TotalShares` as the denominator: [8](#0-7) 

This `TotalShares` value comes from the scheme during distribution: [9](#0-8) 

And is recorded in the distributed profits information: [10](#0-9) 

**Concrete Example:**
- Alice had 100 shares that were removed from `ProfitDetailsMap` but not from `TotalShares`
- Bob is the only real beneficiary with 50 shares  
- `TotalShares` incorrectly remains at 150 (100 + 50)
- When 150 tokens are distributed:
  - **Intended**: Bob should receive 100% = 150 tokens
  - **Actual**: Bob receives `(150 * 50) / 150 = 50` tokens
  - **Lost**: 100 tokens (66.7%) remain permanently locked in the period's virtual address

**Affected Parties:**
All current and future beneficiaries of any affected profit scheme suffer permanent profit dilution proportional to the inflation ratio. The unclaimed profits cannot be recovered as they are locked in past period virtual addresses.

## Likelihood Explanation

**Medium Likelihood - Normal Operations Path:**

1. **Authorized Entry Point**: `FixProfitDetail` is callable by scheme manager or TokenHolder contract (trusted roles for normal operations): [4](#0-3) 

2. **Production Usage**: The method is actively used in the Election contract for voter welfare profit adjustments: [11](#0-10) 

3. **Realistic Triggering Scenarios:**
   - Vote lock period adjustments that result in shorter effective periods
   - Administrative corrections to profit periods
   - Edge cases in election mechanics where calculated `EndPeriod` becomes less than current `LastProfitPeriod`

4. **Automatic Cleanup**: The vulnerability doesn't require attacker action beyond the initial `FixProfitDetail` call - the cleanup happens automatically when any user calls `AddBeneficiary` after the due period expires

5. **No Input Validation**: There are no checks preventing `EndPeriod` from being set to invalid values relative to `LastProfitPeriod`: [3](#0-2) 

6. **Detection Difficulty**: The divergence is not immediately visible and only manifests as unexpectedly reduced profit distributions over multiple periods

## Recommendation

**Fix 1: Add validation in FixProfitDetail**
```csharp
public override Empty FixProfitDetail(FixProfitDetailInput input)
{
    // ... existing authorization checks ...
    
    var profitDetails = State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary];
    ProfitDetail fixingDetail = /* ... existing logic to find detail ... */;
    
    var newDetail = fixingDetail.Clone();
    newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
    newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
    
    // ADD VALIDATION: Prevent EndPeriod from being less than LastProfitPeriod
    Assert(newDetail.EndPeriod >= fixingDetail.LastProfitPeriod, 
        "EndPeriod cannot be less than LastProfitPeriod");
    
    profitDetails.Details.Remove(fixingDetail);
    profitDetails.Details.Add(newDetail);
    State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary] = profitDetails;
    return new Empty();
}
```

**Fix 2: Add TotalShares decrement in AddBeneficiary cleanup**
```csharp
// In AddBeneficiary, after line 204:
var oldProfitDetails = currentProfitDetails.Details.Where(
    d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
         d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod && 
         !d.IsWeightRemoved).ToList(); // Add IsWeightRemoved check

var sharesToRemove = oldProfitDetails.Sum(d => d.Shares);
if (sharesToRemove > 0)
{
    scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
    State.SchemeInfos[schemeId] = scheme;
}

foreach (var detail in oldProfitDetails) 
{
    detail.IsWeightRemoved = true; // Mark as removed
    currentProfitDetails.Details.Remove(detail);
}
```

**Fix 3: Add IsWeightRemoved check in cleanup condition**
Ensure the cleanup only processes details that haven't already had their shares removed from TotalShares.

## Proof of Concept

```csharp
// Test demonstrating the TotalShares divergence
[Fact]
public async Task ProfitContract_FixProfitDetail_TotalShares_Divergence_Test()
{
    // Setup: Create scheme and add beneficiary with 100 shares
    var schemeId = await CreateScheme();
    var beneficiary = Accounts[0].Address;
    var shares = 100L;
    
    // Add beneficiary with EndPeriod = 20
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = beneficiary, Shares = shares },
        EndPeriod = 20
    });
    
    // Verify initial TotalShares = 100
    var schemeInfo = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    schemeInfo.TotalShares.ShouldBe(100);
    
    // Claim profits up to period 10 (sets LastProfitPeriod = 11)
    await AdvanceToPeriod(10);
    await ProfitContractStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiary
    });
    
    // Call FixProfitDetail to set EndPeriod = 5 (< LastProfitPeriod)
    await ProfitContractStub.FixProfitDetail.SendAsync(new FixProfitDetailInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = beneficiary, Shares = shares },
        EndPeriod = 5
    });
    
    // Advance 15 periods so cleanup condition is met
    await AdvanceToPeriod(25);
    
    // Trigger cleanup by adding a new beneficiary
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = Accounts[1].Address, Shares = 50 },
        EndPeriod = long.MaxValue
    });
    
    // Verify vulnerability: TotalShares should be 50, but is actually 150 (100 + 50)
    schemeInfo = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    schemeInfo.TotalShares.ShouldBe(150); // BUG: Should be 50
    
    // Verify detail was removed from ProfitDetailsMap
    var details = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiary
    });
    details.Details.Count.ShouldBe(0); // Detail removed
    
    // Result: TotalShares inflated, causing all future distributions to be diluted
}
```

## Notes

This vulnerability affects the core invariant that `TotalShares` must equal the sum of all active shares in `ProfitDetailsMap`. The lack of validation in `FixProfitDetail` combined with the missing `TotalShares` decrement in `AddBeneficiary` cleanup creates a permanent accounting divergence that cannot be resolved without manual intervention or scheme reset.

The issue is particularly concerning because:
1. It can occur through normal administrative operations, not just malicious actions
2. The Election contract's usage of `FixProfitDetail` creates realistic triggering scenarios
3. The impact scales with the number of affected beneficiaries and profit distributions
4. Detection requires careful monitoring of the `TotalShares` invariant across all schemes

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L204-207)
```csharp
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L268-273)
```csharp
        var scheme = State.SchemeInfos[input.SchemeId];
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L296-305)
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
        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L322-324)
```csharp
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L462-476)
```csharp
        var totalShares = scheme.TotalShares;

        if (scheme.DelayDistributePeriodCount > 0)
        {
            scheme.CachedDelayTotalShares.Add(input.Period.Add(scheme.DelayDistributePeriodCount), totalShares);
            if (scheme.CachedDelayTotalShares.ContainsKey(input.Period))
            {
                totalShares = scheme.CachedDelayTotalShares[input.Period];
                scheme.CachedDelayTotalShares.Remove(input.Period);
            }
            else
            {
                totalShares = 0;
            }
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L567-567)
```csharp
        distributedProfitsInformation.TotalShares = totalShares;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-767)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-792)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L873-874)
```csharp
                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L6-6)
```csharp
    public const int DefaultProfitReceivingDuePeriodCount = 10;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L144-154)
```csharp
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
```
