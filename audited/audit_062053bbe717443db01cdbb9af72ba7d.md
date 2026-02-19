### Title
Share Accounting Divergence via FixProfitDetail and AddBeneficiary Cleanup

### Summary
The sum of shares in `ProfitDetailsMap[schemeId][*].Shares` can diverge from `SchemeInfos[schemeId].TotalShares` when `FixProfitDetail` creates a state where `LastProfitPeriod == EndPeriod`, followed by the cleanup logic in `AddBeneficiary` removing the detail without decrementing `TotalShares`. This causes permanent inflation of `TotalShares`, leading to diluted profit distributions for all beneficiaries.

### Finding Description

The vulnerability exists in the cleanup logic within `AddBeneficiary`: [1](#0-0) 

This code removes expired profit details from `ProfitDetailsMap` but does NOT subtract their shares from `TotalShares`. The cleanup triggers when:
1. `EndPeriod != long.MaxValue`
2. `LastProfitPeriod >= EndPeriod` (greater than or equal)
3. `EndPeriod + ProfitReceivingDuePeriodCount < CurrentPeriod`

In contrast, `ClaimProfits` properly decrements `TotalShares` when removing expired details: [2](#0-1) 

However, `ClaimProfits` only removes details where `LastProfitPeriod > EndPeriod` (strictly greater than), not when equal.

The `FixProfitDetail` method can modify `EndPeriod` without touching `TotalShares` or `IsWeightRemoved`: [3](#0-2) 

This creates an edge case: when `FixProfitDetail` shortens `EndPeriod` to equal `LastProfitPeriod`, the detail will:
- NOT be removed by `ClaimProfits` (requires `>`, not `>=`)
- BE removed by `AddBeneficiary` cleanup (checks `>=`)
- Have shares remain in `TotalShares` (never decremented)

The cleanup logic also fails to check the `IsWeightRemoved` flag, which is used elsewhere to prevent double-counting of removed shares.

### Impact Explanation

**Direct Fund Impact - Profit Misallocation**: When `TotalShares` is inflated while the actual sum of shares in `ProfitDetailsMap` is correct, all future profit distributions are calculated incorrectly. The profit calculation uses `TotalShares` as the denominator: [4](#0-3) 

If `TotalShares` is inflated by X shares while the actual active shares total Y, each beneficiary receives `(Amount * BeneficiaryShares) / (Y + X)` instead of `(Amount * BeneficiaryShares) / Y`. The lost profits remain locked in the period's virtual address indefinitely.

**Concrete Example**: If Alice had 100 shares that were removed from `ProfitDetailsMap` but not from `TotalShares` (which remains at 100), and Bob is the only real beneficiary with 50 shares:
- Intended distribution: Bob gets 100% of profits
- Actual distribution: Bob gets `50 / (100 + 50) = 33.3%` of profits
- 66.7% of profits are permanently locked

**Affected Parties**: All beneficiaries of the scheme suffer diluted profit distributions permanently until a scheme reset or manual intervention.

### Likelihood Explanation

**Attack Complexity - Low to Medium**: The vulnerability can be triggered through normal operations:

1. **Reachable Entry Point**: `FixProfitDetail` is callable by scheme manager or TokenHolder contract: [5](#0-4) 

2. **Production Usage**: `FixProfitDetail` is actively used in the Election contract for extending voter welfare profits: [6](#0-5) 

3. **Realistic Scenario**:
   - Voter has welfare profits with some `EndPeriod`
   - Voter claims profits up to period N (sets `LastProfitPeriod = N`)
   - Election contract calls `FixProfitDetail` to adjust `EndPeriod` to period M where M ≤ N (shorter lock period)
   - 10 periods pass (default `ProfitReceivingDuePeriodCount`): [7](#0-6) 
   - Any `AddBeneficiary` call triggers cleanup, removing the detail without updating `TotalShares`

4. **No Special Privileges Required**: While `FixProfitDetail` requires manager/TokenHolder authorization, it's designed for normal operations and the cleanup is triggered by any subsequent `AddBeneficiary` call.

5. **Detection Difficulty**: The divergence is not immediately visible and only manifests as unexpectedly low profit distributions over time.

### Recommendation

**Fix the cleanup logic in `AddBeneficiary`** to properly handle share removal:

1. Before removing old details, check if `IsWeightRemoved` is already true
2. If false, subtract the shares from `TotalShares` and set `IsWeightRemoved = true`
3. Ensure consistency with the removal logic in `ClaimProfits` and `RemoveBeneficiary`

Suggested code modification at lines 203-207:
```csharp
// Remove details too old and update TotalShares
var oldProfitDetails = currentProfitDetails.Details.Where(
    d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
         d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
         
foreach (var detail in oldProfitDetails) 
{
    if (!detail.IsWeightRemoved)
    {
        scheme.TotalShares = scheme.TotalShares.Sub(detail.Shares);
        detail.IsWeightRemoved = true;
    }
    currentProfitDetails.Details.Remove(detail);
}
State.SchemeInfos[schemeId] = scheme;  // Save updated TotalShares
```

**Add invariant check**: Include a verification mechanism to detect divergence:
```csharp
// After any operation modifying ProfitDetailsMap or TotalShares
var actualSum = ProfitDetailsMap[schemeId].Values
    .SelectMany(pd => pd.Details)
    .Where(d => !d.IsWeightRemoved)
    .Sum(d => d.Shares);
Assert(actualSum == scheme.TotalShares, "Share sum mismatch detected");
```

**Test cases**: Add regression tests covering:
1. `FixProfitDetail` reducing `EndPeriod` to equal `LastProfitPeriod`
2. Subsequent `AddBeneficiary` call after `ProfitReceivingDuePeriodCount` periods
3. Verification that `TotalShares` matches sum of active shares

### Proof of Concept

**Initial State**:
- Scheme created with `ProfitReceivingDuePeriodCount = 10`
- Period 1: Alice added as beneficiary with 100 shares, `EndPeriod = 100`
- `TotalShares = 100`
- `ProfitDetailsMap[Alice] = [{ Shares: 100, EndPeriod: 100, LastProfitPeriod: 0 }]`

**Exploitation Steps**:

1. **Period 50**: Alice claims all available profits
   - After claiming: `LastProfitPeriod = 50`

2. **Period 50**: Manager calls `FixProfitDetail` to adjust Alice's `EndPeriod` to 50
   - `ProfitDetailsMap[Alice] = [{ Shares: 100, EndPeriod: 50, LastProfitPeriod: 50 }]`
   - `TotalShares = 100` (unchanged)
   - Note: `LastProfitPeriod == EndPeriod == 50`

3. **Period 51**: If Alice attempts to claim:
   - `ClaimProfits` condition: `LastProfitPeriod > EndPeriod` → `50 > 50` → FALSE
   - Detail NOT removed, shares NOT subtracted from `TotalShares`

4. **Period 61**: Bob is added as beneficiary (or any `AddBeneficiary` call)
   - Cleanup condition check for Alice's detail:
     - `EndPeriod != long.MaxValue` → `50 != MaxValue` → TRUE
     - `LastProfitPeriod >= EndPeriod` → `50 >= 50` → TRUE  
     - `EndPeriod + 10 < 61` → `60 < 61` → TRUE
   - Alice's detail REMOVED from `ProfitDetailsMap`
   - `TotalShares` NOT decremented → remains 100
   - Bob's 50 shares added: `TotalShares = 150`

**Expected Result**:
- `TotalShares = 50` (only Bob's shares)
- Sum of shares in `ProfitDetailsMap = 50`

**Actual Result**:
- `TotalShares = 150` (includes Alice's ghost shares)
- Sum of shares in `ProfitDetailsMap = 50`
- **DIVERGENCE: 150 ≠ 50**

**Impact Verification**: In next profit distribution of 1000 tokens:
- Bob should receive: `1000 * 50 / 50 = 1000` tokens
- Bob actually receives: `1000 * 50 / 150 = 333` tokens
- 667 tokens permanently locked in period virtual address

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L203-207)
```csharp
        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L269-272)
```csharp
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-792)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
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

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L6-6)
```csharp
    public const int DefaultProfitReceivingDuePeriodCount = 10;
```
