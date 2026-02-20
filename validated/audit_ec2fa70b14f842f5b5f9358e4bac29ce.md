# Audit Report

## Title
Beneficiaries with EndPeriod=long.MaxValue Cannot Be Removed from Schemes with CanRemoveBeneficiaryDirectly=false

## Summary
The Profit contract contains a critical logic flaw where beneficiaries added with default `EndPeriod` (automatically set to `long.MaxValue`) cannot be effectively removed from schemes that have `CanRemoveBeneficiaryDirectly = false` (the default setting). When a manager calls `RemoveBeneficiary` without providing a `profitDetailId`, the removal silently fails, allowing the "removed" beneficiary to continue claiming profits indefinitely and permanently diluting legitimate beneficiaries' shares.

## Finding Description

The vulnerability originates from the interaction between the `AddBeneficiary` default behavior and the `RemoveProfitDetails` filter logic.

When a beneficiary is added without specifying `EndPeriod`, it defaults to `long.MaxValue`: [1](#0-0) 

When a scheme is created without explicitly setting `CanRemoveBeneficiaryDirectly`, it defaults to `false` as per proto3 boolean default semantics: [2](#0-1) 

The critical flaw exists in the `RemoveProfitDetails` helper method, which filters which details can be removed: [3](#0-2) 

When `CanRemoveBeneficiaryDirectly = false`, only details where `d.EndPeriod < scheme.CurrentPeriod` are eligible for removal. Since `long.MaxValue` is always greater than or equal to any `CurrentPeriod`, beneficiaries with `EndPeriod = long.MaxValue` are NEVER included in `detailsCanBeRemoved`.

This causes cascading failures in the removal process where the `IsWeightRemoved` flag is not set and shares are not added to `removedDetails`: [4](#0-3) 

Consequently, when `RemoveBeneficiary` completes, the `TotalShares` reduction is based on the empty `removedDetails`: [5](#0-4) 

Since `removedDetails.Values.Sum()` returns 0, nothing is subtracted from `TotalShares`, and the beneficiary remains fully active in the scheme.

The "removed" beneficiary can continue claiming profits because the claim logic only checks if `EndPeriod >= LastProfitPeriod`: [6](#0-5) 

With `EndPeriod = long.MaxValue`, this condition is always satisfied.

A workaround exists where managers can provide a `profitDetailId` to bypass the filter: [7](#0-6) 

However, this workaround is non-obvious, undocumented, and requires knowledge of internal profit detail IDs.

## Impact Explanation

This vulnerability has **CRITICAL** impact on profit distribution integrity:

1. **Unauthorized Continuous Profit Drainage:** After the manager's attempted removal, the beneficiary continues claiming their proportional share of all future profit distributions indefinitely. For example, if a beneficiary has 100 shares out of 1000 total, they will continue receiving 10% of all future distributions forever.

2. **Permanent Share Dilution:** The "removed" beneficiary's shares remain in the scheme's `TotalShares`, permanently diluting the profit share of all legitimate beneficiaries. This directly reduces the amount received by intended beneficiaries.

3. **Manager Authorization Bypass:** The scheme manager's explicit intent to remove a beneficiary is silently ignored by the contract, violating the core authorization model where only managers control beneficiary membership.

4. **Undetected Exploitation:** Since `RemoveBeneficiary` returns successfully without throwing an error, managers have no indication that the removal failed. This makes the issue extremely difficult to detect without manually querying contract state.

**Who is affected:** All schemes created with default settings (`CanRemoveBeneficiaryDirectly = false`) where beneficiaries are added without explicitly specifying `EndPeriod`. This includes potential third-party dApp profit schemes and any future system contract upgrades using the Profit contract.

## Likelihood Explanation

The likelihood of this vulnerability being triggered is **MEDIUM-HIGH**:

**Reachable Entry Point:** The vulnerability is triggered through normal manager operations:
1. Creating a scheme with default settings (common)
2. Adding beneficiaries without specifying `EndPeriod` (common pattern)
3. Later attempting to remove the beneficiary (legitimate management action)

**Feasible Preconditions:**
- Default scheme configuration (`CanRemoveBeneficiaryDirectly = false`) - this is the proto3 default
- Common beneficiary addition pattern where `EndPeriod` is not specified

**Execution Practicality:** The vulnerability requires no malicious action - it's triggered by normal management operations:
1. Manager creates scheme with default settings
2. Manager adds beneficiary without `EndPeriod` (defaults to `long.MaxValue`)
3. Manager later calls `RemoveBeneficiary` without `profitDetailId`
4. Removal silently fails, beneficiary continues claiming profits

**Detection Constraints:** The vulnerability is silent - `RemoveBeneficiary` completes successfully without error, making it undetectable without querying `ProfitDetailsMap` and `TotalShares` after removal.

**Real-World Risk:** While current system contracts (Treasury, Election) avoid this by explicitly specifying `EndPeriod` values, the contract itself doesn't enforce this protection. Third-party dApps using the Profit contract with default settings would be vulnerable.

## Recommendation

Implement one or more of the following fixes:

1. **Explicit validation**: Add a check to prevent removing beneficiaries with `EndPeriod = long.MaxValue` when `CanRemoveBeneficiaryDirectly = false` and throw a clear error message instructing the manager to provide `profitDetailId`.

2. **Auto-detection**: Modify the filter logic to include an additional condition that handles `long.MaxValue` EndPeriods when removing beneficiaries.

3. **Documentation**: Clearly document that when adding beneficiaries without `EndPeriod` to non-cancelable schemes, removal requires providing the `profitDetailId`.

4. **Default change**: Consider changing the default behavior to either require explicit `EndPeriod` specification or set `CanRemoveBeneficiaryDirectly = true` by default to allow removal without the workaround.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task RemoveBeneficiary_WithDefaultEndPeriod_SilentlyFails()
{
    // 1. Create scheme with default CanRemoveBeneficiaryDirectly = false
    var schemeId = await ProfitContractStub.CreateScheme.SendAsync(new CreateSchemeInput
    {
        // CanRemoveBeneficiaryDirectly not specified, defaults to false
    });
    
    // 2. Add beneficiary without EndPeriod (defaults to long.MaxValue)
    var beneficiary = Accounts[1].Address;
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = beneficiary,
            Shares = 100
        }
        // EndPeriod not specified, defaults to long.MaxValue
    });
    
    var schemeBefore = await ProfitContractStub.GetScheme.CallAsync(schemeId.Output);
    var totalSharesBefore = schemeBefore.TotalShares;
    
    // 3. Attempt to remove beneficiary without profitDetailId
    await ProfitContractStub.RemoveBeneficiary.SendAsync(new RemoveBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        Beneficiary = beneficiary
        // profitDetailId not provided
    });
    
    // 4. Verify removal silently failed
    var schemeAfter = await ProfitContractStub.GetScheme.CallAsync(schemeId.Output);
    var totalSharesAfter = schemeAfter.TotalShares;
    
    // BUG: TotalShares unchanged, removal failed
    Assert.Equal(totalSharesBefore, totalSharesAfter);
    
    // Beneficiary can still claim profits
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeId.Output,
        Beneficiary = beneficiary
    });
    Assert.NotEmpty(profitDetails.Details); // Still has active profit details
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L161-163)
```csharp
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L260-260)
```csharp
        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L334-338)
```csharp
        if (profitDetailId != null && profitDetails.Details.Any(d => d.Id == profitDetailId) &&
            detailsCanBeRemoved.All(d => d.Id != profitDetailId))
        {
            detailsCanBeRemoved.Add(profitDetails.Details.Single(d => d.Id == profitDetailId));
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L340-359)
```csharp
        if (detailsCanBeRemoved.Any())
        {
            foreach (var profitDetail in detailsCanBeRemoved)
            {
                // set remove sign
                profitDetail.IsWeightRemoved = true;
                if (profitDetail.LastProfitPeriod >= scheme.CurrentPeriod)
                {
                    // remove those profits claimed
                    profitDetails.Details.Remove(profitDetail);
                }
                else if (profitDetail.EndPeriod >= scheme.CurrentPeriod)
                {
                    // No profit can be here, except the scheme is cancellable.
                    // shorten profit.
                    profitDetail.EndPeriod = scheme.CurrentPeriod.Sub(1);
                }

                removedDetails.TryAdd(scheme.CurrentPeriod, profitDetail.Shares);
            }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-766)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
```

**File:** protobuf/profit_contract.proto (L130-130)
```text
    bool can_remove_beneficiary_directly = 5;
```
