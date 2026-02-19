### Title
Irremovable Beneficiaries with long.MaxValue EndPeriod in Non-Cancellable Schemes

### Summary
The `AddBeneficiary` function converts `EndPeriod = 0` to `long.MaxValue` to create "permanent" beneficiaries. However, when a scheme has `CanRemoveBeneficiaryDirectly = false`, these beneficiaries cannot be removed through `RemoveBeneficiary` because the removal logic filters by `EndPeriod < CurrentPeriod`, which is never true for `long.MaxValue`. This creates irremovable beneficiaries that permanently dilute profit distributions.

### Finding Description

In the `AddBeneficiary` function, when `EndPeriod` is set to 0, it is automatically converted to `long.MaxValue`: [1](#0-0) 

This is intended to create beneficiaries that "will never expire unless removed" as indicated by the code comment.

Within the same function, old profit details are cleaned up, but explicitly exclude details with `EndPeriod == long.MaxValue`: [2](#0-1) 

The critical issue occurs in the `RemoveProfitDetails` function called by `RemoveBeneficiary`. When `CanRemoveBeneficiaryDirectly` is `false`, only details where `d.EndPeriod < scheme.CurrentPeriod` can be removed: [3](#0-2) 

Since `long.MaxValue` will never be less than `scheme.CurrentPeriod`, these details cannot be filtered for removal.

There is a fallback mechanism that allows targeting specific details by `profitDetailId`: [4](#0-3) 

However, this only works if the detail was created with a `profitDetailId`. The `profit_detail_id` field is optional in `AddBeneficiaryInput`: [5](#0-4) 

If a beneficiary is added without providing a `profitDetailId` (meaning `detail.Id = null`), the fallback mechanism cannot target it for removal.

### Impact Explanation

**Direct Impact:**
- Beneficiaries that were intended to be temporary become permanent participants in profit distribution
- Other beneficiaries receive permanently diluted shares since total shares cannot be reduced
- The scheme manager loses control over the beneficiary composition of the scheme

**Affected Parties:**
- Legitimate beneficiaries receive reduced profit allocations
- Scheme managers cannot correct mistakes or adjust beneficiary lists
- The overall scheme integrity is compromised

**Severity Justification:**
This is a **Medium** severity issue because:
1. It requires specific preconditions (`CanRemoveBeneficiaryDirectly = false`, `EndPeriod = 0`, no `profitDetailId`)
2. The impact is fund distribution distortion rather than direct theft
3. It affects governance and operational control of profit schemes
4. No workaround exists for the manager without recreating the entire scheme

### Likelihood Explanation

**Feasibility:**
The vulnerability is highly feasible under normal operations:

1. **Realistic Preconditions:** The `can_remove_beneficiary_directly` flag is a legitimate configuration option used to prevent premature beneficiary removal: [6](#0-5) 

2. **Common Usage Pattern:** Setting `EndPeriod = 0` is explicitly documented as the way to create permanent beneficiaries per the code comment

3. **Optional ID:** The `profit_detail_id` is an optional field and may not be provided in many legitimate use cases

4. **Entry Point:** Both `AddBeneficiary` and `RemoveBeneficiary` are public methods accessible to scheme managers: [7](#0-6) [8](#0-7) 

**Attack Complexity:**
- Low complexity - occurs through normal contract usage without requiring special conditions
- Can happen unintentionally when managers don't realize the implications
- No special attacker capabilities required beyond being a scheme manager

### Recommendation

**Code-Level Mitigation:**

1. **Modify RemoveProfitDetails logic** to allow removal of `long.MaxValue` EndPeriod details when explicitly requested by the manager:

```csharp
// In RemoveProfitDetails around line 321-324:
var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
    ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
    : profitDetails.Details
        .Where(d => (d.EndPeriod < scheme.CurrentPeriod || 
                     (d.EndPeriod == long.MaxValue && profitDetailId != null && d.Id == profitDetailId)) 
               && !d.IsWeightRemoved).ToList();
```

2. **Add invariant check** in `RemoveBeneficiary` to validate that removal was successful:

```csharp
// After RemoveProfitDetails call:
Assert(removedDetails.Count > 0 || profitDetailId == null, 
    "Cannot remove beneficiary with permanent EndPeriod without profit_detail_id");
```

3. **Enforce profit_detail_id** for long.MaxValue EndPeriod beneficiaries:

```csharp
// In AddBeneficiary around line 161:
if (input.EndPeriod == 0)
{
    input.EndPeriod = long.MaxValue;
    Assert(input.ProfitDetailId != null, 
        "profit_detail_id is required for permanent beneficiaries to enable future removal");
}
```

**Test Cases:**
- Test removal of beneficiary with `EndPeriod = long.MaxValue` and `CanRemoveBeneficiaryDirectly = false` with valid `profitDetailId`
- Test that removal fails gracefully when `profitDetailId` is not provided
- Verify that `TotalShares` is correctly updated after removal of permanent beneficiaries

### Proof of Concept

**Required Initial State:**
1. Deploy Profit contract
2. Create a scheme with `can_remove_beneficiary_directly = false`

**Transaction Sequence:**

**Step 1:** Create scheme
```
CreateScheme({
    profit_receiving_due_period_count: 10,
    can_remove_beneficiary_directly: false,
    manager: ManagerAddress
})
→ Returns: SchemeId
```

**Step 2:** Add beneficiary with EndPeriod = 0 and no profit_detail_id
```
AddBeneficiary({
    scheme_id: SchemeId,
    beneficiary_share: {
        beneficiary: BeneficiaryAddress,
        shares: 100
    },
    end_period: 0,
    profit_detail_id: null
})
→ EndPeriod internally converted to long.MaxValue
→ ProfitDetail created with Id = null
```

**Step 3:** Attempt to remove the beneficiary
```
RemoveBeneficiary({
    scheme_id: SchemeId,
    beneficiary: BeneficiaryAddress,
    profit_detail_id: null
})
→ RemoveProfitDetails filters by: d.EndPeriod < scheme.CurrentPeriod
→ long.MaxValue < CurrentPeriod evaluates to FALSE
→ Detail is NOT removed
```

**Step 4:** Verify beneficiary still exists
```
GetProfitDetails({
    scheme_id: SchemeId,
    beneficiary: BeneficiaryAddress
})
→ Returns: ProfitDetails with the original detail still present
→ Scheme.TotalShares still includes the beneficiary's shares
```

**Expected vs Actual Result:**
- **Expected:** Beneficiary is removed and TotalShares is decreased
- **Actual:** Beneficiary remains in the scheme permanently, continuing to receive profit distributions indefinitely

**Success Condition:** 
The beneficiary cannot be removed, creating a permanent participant in the profit scheme that dilutes distributions to all other beneficiaries.

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

**File:** protobuf/profit_contract.proto (L129-130)
```text
    // Whether you can directly remove the beneficiary.
    bool can_remove_beneficiary_directly = 5;
```

**File:** protobuf/profit_contract.proto (L176-184)
```text
}

message FixProfitDetailInput {
    aelf.Hash scheme_id = 1;
    BeneficiaryShare beneficiary_share = 2;
    int64 start_period = 3;
    int64 end_period = 4;
    aelf.Hash profit_detail_id = 5;
}
```
