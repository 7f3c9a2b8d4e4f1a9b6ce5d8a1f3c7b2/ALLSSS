### Title
Beneficiaries with EndPeriod=long.MaxValue Cannot Be Removed from Schemes with CanRemoveBeneficiaryDirectly=false

### Summary
When a profit scheme has `CanRemoveBeneficiaryDirectly = false` (the default setting) and a beneficiary is added with `EndPeriod = long.MaxValue` (automatically set when EndPeriod is not specified), the scheme manager cannot effectively remove the beneficiary using `RemoveBeneficiary` without providing the `profitDetailId`. This allows the "removed" beneficiary to continue claiming profits indefinitely, permanently diluting legitimate beneficiaries' shares and causing unauthorized fund drainage from the profit scheme.

### Finding Description

The vulnerability exists in the `RemoveProfitDetails` helper method called by `RemoveBeneficiary`. [1](#0-0) 

When a manager calls `RemoveBeneficiary`, the method invokes `RemoveProfitDetails` to identify which profit details can be removed: [2](#0-1) 

The critical flaw is at lines 321-324. When `CanRemoveBeneficiaryDirectly = false`, only details where `d.EndPeriod < scheme.CurrentPeriod` are eligible for removal. Since `long.MaxValue` is always greater than or equal to `CurrentPeriod`, beneficiaries with `EndPeriod = long.MaxValue` are NEVER included in `detailsCanBeRemoved`.

The default `EndPeriod` assignment occurs in `AddBeneficiary`: [3](#0-2) 

When `EndPeriod` is 0 (not specified), it defaults to `long.MaxValue`, meaning the beneficiary never expires.

Consequently, when the beneficiary is not in `detailsCanBeRemoved`:
- The `IsWeightRemoved` flag is NOT set to true (line 345 never executes)
- The `EndPeriod` is NOT shortened (line 355 never executes)
- The detail remains in `ProfitDetailsMap` (line 349 never executes)
- No shares are added to `removedDetails` (line 358 never executes)
- At line 260, `removedDetails.Values.Sum()` returns 0, so nothing is subtracted from `TotalShares` [4](#0-3) 

A workaround exists where the manager can provide a `profitDetailId` to target a specific detail: [5](#0-4) 

However, this workaround is non-obvious, undocumented, and requires knowledge of the internal profit detail ID.

### Impact Explanation

**Direct Fund Impact - CRITICAL:**

1. **Unauthorized Continuous Profit Claims**: After the manager attempts to remove a beneficiary, that beneficiary can continue claiming profits indefinitely. The profit claiming logic only checks if `EndPeriod >= LastProfitPeriod`: [6](#0-5) 

With `EndPeriod = long.MaxValue`, this condition is always satisfied.

2. **Permanent Share Dilution**: The "removed" beneficiary's shares remain in the scheme's `TotalShares`, permanently diluting the profit share of all legitimate beneficiaries. For example, if 1000 tokens are distributed and the removed beneficiary had 100 shares out of 1000 total, they continue receiving 10% of all future distributions.

3. **Manager Authorization Bypass**: The scheme manager's explicit intent to remove a beneficiary is silently ignored by the contract, violating the authorization model where only managers control beneficiary membership.

4. **Undetected Exploitation**: Since `RemoveBeneficiary` returns successfully without error, the manager has no indication that the removal failed, making this issue difficult to detect.

**Who is affected**: All schemes created with `CanRemoveBeneficiaryDirectly = false` (the default) where beneficiaries are added without explicitly specifying `EndPeriod`. This includes potential third-party dApp profit schemes and any future system contract upgrades using the Profit contract.

### Likelihood Explanation

**Reachable Entry Point**: The attack requires no special privileges beyond normal beneficiary status. The manager unknowingly enables the vulnerability when:
1. Creating a scheme without setting `CanRemoveBeneficiaryDirectly = true`
2. Adding beneficiaries without specifying `EndPeriod` (common pattern)

**Feasible Preconditions**: 
- Default scheme configuration (`CanRemoveBeneficiaryDirectly = false`)
- Common beneficiary addition pattern (EndPeriod not specified, seen in test code): [7](#0-6) 

**Execution Practicality**: 
1. Manager creates scheme with default settings
2. Manager adds beneficiary without EndPeriod (defaults to long.MaxValue)
3. Manager later calls RemoveBeneficiary (without profitDetailId)
4. Removal silently fails, beneficiary continues claiming profits

**Detection Constraints**: The vulnerability is silent - `RemoveBeneficiary` succeeds without error, making it undetectable without querying `ProfitDetailsMap` and `TotalShares` post-removal.

**Probability**: MEDIUM-HIGH for third-party schemes and future system contracts that don't explicitly set `CanRemoveBeneficiaryDirectly = true`. Current system contracts (Treasury schemes) avoid this by always specifying EndPeriod values, but this protection is not enforced by the contract itself.

### Recommendation

**Code-Level Mitigation:**

Modify the `RemoveProfitDetails` method to handle `EndPeriod = long.MaxValue` even when `CanRemoveBeneficiaryDirectly = false`:

```csharp
var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
    ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
    : profitDetails.Details
        .Where(d => (d.EndPeriod < scheme.CurrentPeriod || profitDetailId != null) && !d.IsWeightRemoved).ToList();
```

**Alternative Fix:**

When `profitDetailId` is null, explicitly check for details with `EndPeriod >= CurrentPeriod` and shorten their `EndPeriod` to `CurrentPeriod - 1` before processing removal.

**Invariant Checks:**

1. Assert that after `RemoveBeneficiary`, the beneficiary's shares have been subtracted from `TotalShares`
2. Assert that after `RemoveBeneficiary`, all the beneficiary's profit details either have `IsWeightRemoved = true` or `EndPeriod < CurrentPeriod`

**Test Cases:**

Add regression tests for:
1. Removing beneficiary with `EndPeriod = long.MaxValue` from scheme with `CanRemoveBeneficiaryDirectly = false` without profitDetailId
2. Verify `TotalShares` decreases correctly
3. Verify beneficiary cannot claim profits after removal
4. Verify existing test at line 564 passes with the fix [8](#0-7) 

### Proof of Concept

**Initial State:**
1. Scheme created with default settings (CanRemoveBeneficiaryDirectly = false, CurrentPeriod = 1, TotalShares = 0)
2. Scheme funded with 1000 tokens

**Transaction Steps:**

1. Manager calls `AddBeneficiary(beneficiaryA, shares=100, endPeriod=0)` 
   - EndPeriod automatically set to long.MaxValue
   - TotalShares = 100

2. Manager calls `AddBeneficiary(beneficiaryB, shares=100, endPeriod=0)`
   - TotalShares = 200

3. Manager calls `DistributeProfits(period=1, amount=1000)`
   - Each beneficiary can claim 500 tokens (100/200 share)

4. Manager calls `RemoveBeneficiary(beneficiaryA)` without profitDetailId
   - **Expected**: beneficiaryA removed, TotalShares = 100
   - **Actual**: beneficiaryA NOT removed, TotalShares = 200 (unchanged)

5. BeneficiaryA calls `ClaimProfits()`
   - **Expected**: Transaction fails or zero tokens claimed
   - **Actual**: Successfully claims ongoing profits

6. Manager calls `DistributeProfits(period=2, amount=1000)`
   - BeneficiaryA can claim 500 tokens despite being "removed"
   - BeneficiaryB receives only 500 tokens instead of 1000

**Success Condition:** BeneficiaryA successfully claims profits from period 2 onwards despite RemoveBeneficiary being called, and TotalShares remains at 200 instead of decreasing to 100.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-163)
```csharp
    public override Empty AddBeneficiary(AddBeneficiaryInput input)
    {
        AssertValidInput(input);
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L308-324)
```csharp
    private RemovedDetails RemoveProfitDetails(Scheme scheme, Address beneficiary, Hash profitDetailId = null)
    {
        var removedDetails = new RemovedDetails();

        var profitDetails = State.ProfitDetailsMap[scheme.SchemeId][beneficiary];
        if (profitDetails == null)
        {
            return removedDetails;
        }
        
        // remove all removalbe profitDetails.
        // If a scheme can be cancelled, get all available profitDetail.
        // else, get those available and out of date ones.
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L342-359)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L113-117)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod < scheme.CurrentPeriod && (d.LastProfitPeriod == 0
                ? d.EndPeriod >= d.StartPeriod
                : d.EndPeriod >= d.LastProfitPeriod)
        ).ToList();
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L564-630)
```csharp
    public async Task ProfitContract_RemoveBeneficiary_Test()
    {
        const int shares = 100;
        const int amount = 100;

        var creator = Creators[0];
        var beneficiary = Normal[0];
        var receiverAddress = Address.FromPublicKey(NormalKeyPair[0].PublicKey);

        var schemeId = await CreateSchemeAsync();

        await ContributeProfits(schemeId);

        await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
        {
            BeneficiaryShare = new BeneficiaryShare { Beneficiary = receiverAddress, Shares = shares },
            SchemeId = schemeId,
            EndPeriod = 1
        });

        await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
        {
            SchemeId = schemeId,
            AmountsMap =
            {
                { ProfitContractTestConstants.NativeTokenSymbol, amount }
            },
            Period = 1
        });

        // Check total_weight and profit_detail
        {
            var profitItem = await creator.GetScheme.CallAsync(schemeId);
            profitItem.TotalShares.ShouldBe(shares);

            var profitDetails = await creator.GetProfitDetails.CallAsync(new GetProfitDetailsInput
            {
                SchemeId = schemeId,
                Beneficiary = receiverAddress
            });
            profitDetails.Details.Count.ShouldBe(1);
        }

        await beneficiary.ClaimProfits.SendAsync(new ClaimProfitsInput
        {
            SchemeId = schemeId,
        });

        await creator.RemoveBeneficiary.SendAsync(new RemoveBeneficiaryInput
        {
            Beneficiary = receiverAddress,
            SchemeId = schemeId
        });

        // Check total_weight and profit_detail
        {
            var profitItem = await creator.GetScheme.CallAsync(schemeId);
            profitItem.TotalShares.ShouldBe(0);

            var profitDetails = await creator.GetProfitDetails.CallAsync(new GetProfitDetailsInput
            {
                SchemeId = schemeId,
                Beneficiary = receiverAddress
            });
            profitDetails.Details.Count.ShouldBe(0);
        }
    }
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L1401-1405)
```csharp
        await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
        {
            BeneficiaryShare = new BeneficiaryShare { Beneficiary = Accounts[0].Address, Shares = 100 },
            SchemeId = schemeId,
        });
```
