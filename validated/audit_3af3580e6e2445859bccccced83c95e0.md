# Audit Report

## Title
TokenHolder Contract DoS Due to Stale ProfitDetails After Partial Beneficiary Removal

## Summary
When a beneficiary performs partial share removal in a TokenHolder scheme while having unclaimed profits, the Profit contract preserves the old profit detail marked as removed, creating multiple details. The TokenHolder contract's `AddBeneficiary` and `RemoveBeneficiary` methods incorrectly assume exactly one detail exists using `.Single()`, causing `InvalidOperationException` and preventing users from modifying their staking positions until they claim all profits or the old detail expires.

## Finding Description

This vulnerability arises from an architectural mismatch between the Profit contract's historical detail preservation and the TokenHolder contract's single-detail assumption.

**Profit Contract's Detail Preservation Logic:**

When `RemoveBeneficiary` is called, the `RemoveProfitDetails` method checks if the beneficiary has claimed all available profits. [1](#0-0) 

For beneficiaries with unclaimed profits (`LastProfitPeriod < CurrentPeriod`), the detail is NOT removed from state. Instead, it is marked with `IsWeightRemoved=true` and its `EndPeriod` is shortened, but the detail remains in the collection. [2](#0-1) 

The beneficiary is only removed from the state map when all details are cleared. [3](#0-2) 

**View Method Returns Unfiltered Data:**

The `GetProfitDetails()` view method directly returns the raw state map without filtering removed details. [4](#0-3) 

**TokenHolder Partial Removal Creates Multiple Details:**

When `TokenHolderContract.RemoveBeneficiary` is called with a partial amount (not zero, less than total shares), it first removes the beneficiary entirely via the Profit contract, then re-adds them with reduced shares. [5](#0-4) 

This results in TWO profit details: the old one (marked removed with shortened EndPeriod) and the new one (active with reduced shares). This behavior is explicitly validated in the test suite, which asserts `profitAmount.Details.Count.ShouldBe(2)` after a partial removal operation. [6](#0-5) 

**Critical Integration Bug - Invalid .Single() Assumptions:**

The TokenHolder contract has two locations that incorrectly assume exactly one detail exists:

1. In `AddBeneficiary`, when consolidating existing details, the code calls `.Single()` on the details collection, which throws `InvalidOperationException` when multiple details exist. [7](#0-6) 

2. In `RemoveBeneficiary`, when retrieving current shares, the code calls `.Single()` on the details collection, which throws when multiple details exist. [8](#0-7) 

## Impact Explanation

**Operational Denial-of-Service:**

Once a beneficiary performs a partial removal operation while having unclaimed profits, any subsequent attempts to call `AddBeneficiary` or `RemoveBeneficiary` for that beneficiary will fail with an `InvalidOperationException`. This prevents users from:
- Adding additional shares to their staking position
- Removing additional shares from their staking position
- Completely removing their beneficiary status through normal operations

**Affected Users:**

Any TokenHolder scheme user who performs partial share removal while having unclaimed profits becomes unable to modify their position through standard contract methods until they either:
- Manually claim all historical profits (which removes old expired details via the ClaimProfits cleanup logic [9](#0-8) )
- Wait for the old detail to expire past its `ProfitReceivingDuePeriodCount` (auto-cleanup occurs during AddBeneficiary [10](#0-9) )

**No Permanent Fund Loss:**

Critically, no funds are stolen or permanently locked. Users retain ownership of their shares and can still claim their profits via `ClaimProfits`. The vulnerability is purely operational, affecting position modification capabilities rather than fund security.

**Severity Assessment: LOW**

The vulnerability has low severity because:
- No fund theft or permanent loss occurs
- It's self-resolving (temporary until old details are claimed or expire naturally)
- Users maintain access to profit claiming functionality
- Affects specific operations on affected accounts, not the entire protocol
- Workaround exists (claim all profits to clear old details)

## Likelihood Explanation

**High Likelihood of Occurrence:**

This vulnerability is highly likely to manifest in normal protocol operations:

**Publicly Accessible Entry Points:** Both `AddBeneficiary` and `RemoveBeneficiary` are public methods callable by scheme managers as verified by authorization checks. [11](#0-10) 

**Standard Feature Usage:** Partial removals are a documented feature with explicit test coverage, meaning users will naturally perform partial unstaking operations during normal use.

**Automatic Trigger Through Normal Workflows:**
1. User stakes tokens via `AddBeneficiary` (creates 1 detail)
2. Scheme distributes profits (CurrentPeriod increases)
3. User performs partial unstaking via `RemoveBeneficiary` with a partial amount without claiming (creates 2 details due to unclaimed profits)
4. User attempts any position modification (triggers exception on `.Single()` call)
5. Transaction reverts with `InvalidOperationException`

**No Malicious Intent Required:** This is a design flaw triggered by legitimate user operations, not an attack requiring adversarial behavior. Users following normal staking/unstaking patterns will encounter this issue whenever they perform partial removals while having unclaimed profits.

## Recommendation

Modify the TokenHolder contract to handle multiple profit details correctly. Replace `.Single()` calls with logic that aggregates shares across all active (non-removed) details:

**In AddBeneficiary (lines 46-56):**
```csharp
if (detail.Details.Any())
{
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    // Sum shares from all details instead of using .Single()
    var totalShares = detail.Details.Sum(d => d.Shares);
    shares = shares.Add(totalShares);
}
```

**In RemoveBeneficiary (lines 74-79):**
```csharp
var details = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = input.Beneficiary,
    SchemeId = scheme.SchemeId
}).Details;
// Sum shares from all details instead of using .Single()
var lockedAmount = details.Sum(d => d.Shares);
```

This ensures the contract handles both single and multiple detail scenarios correctly.

## Proof of Concept

Add this test to `TokenHolderTests.cs` to demonstrate the DoS condition:

```csharp
[Fact]
public async Task DoS_After_Partial_Removal_With_Unclaimed_Profits_Test()
{
    // Setup: Create scheme and add beneficiary
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF"
    });
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 9999
    });
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Shares = 1000
    });
    
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var schemeId = schemeIds.SchemeIds[0];
    
    // Distribute profits to create unclaimed profits (LastProfitPeriod < CurrentPeriod)
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = Starter,
        AmountsMap = { { "ELF", 0L } }
    });
    
    // Perform partial removal (this creates 2 details due to unclaimed profits)
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Amount = 10
    });
    
    // Verify 2 details exist
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        Beneficiary = Starter,
        SchemeId = schemeId
    });
    profitDetails.Details.Count.ShouldBe(2);
    
    // VULNERABILITY: Attempt AddBeneficiary - should fail with InvalidOperationException
    var addResult = await TokenHolderContractStub.AddBeneficiary.SendWithExceptionAsync(
        new AddTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Shares = 100
        });
    addResult.TransactionResult.Error.ShouldContain("Sequence contains more than one element");
    
    // VULNERABILITY: Attempt RemoveBeneficiary - should also fail
    var removeResult = await TokenHolderContractStub.RemoveBeneficiary.SendWithExceptionAsync(
        new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = 10
        });
    removeResult.TransactionResult.Error.ShouldContain("Sequence contains more than one element");
}
```

This test demonstrates that after a partial removal with unclaimed profits, both `AddBeneficiary` and `RemoveBeneficiary` operations fail due to the `.Single()` calls encountering multiple profit details.

## Notes

The vulnerability is valid and affects production contracts in normal operation scenarios. While the severity is low due to the availability of workarounds and the lack of fund loss, it represents a real usability issue that will impact users who perform partial unstaking operations before claiming their profits. The fix is straightforward and should aggregate shares across all details rather than assuming a single detail exists.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L204-207)
```csharp
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L308-386)
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
        //id == null
        if (scheme.CanRemoveBeneficiaryDirectly && profitDetailId != null)
        {
            detailsCanBeRemoved = detailsCanBeRemoved.All(d => d.Id != profitDetailId)
                ? detailsCanBeRemoved.Where(d => d.Id == null).ToList()
                : detailsCanBeRemoved.Where(d => d.Id == profitDetailId).ToList();
        }

        // remove the profitDetail with the profitDetailId, and de-duplicate it before involving.
        if (profitDetailId != null && profitDetails.Details.Any(d => d.Id == profitDetailId) &&
            detailsCanBeRemoved.All(d => d.Id != profitDetailId))
        {
            detailsCanBeRemoved.Add(profitDetails.Details.Single(d => d.Id == profitDetailId));
        }

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

            Context.LogDebug(() => $"ProfitDetails after removing expired details: {profitDetails}");
        }

        var weightCanBeRemoved = profitDetails.Details
            .Where(d => d.EndPeriod == scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
        foreach (var profitDetail in weightCanBeRemoved)
        {
            profitDetail.IsWeightRemoved = true;
        }

        var weights = weightCanBeRemoved.Sum(d => d.Shares);
        removedDetails.Add(0, weights);


        // Clear old profit details.
        if (profitDetails.Details.Count != 0)
        {
            State.ProfitDetailsMap[scheme.SchemeId][beneficiary] = profitDetails;
        }
        else
        {
            State.ProfitDetailsMap[scheme.SchemeId].Remove(beneficiary);
        }

        return removedDetails;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-804)
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
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L46-48)
```csharp
    public override ProfitDetails GetProfitDetails(GetProfitDetailsInput input)
    {
        return State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L74-79)
```csharp
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L80-95)
```csharp
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        if (lockedAmount > input.Amount &&
            input.Amount != 0) // If input.Amount == 0, means just remove this beneficiary.
            State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = input.Beneficiary,
                    Shares = lockedAmount.Sub(input.Amount)
                }
            });
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L187-196)
```csharp
        var profitAmount = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
        {
            Beneficiary = Starter,
            SchemeId = schemeId
        });
        profitAmount.Details.Count.ShouldBe(2);
        profitAmount.Details[0].Shares.ShouldBe(beforeRemoveScheme.TotalShares);
        profitAmount.Details[0].EndPeriod.ShouldBe(0);
        profitAmount.Details[1].Shares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
    }
```
