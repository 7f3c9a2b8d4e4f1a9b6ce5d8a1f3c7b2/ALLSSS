# Audit Report

## Title
TokenHolder Contract DoS Due to Stale ProfitDetails After Partial Beneficiary Removal

## Summary
When a beneficiary is partially removed from a TokenHolder scheme, the Profit contract preserves historical profit details marked as removed instead of deleting them. The TokenHolder contract's `AddBeneficiary` and `RemoveBeneficiary` methods incorrectly assume exactly one profit detail exists using `.Single()`, causing `InvalidOperationException` when multiple details are present. This creates a denial-of-service condition that prevents users from modifying their staking positions.

## Finding Description

This vulnerability arises from an architectural mismatch between the Profit contract's state management design and the TokenHolder contract's assumptions.

**Profit Contract's Historical Detail Preservation:**

When `RemoveBeneficiary` is called on the Profit contract, the `RemoveProfitDetails` method evaluates whether the beneficiary has unclaimed profits. [1](#0-0) 

For beneficiaries with unclaimed profits (`LastProfitPeriod < CurrentPeriod`), the detail is NOT removed from state. Instead, it is marked with `IsWeightRemoved=true` and has its `EndPeriod` shortened, but remains in the details collection. [2](#0-1) 

The beneficiary is only removed from the state map when all details are cleared. [3](#0-2) 

**View Method Returns Unfiltered Data:**

The `GetProfitDetails()` view method directly returns the state map without filtering removed details. [4](#0-3) 

**TokenHolder Partial Removal Creates Multiple Details:**

When `TokenHolderContract.RemoveBeneficiary` is called with a partial amount (not zero, less than total shares), it removes the beneficiary entirely, then re-adds them with reduced shares. [5](#0-4) 

This results in TWO profit details: the old one (marked removed, shortened EndPeriod) and the new one (active with reduced shares). This behavior is explicitly validated in the test suite. [6](#0-5) 

**Critical Integration Bug - Invalid .Single() Assumptions:**

The TokenHolder contract has two locations that incorrectly assume exactly one detail exists:

1. In `AddBeneficiary`, when consolidating existing details: The code calls `.Single()` which throws `InvalidOperationException` when multiple details exist. [7](#0-6) 

2. In `RemoveBeneficiary`, when retrieving current shares: The code calls `.Single()` which throws when multiple details exist. [8](#0-7) 

## Impact Explanation

**Operational Denial-of-Service:**

Once a beneficiary performs a partial removal operation, any subsequent attempts to call `AddBeneficiary` or `RemoveBeneficiary` for that beneficiary will fail with an `InvalidOperationException`. This prevents users from:
- Adding additional shares to their staking position
- Removing additional shares from their staking position
- Completely removing their beneficiary status through normal operations

**Affected Users:**

Any TokenHolder scheme user who performs partial share removal becomes unable to modify their position through standard contract methods until:
- They manually claim all historical profits (clearing the old detail via ClaimProfits)
- The old detail expires past its `ProfitReceivingDuePeriodCount`

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

**Publicly Accessible Entry Points:** Both `AddBeneficiary` and `RemoveBeneficiary` are public methods callable by scheme managers and integrated contracts.

**Standard Feature Usage:** Partial removals are a documented feature with explicit test coverage, meaning users will naturally perform partial unstaking operations.

**Automatic Trigger Through Normal Workflows:**
1. User stakes tokens via `AddBeneficiary` (creates 1 detail with `LastProfitPeriod=0`)
2. User performs partial unstaking via `RemoveBeneficiary` with a partial amount (creates 2 details because `LastProfitPeriod < CurrentPeriod`)
3. User attempts any position modification (triggers exception on `.Single()` call)
4. Transaction reverts with `InvalidOperationException`

**No Malicious Intent Required:** This is a design flaw triggered by legitimate user operations, not an attack requiring adversarial behavior. Users following normal staking/unstaking patterns will encounter this issue.

## Recommendation

Replace `.Single()` calls with safer alternatives that handle multiple details:

**In AddBeneficiary (line 55):**
```csharp
if (detail.Details.Any())
{
    // Consolidate all existing details by summing their shares
    var totalExistingShares = detail.Details.Sum(d => d.Shares);
    
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    shares.Add(totalExistingShares);
}
```

**In RemoveBeneficiary (line 74-78):**
```csharp
var details = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = input.Beneficiary,
    SchemeId = scheme.SchemeId
}).Details;

// Sum all active (non-removed) shares
var lockedAmount = details.Where(d => !d.IsWeightRemoved).Sum(d => d.Shares);
```

Alternatively, ensure `RemoveProfitDetails` fully removes details when `LastProfitPeriod < CurrentPeriod` for schemes with `CanRemoveBeneficiaryDirectly=true`.

## Proof of Concept

```csharp
[Fact]
public async Task DoS_After_Partial_Removal_Proof_Of_Concept()
{
    // Setup: Create scheme and add beneficiary with 1000 shares
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF"
    });
    
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 10000
    });
    
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Shares = 1000
    });
    
    // Trigger vulnerability: Partial removal creates 2 details
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Amount = 100
    });
    
    // Verify DoS: AddBeneficiary now fails with InvalidOperationException
    var addResult = await TokenHolderContractStub.AddBeneficiary.SendWithExceptionAsync(
        new AddTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Shares = 50
        });
    
    addResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    addResult.TransactionResult.Error.ShouldContain("Sequence contains more than one element");
    
    // Verify DoS: RemoveBeneficiary also fails
    var removeResult = await TokenHolderContractStub.RemoveBeneficiary.SendWithExceptionAsync(
        new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = 50
        });
    
    removeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    removeResult.TransactionResult.Error.ShouldContain("Sequence contains more than one element");
}
```

## Notes

This vulnerability demonstrates a classic integration bug where one contract (Profit) implements historical state preservation for legitimate reasons (allowing users to claim past profits), but another contract (TokenHolder) makes incorrect assumptions about state cardinality. The `.Single()` LINQ operator is dangerous in distributed systems where state can evolve through multiple code paths. The LOW severity rating is appropriate because while this creates operational friction, it doesn't compromise fund security and is self-resolving through the normal profit claiming workflow.

### Citations

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

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L46-49)
```csharp
    public override ProfitDetails GetProfitDetails(GetProfitDetailsInput input)
    {
        return State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];
    }
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-98)
```csharp
    public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);

        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
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

        return new Empty();
    }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L156-196)
```csharp
    public async Task RemoveBeneficiary_With_Amount_Test()
    {
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
        var beforeRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
        var amount = 10;
        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = amount
        });
        var afterRemoveScheme = await ProfitContractStub.GetScheme.CallAsync(schemeIds.SchemeIds[0]);
        afterRemoveScheme.TotalShares.ShouldBe(beforeRemoveScheme.TotalShares - amount);
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
