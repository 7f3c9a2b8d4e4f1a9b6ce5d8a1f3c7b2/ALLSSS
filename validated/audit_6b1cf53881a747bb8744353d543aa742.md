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
1. User stakes tokens via `AddBeneficiary` (creates 1 detail)
2. User performs partial unstaking via `RemoveBeneficiary` with a partial amount (creates 2 details)
3. User attempts any position modification (triggers exception on `.Single()` call)
4. Transaction reverts with `InvalidOperationException`

**No Malicious Intent Required:** This is a design flaw triggered by legitimate user operations, not an attack requiring adversarial behavior. Users following normal staking/unstaking patterns will encounter this issue.

## Recommendation

**Fix Option 1 - Handle Multiple Details in TokenHolder:**
Modify the TokenHolder contract to handle multiple profit details instead of assuming a single detail:

```csharp
// In AddBeneficiary (line 46-56)
if (detail.Details.Any())
{
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    // Sum all active shares instead of using .Single()
    var totalShares = detail.Details.Where(d => !d.IsWeightRemoved).Sum(d => d.Shares);
    shares.Add(totalShares);
}

// In RemoveBeneficiary (line 74-79)
var details = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = input.Beneficiary,
    SchemeId = scheme.SchemeId
}).Details;
// Sum active shares instead of using .Single()
var lockedAmount = details.Where(d => !d.IsWeightRemoved).Sum(d => d.Shares);
```

**Fix Option 2 - Filter Removed Details in Profit Contract:**
Modify `GetProfitDetails` to filter out removed details:

```csharp
public override ProfitDetails GetProfitDetails(GetProfitDetailsInput input)
{
    var allDetails = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];
    if (allDetails == null) return null;
    
    // Filter out removed details
    var activeDetails = allDetails.Details.Where(d => !d.IsWeightRemoved).ToList();
    return new ProfitDetails { Details = { activeDetails } };
}
```

**Recommended Approach:** Implement Fix Option 1 as it's more robust and handles the reality that multiple details can exist for valid reasons (historical profit tracking).

## Proof of Concept

```csharp
[Fact]
public async Task TokenHolder_DoS_After_Partial_Removal_Test()
{
    // Setup: Create scheme and add beneficiary with 1000 shares
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF"
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
    
    // Partial removal creates 2 profit details
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
    profitDetails.Details.Count.ShouldBe(2); // Historical + current detail
    
    // DoS: Attempting to add more shares throws InvalidOperationException
    var addException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Shares = 100
        });
    });
    addException.Message.ShouldContain("Sequence contains more than one element");
    
    // DoS: Attempting to remove more shares also throws InvalidOperationException  
    var removeException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = Starter,
            Amount = 10
        });
    });
    removeException.Message.ShouldContain("Sequence contains more than one element");
}
```

## Notes

This vulnerability demonstrates a subtle integration issue where the Profit contract's intentional design decision (preserving historical details for profit claiming) conflicts with the TokenHolder contract's simplifying assumption (exactly one detail per beneficiary). The issue is self-resolving but degrades user experience during the resolution period. While severity is low due to no fund loss, the high likelihood of occurrence through normal operations makes this a valid operational vulnerability requiring remediation.

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L344-356)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L376-383)
```csharp
        if (profitDetails.Details.Count != 0)
        {
            State.ProfitDetailsMap[scheme.SchemeId][beneficiary] = profitDetails;
        }
        else
        {
            State.ProfitDetailsMap[scheme.SchemeId].Remove(beneficiary);
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
