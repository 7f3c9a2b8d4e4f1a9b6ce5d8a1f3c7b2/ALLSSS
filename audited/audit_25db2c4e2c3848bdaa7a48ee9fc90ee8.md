### Title
TokenHolder Contract DoS Due to Stale ProfitDetails After Partial Beneficiary Removal

### Summary
When a beneficiary is partially removed from a TokenHolder scheme, `GetProfitDetails()` returns multiple profit details including historical entries marked as removed. The TokenHolder contract's `AddBeneficiary` and `RemoveBeneficiary` methods incorrectly assume exactly one detail exists, causing them to throw `InvalidOperationException` when `.Single()` is called. This creates a denial-of-service condition preventing users from modifying their staking positions.

### Finding Description

The root cause involves the interaction between the Profit contract's state management and the TokenHolder contract's assumptions:

**Profit Contract Behavior:**
When `RemoveBeneficiary` is called, the `RemoveProfitDetails` method handles removal logic. [1](#0-0)  If a beneficiary has unclaimed profits from past periods (LastProfitPeriod < CurrentPeriod), the detail is NOT removed from state. Instead, it is marked with `IsWeightRemoved=true` and has its `EndPeriod` shortened. [2](#0-1)  The beneficiary is only removed from the state map when all details are gone. [3](#0-2) 

**View Method Returns Unfiltered Data:**
The `GetProfitDetails()` view method directly returns the state map without filtering out removed details. [4](#0-3) 

**TokenHolder Partial Removal Creates Multiple Details:**
When `TokenHolderContract.RemoveBeneficiary` is called with a partial amount, it first removes the beneficiary entirely, then re-adds them with reduced shares. [5](#0-4)  This results in the beneficiary having TWO profit details as confirmed by test assertions. [6](#0-5) 

**Integration Bug - Invalid Single() Assumptions:**
The TokenHolder contract has two critical locations that incorrectly assume exactly one detail exists:

1. In `AddBeneficiary`, after fetching details but before processing: [7](#0-6)  The code calls `.Single()` on line 55, which throws when multiple details exist.

2. In `RemoveBeneficiary`, when retrieving the current shares: [8](#0-7)  The code calls `.Single()` on line 78, which throws when multiple details exist.

### Impact Explanation

**Operational DoS:**
Once a beneficiary undergoes a partial removal operation (which creates 2 details), any subsequent attempts to call `AddBeneficiary` or `RemoveBeneficiary` for that beneficiary will fail with an `InvalidOperationException`. This prevents users from:
- Adding additional shares to their staking position
- Removing additional shares from their staking position
- Completely removing their beneficiary status

**Affected Users:**
Any TokenHolder scheme user who performs a partial share removal becomes unable to modify their position through normal contract operations until:
- They manually claim all historical profits (clearing the old detail)
- The old detail expires past its `ProfitReceivingDuePeriodCount`

**No Fund Loss:**
Importantly, no funds are stolen or permanently locked. Users retain ownership of their shares and can still claim profits. The issue is purely operational, preventing position modifications.

**Severity: LOW**
The vulnerability has low severity because:
- No fund theft or permanent loss occurs
- It's self-resolving (temporary until old details expire or are claimed)
- Users can still claim their profits
- Affects specific contract operations, not the entire protocol

### Likelihood Explanation

**High Likelihood:**
This vulnerability is highly likely to occur in normal operations:

**Reachable Entry Point:** Both `AddBeneficiary` and `RemoveBeneficiary` are public methods accessible to scheme managers and the TokenHolder contract itself.

**Feasible Preconditions:** Partial removals are a standard feature explicitly tested in the codebase. [9](#0-8)  Users performing partial unstaking operations will naturally trigger this condition.

**Execution Practicality:** The vulnerability triggers automatically through normal user workflows:
1. User stakes tokens (AddBeneficiary)
2. User partially unstakes (RemoveBeneficiary with Amount parameter)
3. User attempts to modify position again (AddBeneficiary or RemoveBeneficiary)
4. Operation fails with exception

**No Malicious Intent Required:** This is not an attack scenario but rather a design flaw that surfaces during legitimate operations.

### Recommendation

**Immediate Fix - Handle Multiple Details:**

1. In `TokenHolderContract.AddBeneficiary`, replace `.Single()` with proper multi-detail handling:
```csharp
// Instead of: shares.Add(detail.Details.Single().Shares);
// Use: shares.Add(detail.Details.Sum(d => d.Shares));
```

2. In `TokenHolderContract.RemoveBeneficiary`, sum all detail shares:
```csharp
// Instead of: var lockedAmount = detail.Shares;
// Use: var lockedAmount = detail.Details.Sum(d => d.Shares);
```

**Alternative Fix - Filter Before Use:**
Query details after removal operation rather than relying on stale fetched data.

**Invariant Checks:**
Add assertions in TokenHolder methods to validate detail count expectations or handle multiple details gracefully.

**Regression Test:**
Create a test case that:
1. Adds beneficiary with shares
2. Performs partial removal
3. Attempts AddBeneficiary or RemoveBeneficiary again
4. Verifies operations succeed without exceptions

### Proof of Concept

**Initial State:**
- TokenHolder scheme exists with ELF token
- User A has no beneficiary status

**Exploitation Steps:**

1. **Add Initial Shares:**
   Call `TokenHolderContract.AddBeneficiary(Beneficiary=UserA, Shares=1000)`
   - Result: UserA has 1 profit detail with 1000 shares

2. **Partial Removal:**
   Call `TokenHolderContract.RemoveBeneficiary(Beneficiary=UserA, Amount=100)`
   - Result: UserA has 2 profit details
   - Detail 1: 1000 shares, EndPeriod=0, IsWeightRemoved=true (confirmed by test assertion) [6](#0-5) 
   - Detail 2: 900 shares, active

3. **Trigger DoS:**
   Call `TokenHolderContract.AddBeneficiary(Beneficiary=UserA, Shares=500)`
   - Expected: Add 500 shares to UserA's position
   - Actual: `InvalidOperationException` thrown at `.Single()` call [10](#0-9) 
   - UserA cannot modify their staking position

**Success Condition:**
The operation fails with an exception, confirming the denial-of-service condition. This can be verified by checking transaction failure status or catching the `InvalidOperationException` in a test environment.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L40-56)
```csharp
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        var shares = input.Shares;
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
