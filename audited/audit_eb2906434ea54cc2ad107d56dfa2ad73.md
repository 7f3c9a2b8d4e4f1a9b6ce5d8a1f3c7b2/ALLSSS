# Audit Report

## Title
State Inconsistency in AddSubScheme: TotalShares Update Lost Due to Stale State Overwrite

## Summary
The `AddSubScheme` function in the Profit contract contains a critical state management flaw where it loads the scheme state at the beginning, calls `AddBeneficiary` (which updates and saves `TotalShares`), but then overwrites this update by saving its original stale copy. This causes sub-schemes to be registered without their shares being counted in `TotalShares`, resulting in incorrect profit distribution calculations that allocate excess funds to sub-schemes at the expense of other beneficiaries.

## Finding Description

The vulnerability exists in the `AddSubScheme` function's state management sequence. [1](#0-0) 

The function first loads the scheme into a local variable, then calls `AddBeneficiary`: [2](#0-1) 

Inside `AddBeneficiary`, a fresh copy of the scheme is loaded, `TotalShares` is incremented, and the updated scheme is saved back to state: [3](#0-2) 

The critical issue occurs when `AddSubScheme` continues execution after `AddBeneficiary` returns. It modifies the `SubSchemes` collection on the stale local variable (which still contains the original `TotalShares` value from line 96), then saves this stale copy back to state, completely overwriting the `TotalShares` update: [4](#0-3) 

This creates an inconsistent state where:
- The sub-scheme entry exists in `scheme.SubSchemes`
- The beneficiary details exist in `State.ProfitDetailsMap[schemeId][subSchemeVirtualAddress]`
- BUT `scheme.TotalShares` does NOT include the sub-scheme's shares

## Impact Explanation

This vulnerability causes direct fund misallocation during every profit distribution. When `DistributeProfits` is called, it uses the corrupted `TotalShares` value: [5](#0-4) 

This incorrect `totalShares` is then passed to `DistributeProfitsForSubSchemes`, which calculates each sub-scheme's portion using the understated denominator: [6](#0-5) 

**Concrete Impact:**
- Sub-schemes receive disproportionately large shares because the calculation is `(subSchemeShares / totalShares) * totalAmount` where `totalShares` is missing the sub-scheme's own contribution
- Other beneficiaries receive less than their entitled share as the remaining amount is reduced
- Each `AddSubScheme` call compounds the problem
- No recovery mechanism exists to fix the corrupted state

**Example:** If a scheme has 100 shares and adds a sub-scheme with 50 shares:
- Expected TotalShares: 150
- Actual TotalShares after bug: 100
- When distributing 1000 tokens, sub-scheme receives: (50/100) * 1000 = 500 tokens
- Correct amount should be: (50/150) * 1000 = 333 tokens
- Sub-scheme steals ~167 tokens per distribution from other beneficiaries

## Likelihood Explanation

**Exploitability: HIGH**

The vulnerability triggers automatically on every successful `AddSubScheme` call. The attacker only needs to be the scheme manager, which is a standard authorized role for scheme management operations. No special privileges, timing, or complex sequencing is required.

**Attack Complexity: TRIVIAL**

A scheme manager simply calls `AddSubScheme` through normal contract interaction. The bug executes deterministically in the standard code path without requiring race conditions or specific blockchain state.

**Feasibility: CERTAIN**

Sub-schemes are a core feature of the Profit contract system used for hierarchical profit distribution (e.g., Treasury → TokenHolder → Individual stakers). The vulnerable code path executes on every legitimate use of `AddSubScheme`. This is not an edge case but rather affects normal operations.

**Detection: SILENT**

The bug produces no error conditions or failed assertions. The sub-scheme appears properly registered on surface inspection. Only detailed mathematical analysis of subsequent profit distributions would reveal the discrepancy, and victims are unlikely to notice small percentage losses.

## Recommendation

Reload the scheme state after the `AddBeneficiary` call to ensure the local variable reflects the updated `TotalShares` value:

```csharp
public override Empty AddSubScheme(AddSubSchemeInput input)
{
    Assert(input.SchemeId != input.SubSchemeId, "Two schemes cannot be same.");
    Assert(input.SubSchemeShares > 0, "Shares of sub scheme should greater than 0.");

    var scheme = State.SchemeInfos[input.SchemeId];
    Assert(scheme != null, "Scheme not found.");
    Assert(Context.Sender == scheme.Manager, "Only manager can add sub-scheme.");
    Assert(scheme.SubSchemes.All(s => s.SchemeId != input.SubSchemeId),
        $"Sub scheme {input.SubSchemeId} already exist.");

    var subSchemeId = input.SubSchemeId;
    var subScheme = State.SchemeInfos[subSchemeId];
    Assert(subScheme != null, "Sub scheme not found.");

    var subSchemeVirtualAddress = Context.ConvertVirtualAddressToContractAddress(subSchemeId);
    
    AddBeneficiary(new AddBeneficiaryInput
    {
        SchemeId = input.SchemeId,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = subSchemeVirtualAddress,
            Shares = input.SubSchemeShares
        },
        EndPeriod = long.MaxValue
    });

    // RELOAD the scheme to get the updated TotalShares
    scheme = State.SchemeInfos[input.SchemeId];

    scheme.SubSchemes.Add(new SchemeBeneficiaryShare
    {
        SchemeId = input.SubSchemeId,
        Shares = input.SubSchemeShares
    });
    State.SchemeInfos[input.SchemeId] = scheme;

    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AddSubScheme_TotalSharesCorruption_Test()
{
    const long initialShares = 100;
    const long subSchemeShares = 50;
    
    var creator = Creators[0];
    
    // Create main scheme and add initial beneficiary
    var schemeId = await CreateSchemeAsync();
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare 
        { 
            Beneficiary = Accounts[0].Address, 
            Shares = initialShares 
        }
    });
    
    // Verify initial TotalShares
    var schemeBefore = await creator.GetScheme.CallAsync(schemeId);
    schemeBefore.TotalShares.ShouldBe(initialShares);
    
    // Create and add sub-scheme
    var subSchemeId = await CreateSchemeAsync(1);
    await creator.AddSubScheme.SendAsync(new AddSubSchemeInput
    {
        SchemeId = schemeId,
        SubSchemeId = subSchemeId,
        SubSchemeShares = subSchemeShares
    });
    
    // Check TotalShares after AddSubScheme
    var schemeAfter = await creator.GetScheme.CallAsync(schemeId);
    
    // BUG: TotalShares should be 150 (100 + 50) but will be 100 (stale overwrite)
    // This assertion will FAIL, proving the vulnerability:
    schemeAfter.TotalShares.ShouldBe(initialShares + subSchemeShares); // Expected: 150, Actual: 100
}
```

## Notes

This vulnerability affects the core profit distribution mechanism used throughout the AElf ecosystem. The stale state overwrite pattern is a classic concurrency bug that occurs in a sequential context due to improper state management. While the scheme manager role is required to trigger this bug, scheme managers are not considered fully trusted roles (unlike genesis/consensus/organization controllers), making this a valid security issue. The bug manifests silently and permanently corrupts the accounting state, causing continuous fund misallocation in all subsequent distributions.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L96-96)
```csharp
        var scheme = State.SchemeInfos[input.SchemeId];
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L109-118)
```csharp
        AddBeneficiary(new AddBeneficiaryInput
        {
            SchemeId = input.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = subSchemeVirtualAddress,
                Shares = input.SubSchemeShares
            },
            EndPeriod = long.MaxValue
        });
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L121-126)
```csharp
        scheme.SubSchemes.Add(new SchemeBeneficiaryShare
        {
            SchemeId = input.SubSchemeId,
            Shares = input.SubSchemeShares
        });
        State.SchemeInfos[input.SchemeId] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L166-184)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L462-462)
```csharp
        var totalShares = scheme.TotalShares;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L621-621)
```csharp
            var distributeAmount = SafeCalculateProfits(subSchemeShares.Shares, totalAmount, totalShares);
```
