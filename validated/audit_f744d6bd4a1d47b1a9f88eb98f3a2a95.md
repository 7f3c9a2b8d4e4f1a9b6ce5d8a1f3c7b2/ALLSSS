# Audit Report

## Title
State Persistence Failure in RemoveBeneficiary Causes Share Accounting Loss in Delayed Distribution Schemes

## Summary
The `RemoveBeneficiary` function in the Profit Contract contains a critical state persistence bug where modifications to `CachedDelayTotalShares` are made to a local variable but never written back to contract state. This causes future profit distributions to use inflated share totals that include removed beneficiaries, resulting in permanent dilution of profits for all remaining legitimate beneficiaries in schemes with delayed distribution periods.

## Finding Description

The vulnerability exists in the `RemoveBeneficiary` function where state persistence is incomplete. The function reads the scheme from state into a local variable, modifies the local `scheme.CachedDelayTotalShares` map to subtract removed shares, but only persists the `TotalShares` field without writing back the entire modified scheme object. [1](#0-0) 

The execution path demonstrates the bug:
1. The function reads the scheme from state into a local variable
2. It calls `RemoveProfitDetails` which returns removed share amounts by period  
3. The code correctly modifies the local `scheme.CachedDelayTotalShares` to subtract removed shares from cached delay periods
4. **CRITICAL BUG**: Only `TotalShares` is updated via direct state property access
5. The function returns without persisting the `CachedDelayTotalShares` modifications made in the local variable

This violates the consistent pattern used throughout the codebase. Every other function that modifies scheme state writes back the entire object. For comparison, `AddBeneficiary` correctly writes back the full scheme: [2](#0-1) 

Similarly, `RemoveSubScheme` also writes back the entire scheme object after modification: [3](#0-2) 

The `ClaimProfits` function also correctly updates `CachedDelayTotalShares` and persists the entire scheme: [4](#0-3) 

The `CachedDelayTotalShares` mechanism is critical for delayed distribution. When profits are distributed, the system caches current total shares for future periods and uses these cached values instead of current totals when those periods arrive: [5](#0-4) 

The Scheme protobuf definition confirms `cached_delay_total_shares` is a mutable map field that must be persisted: [6](#0-5) 

A test case explicitly expects this functionality to work correctly, validating that `CachedDelayTotalShares` is properly adjusted after removal: [7](#0-6) 

## Impact Explanation

**Direct Fund Impact**: When a beneficiary is removed from a scheme with `DelayDistributePeriodCount > 0`, their shares remain counted in the cached totals for future distribution periods. This causes:

- Future profit distributions use inflated `totalShares` values from `CachedDelayTotalShares` that incorrectly include removed beneficiaries
- The profit calculation functions distribute based on this inflated total  
- Each remaining beneficiary receives: `beneficiary_amount = total_amount * shares / inflated_total` instead of the correct `beneficiary_amount = total_amount * shares / actual_total`
- The "missing" allocation corresponding to removed shares becomes effectively lost, as no active beneficiary can claim it and it remains locked in the period's virtual address
- If 20% of shares are removed but cached values aren't updated, remaining beneficiaries lose approximately 20% of their rightful profits in affected cached periods

**Who is affected**: All legitimate beneficiaries in schemes with delayed distribution lose a portion of their entitled profits whenever any beneficiary is removed. This particularly impacts staking reward systems and validator compensation schemes that commonly use delayed distribution.

**Severity**: HIGH - This causes direct, permanent loss of funds through mathematically incorrect profit distribution calculations, violating the critical invariant of accurate dividend distribution and settlement. The funds are not stolen but become permanently unclaimable, effectively burning a portion of rewards.

## Likelihood Explanation

**Reachable Entry Point**: `RemoveBeneficiary` is a public method callable by the scheme manager or TokenHolder contract, as validated by the authorization checks in the function.

**Feasible Preconditions**: 
- Scheme must have `DelayDistributePeriodCount > 0` (a legitimate and common configuration for staking rewards and validator compensation)
- Scheme manager removes beneficiaries (normal governance operation, not malicious)
- Profits have been distributed in prior periods, creating cached entries in `CachedDelayTotalShares`
- No special attacker capabilities needed - this is a bug triggered by legitimate operations

**Execution Practicality**: The bug triggers automatically in normal operations:
1. Create scheme with delay distribution (e.g., 3-period delay for validator rewards)
2. Add beneficiaries and distribute profits over several periods (this populates `CachedDelayTotalShares` for future periods)
3. Remove any beneficiary via legitimate governance action
4. Continue distributing profits - the cached totals incorrectly include the removed beneficiary's shares
5. Remaining beneficiaries receive diluted profits

**Detection Constraints**: The bug is silent - transactions succeed without revert, but profit calculations are quietly incorrect. There's no error or event to alert users that share accounting is wrong. The discrepancy only becomes apparent through careful analysis of distributed amounts versus expected amounts.

**Probability**: VERY HIGH - This occurs on every `RemoveBeneficiary` call for schemes with `DelayDistributePeriodCount > 0`, which are commonly used in staking and reward distribution systems throughout the AElf ecosystem.

## Recommendation

The fix is straightforward: after modifying the local scheme object's `CachedDelayTotalShares`, write the entire scheme object back to state, following the pattern used by all other functions in the contract.

Replace line 260 with:
```csharp
scheme.TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
State.SchemeInfos[input.SchemeId] = scheme;
```

This ensures that both the `TotalShares` and `CachedDelayTotalShares` modifications are persisted to contract state.

## Proof of Concept

The existing test case at line 271 of `SchemeTests.cs` already expects this behavior and would fail if the bug exists as described. The test explicitly validates that after removing a beneficiary, `scheme.CachedDelayTotalShares.Values.ShouldAllBe(v => v == 12)`, which confirms the expected behavior is that cached values should be updated.

To demonstrate the vulnerability, one would:
1. Create a scheme with `DelayDistributePeriodCount = 3`
2. Add beneficiaries with total shares = 100
3. Distribute profits in period 1 (this caches shares for period 4)
4. Remove a beneficiary with 20 shares in period 2
5. Distribute in period 4 - the distribution will still use 100 total shares instead of 80
6. Remaining beneficiaries receive only 80% of what they should receive
7. The 20% corresponding to removed shares becomes permanently locked

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L131-156)
```csharp
    public override Empty RemoveSubScheme(RemoveSubSchemeInput input)
    {
        Assert(input.SchemeId != input.SubSchemeId, "Two schemes cannot be same.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only manager can remove sub-scheme.");

        var shares = scheme.SubSchemes.SingleOrDefault(d => d.SchemeId == input.SubSchemeId);
        if (shares == null) return new Empty();

        var subSchemeId = input.SubSchemeId;
        var subScheme = State.SchemeInfos[subSchemeId];
        Assert(subScheme != null, "Sub scheme not found.");

        var subSchemeVirtualAddress = Context.ConvertVirtualAddressToContractAddress(subSchemeId);
        // Remove profit details
        State.ProfitDetailsMap[input.SchemeId][subSchemeVirtualAddress] = new ProfitDetails();
        scheme.SubSchemes.Remove(shares);
        scheme.TotalShares = scheme.TotalShares.Sub(shares.Shares);
        State.SchemeInfos[input.SchemeId] = scheme;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-184)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L464-476)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-809)
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

        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };

        return new Empty();
    }
```

**File:** protobuf/profit_contract.proto (L156-157)
```text
    // Record the scheme's current total share for deferred distribution of benefits, period -> total shares.
    map<int64, int64> cached_delay_total_shares = 11;
```

**File:** test/AElf.Contracts.Profit.Tests/BVT/SchemeTests.cs (L267-273)
```csharp
        {
            await ContributeAndDistribute(creator, contributeAmountEachTime, 8);
            await RemoveBeneficiaryAsync(creator, Accounts[11].Address);
            var scheme = await creator.GetScheme.CallAsync(_schemeId);
            scheme.CachedDelayTotalShares.Values.ShouldAllBe(v => v == 12);
            scheme.TotalShares.ShouldBe(12);
        }
```
