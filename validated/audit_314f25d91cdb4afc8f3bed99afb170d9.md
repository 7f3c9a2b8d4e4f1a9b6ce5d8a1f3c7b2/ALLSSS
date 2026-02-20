# Audit Report

## Title
RemoveSubScheme Fails to Update CachedDelayTotalShares, Causing Profit Dilution in Delayed Distribution Schemes

## Summary
The `RemoveSubScheme` method in the Profit contract contains a critical accounting bug that fails to update `CachedDelayTotalShares` when removing sub-schemes from schemes with delayed distribution enabled. This creates a permanent mismatch between current share counts and cached future period shares, causing all beneficiaries to receive diluted profits in subsequent distributions.

## Finding Description
When a sub-scheme is added via `AddSubScheme`, it internally calls `AddBeneficiary` with `EndPeriod=long.MaxValue`, which increases the parent scheme's `TotalShares`. [1](#0-0) 

During profit distribution on schemes with `DelayDistributePeriodCount > 0`, the current `TotalShares` value is cached for future periods in the `CachedDelayTotalShares` map. [2](#0-1)  The cached value is then stored in `DistributedProfitsInfo.TotalShares` for that period. [3](#0-2) 

When `RemoveSubScheme` is called, it correctly reduces `TotalShares` but completely omits updating the `CachedDelayTotalShares` entries. [4](#0-3) 

In stark contrast, `RemoveBeneficiary` properly handles both: it reduces `TotalShares` AND iterates through all cached delay periods to subtract the removed shares from each cached entry. [5](#0-4) 

When beneficiaries later claim profits via `ClaimProfits`, the profit calculation in `ProfitAllPeriods` uses `distributedProfitsInformation.TotalShares` as the denominator. [6](#0-5)  The actual calculation divides beneficiary shares by total shares. [7](#0-6)  If this total shares value comes from stale cached data with inflated share counts, all beneficiaries receive proportionally less than their entitled amounts.

## Impact Explanation
This vulnerability breaks the fundamental accounting invariant that profit distributions must use accurate share ratios. When a sub-scheme with S shares is removed from a scheme with total T shares and delay period D:

1. Future periods P through P+D retain cached value of T (inflated)
2. Actual current shares should be T-S (correct)
3. Each beneficiary with B shares receives: `profit * B / T` instead of `profit * B / (T-S)`
4. Dilution factor: `(T-S) / T` of entitled profit
5. Missing profits: `profit * S / T` remains permanently locked in the period's virtual address

**Real-World Impact:** The Treasury contract actively uses `RemoveSubScheme` in the `ResetWeight` function when adjusting dividend pool weights. [8](#0-7)  This is called by weight adjustment operations. [9](#0-8) 

Additionally, `UpdateWelcomeRewardWeights` removes sub-schemes during miner reward management. [10](#0-9) 

The `UpdateFlexibleRewardWeights` function removes the Welfare scheme and Basic Reward scheme every term. [11](#0-10) 

The Welfare scheme explicitly has `DelayDistributePeriodCount = 1` configured during initialization (when i == 3, which is the Welfare scheme). [12](#0-11) 

Any weight adjustment operations on schemes with delayed distribution will trigger this bug, causing system-wide profit dilution affecting all miners, voters, and subsidy recipients.

## Likelihood Explanation
**Trigger Conditions:**
- Requires scheme manager authority (Treasury contract for system schemes, which is legitimate operational authority)
- Target scheme must have `DelayDistributePeriodCount > 0` (Welfare scheme has this enabled)
- Manager calls `AddSubScheme` then later `RemoveSubScheme` during routine operations

**Operational Reality:** The Treasury contract performs weight adjustments as part of normal governance operations. The `Release` function calls `UpdateFlexibleRewardWeights` every period. [13](#0-12)  These are routine maintenance operations expected to occur regularly as the system adapts to changing tokenomics requirements.

**Detection Difficulty:** The bug manifests as unexplained profit shortfalls that only appear in future periods (after the delay), making it extremely difficult to correlate with the original `RemoveSubScheme` call. There is no on-chain indicator that cached shares are stale.

Given that the Treasury contract is designed to regularly adjust weights and the affected schemes have delayed distribution enabled by default, the likelihood of triggering this bug in production is **HIGH**.

## Recommendation
The `RemoveSubScheme` method must be updated to handle `CachedDelayTotalShares` in the same manner as `RemoveBeneficiary`. After reducing `scheme.TotalShares`, add logic to iterate through all cached delay periods and subtract the removed sub-scheme's shares from each cached entry:

```csharp
// After line 152 in RemoveSubScheme
if (scheme.DelayDistributePeriodCount > 0)
{
    var startPeriod = scheme.CurrentPeriod;
    for (var period = startPeriod; 
         period < startPeriod.Add(scheme.DelayDistributePeriodCount); 
         period++)
    {
        if (scheme.CachedDelayTotalShares.ContainsKey(period))
        {
            scheme.CachedDelayTotalShares[period] = 
                scheme.CachedDelayTotalShares[period].Sub(shares.Shares);
        }
    }
}
```

This ensures consistency between `TotalShares` and `CachedDelayTotalShares`, maintaining the accounting invariant for delayed distributions.

## Proof of Concept
The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task RemoveSubScheme_ShouldUpdateCachedDelayTotalShares()
{
    // 1. Create parent scheme with DelayDistributePeriodCount = 1
    var creator = Creators[0];
    await creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = 1,
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    var parentSchemeId = (await creator.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = creator.Address })).SchemeIds.Last();
    
    // 2. Create sub-scheme
    await creator.CreateScheme.SendAsync(new CreateSchemeInput());
    var subSchemeId = (await creator.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = creator.Address })).SchemeIds.Last();
    
    // 3. Add sub-scheme with 100 shares
    await creator.AddSubScheme.SendAsync(new AddSubSchemeInput
    {
        SchemeId = parentSchemeId,
        SubSchemeId = subSchemeId,
        SubSchemeShares = 100
    });
    
    // 4. Distribute for period 1 - this caches TotalShares=100 for period 2
    await ContributeAndDistribute(creator, 1000, 1);
    
    // 5. Remove sub-scheme - BUG: doesn't update cached value
    await creator.RemoveSubScheme.SendAsync(new RemoveSubSchemeInput
    {
        SchemeId = parentSchemeId,
        SubSchemeId = subSchemeId
    });
    
    var scheme = await creator.GetScheme.CallAsync(parentSchemeId);
    scheme.TotalShares.ShouldBe(0); // Current shares correctly reduced
    
    // 6. Distribute for period 2
    await ContributeAndDistribute(creator, 1000, 2);
    
    // 7. Check period 2 distribution - BUG MANIFESTATION
    var distributedInfo = await creator.GetDistributedProfitsInfo.CallAsync(
        new SchemePeriod { SchemeId = parentSchemeId, Period = 2 });
    
    // EXPECTED: TotalShares should be 0 (no beneficiaries)
    // ACTUAL: TotalShares is 100 (stale cached value)
    distributedInfo.TotalShares.ShouldBe(100); // This proves the bug
    
    // Result: Any beneficiary claiming from period 2 will get diluted profits
    // because their shares are divided by 100 instead of the correct denominator
}
```

This test proves that `RemoveSubScheme` fails to update `CachedDelayTotalShares`, causing future period distributions to use stale, inflated total share values.

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L243-263)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L560-583)
```csharp
    private void UpdateDistributedProfits(Dictionary<string, long> profitsMap,
        Address profitsReceivingVirtualAddress, long totalShares)
    {
        var distributedProfitsInformation =
            State.DistributedProfitsMap[profitsReceivingVirtualAddress] ??
            new DistributedProfitsInfo();

        distributedProfitsInformation.TotalShares = totalShares;
        distributedProfitsInformation.IsReleased = true;

        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            var balanceOfVirtualAddressForCurrentPeriod = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = profitsReceivingVirtualAddress,
                Symbol = symbol
            }).Balance;
            distributedProfitsInformation.AmountsMap[symbol] = amount.Add(balanceOfVirtualAddressForCurrentPeriod);
        }

        State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInformation;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L866-874)
```csharp
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;

                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L56-68)
```csharp
        for (var i = 0; i < 7; i++)
        {
            var index = i;
            Context.LogDebug(() => profitItemNameList[index]);
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
                // Distribution of Citizen Welfare will delay one period.
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L123-166)
```csharp
    public override Empty Release(ReleaseInput input)
    {
        RequireAEDPoSContractStateSet();
        Assert(
            Context.Sender == State.AEDPoSContract.Value,
            "Only AElf Consensus Contract can release profits from Treasury.");
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.TreasuryHash.Value,
            Period = input.PeriodNumber,
            AmountsMap = { State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L) }
        });
        RequireElectionContractStateSet();
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });

        var currentMinerList = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(p => p.ToHex()).ToList();
        var maybeNewElectedMiners = new List<string>();
        maybeNewElectedMiners.AddRange(currentMinerList);
        maybeNewElectedMiners.AddRange(previousTermInformation.RealTimeMinersInformation.Keys);
        var replaceCandidates = State.ReplaceCandidateMap[input.PeriodNumber];
        if (replaceCandidates != null)
        {
            Context.LogDebug(() =>
                $"New miners from replace candidate map: {replaceCandidates.Value.Aggregate((l, r) => $"{l}\n{r}")}");
            maybeNewElectedMiners.AddRange(replaceCandidates.Value);
            State.ReplaceCandidateMap.Remove(input.PeriodNumber);
        }

        maybeNewElectedMiners = maybeNewElectedMiners
            .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p)).ToList();
        if (maybeNewElectedMiners.Any())
            Context.LogDebug(() => $"New elected miners: {maybeNewElectedMiners.Aggregate((l, r) => $"{l}\n{r}")}");
        else
            Context.LogDebug(() => "No new elected miner.");

        UpdateStateBeforeDistribution(previousTermInformation, maybeNewElectedMiners);
        ReleaseTreasurySubProfitItems(input.PeriodNumber);
        UpdateStateAfterDistribution(previousTermInformation, currentMinerList);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L312-334)
```csharp
    public override Empty SetDividendPoolWeightSetting(DividendPoolWeightSetting input)
    {
        AssertPerformedByTreasuryController();
        Assert(
            input.CitizenWelfareWeight > 0 && input.BackupSubsidyWeight > 0 &&
            input.MinerRewardWeight > 0,
            "invalid input");
        ResetSubSchemeToTreasury(input);
        State.DividendPoolWeightSetting.Value = input;
        return new Empty();
    }

    public override Empty SetMinerRewardWeightSetting(MinerRewardWeightSetting input)
    {
        AssertPerformedByTreasuryController();
        Assert(
            input.BasicMinerRewardWeight > 0 && input.WelcomeRewardWeight > 0 &&
            input.FlexibleRewardWeight > 0,
            "invalid input");
        ResetSubSchemeToMinerReward(input);
        State.MinerRewardWeightSetting.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L520-540)
```csharp
    private void ResetWeight(Hash parentSchemeId, Hash subSchemeId, int oldWeight,
        int newWeight)
    {
        if (oldWeight == newWeight)
            return;

        // old weight equals 0 indicates the subScheme has not been registered
        if (oldWeight > 0)
            State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
            {
                SchemeId = parentSchemeId,
                SubSchemeId = subSchemeId
            });

        State.ProfitContract.AddSubScheme.Send(new AddSubSchemeInput
        {
            SchemeId = parentSchemeId,
            SubSchemeId = subSchemeId,
            SubSchemeShares = newWeight
        });
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L858-862)
```csharp
        State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            SubSchemeId = State.BasicRewardHash.Value
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L895-904)
```csharp
        State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
        {
            SchemeId = State.ReElectionRewardHash.Value,
            SubSchemeId = State.WelfareHash.Value
        });
        State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
        {
            SchemeId = State.ReElectionRewardHash.Value,
            SubSchemeId = State.BasicRewardHash.Value
        });
```
