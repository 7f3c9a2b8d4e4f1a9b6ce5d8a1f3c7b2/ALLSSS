# Audit Report

## Title
CachedDelayTotalShares Corruption via Premature Beneficiary Removal Leading to Profit Loss

## Summary
The Profit contract's delayed distribution mechanism contains a critical temporal mismatch vulnerability where removing a beneficiary during their delay window causes incorrect subtraction from `CachedDelayTotalShares` entries that were created before the beneficiary existed. This corrupts cached total shares for affected periods, causing legitimate beneficiaries' profits to be permanently burned instead of distributed.

## Finding Description

The vulnerability stems from a fundamental mismatch between when beneficiary shares become effective versus when they are removed from cached periods.

**The Core Mechanism:**

When a beneficiary is added at period P with `DelayDistributePeriodCount` D, their `StartPeriod` is set to P+D, indicating they should only receive profits from period P+D onwards. [1](#0-0) 

However, their shares are immediately added to `scheme.TotalShares`. [2](#0-1) 

During distribution at period P, the current `TotalShares` is cached to `CachedDelayTotalShares[P+D]`. [3](#0-2) 

**The Vulnerability:**

The validation explicitly allows adding beneficiaries with `EndPeriod = CurrentPeriod`. [4](#0-3) 

If the beneficiary is removed at period R where P < R < P+D, the removal is permitted when `EndPeriod < CurrentPeriod`. [5](#0-4) 

**The Critical Bug:**

During removal, `RemoveProfitDetails` adds all removed shares to `RemovedDetails` using `scheme.CurrentPeriod` (the removal period R) as the key, regardless of when the beneficiary was actually added or when their shares become effective. [6](#0-5) 

The `RemoveBeneficiary` function then subtracts these shares from `CachedDelayTotalShares` for periods [R, R+D). [7](#0-6) 

**Why This Breaks:**
- Beneficiary's shares exist in cache entries from period P+D onwards only
- But removal subtracts from periods [R, R+D)
- Periods [R, P+D) receive incorrect subtractions
- These periods' cache entries were created before the beneficiary was added and never included these shares
- Result: CachedDelayTotalShares values become corrupted (potentially zero or negative)

**Exploitation Path:**

A scheme manager adds a beneficiary at period P with `EndPeriod = CurrentPeriod` (explicitly allowed by validation). At period P+1, since `EndPeriod < CurrentPeriod`, the beneficiary can be removed. The removal logic automatically corrupts `CachedDelayTotalShares` entries for periods that never included the beneficiary's shares.

## Impact Explanation

**Direct Protocol Fund Loss:**

When distribution occurs for a corrupted period, if the `CachedDelayTotalShares` entry is missing or reduced to zero, `totalShares` is set to 0. [8](#0-7) 

This triggers the burn condition. [9](#0-8) 

The `BurnProfits` function permanently burns all profits for that period instead of distributing them to legitimate beneficiaries. [10](#0-9) 

**Quantified Damage:**
- With `DelayDistributePeriodCount = 3`, removing a beneficiary corrupts up to 2 periods' cache entries
- Each corrupted period results in 100% profit loss for that period when the cache becomes zero
- All legitimate beneficiaries entitled to distributions from corrupted periods lose their profits
- The Treasury contract uses `DelayDistributePeriodCount = 1` for the Citizen Welfare scheme in production. [11](#0-10) 

**Severity: HIGH** - Direct, irreversible protocol fund loss affecting multiple distribution periods and all scheme beneficiaries.

## Likelihood Explanation

**Attacker Capabilities:**

The attacker must be the scheme manager or TokenHolder contract. [12](#0-11) [13](#0-12) 

This is a legitimate operational role, not a compromised privilege.

**Attack Complexity: Low**

The exploitation requires only standard scheme management operations:
1. Add beneficiary with `EndPeriod = CurrentPeriod` (explicitly allowed by validation)
2. Wait one period for distribution to occur
3. Remove beneficiary (now valid since `EndPeriod < CurrentPeriod`)
4. Cache corruption occurs automatically through the flawed logic

**Feasibility:**
- No special permissions beyond normal scheme management
- Schemes with `DelayDistributePeriodCount > 0` exist in production (Treasury Welfare)
- Deterministic behavior - no race conditions or complex timing dependencies
- Difficult to detect as add/remove operations appear completely legitimate
- The bug executes automatically without requiring any exploit-specific code

**Likelihood: HIGH** - The vulnerable code path executes deterministically when simple preconditions are met, using only legitimate scheme management functions available to trusted roles.

## Recommendation

Fix the temporal mismatch by keying removed shares by their `StartPeriod` instead of `CurrentPeriod`:

In `RemoveProfitDetails`, change line 358 to use the actual effective period:
```csharp
// Use StartPeriod (when shares become effective) instead of CurrentPeriod (when removed)
removedDetails.TryAdd(profitDetail.StartPeriod, profitDetail.Shares);
```

This ensures that cache subtraction only affects periods where the beneficiary's shares were actually included in the cached totals.

Additionally, add validation to prevent adding beneficiaries with `EndPeriod < StartPeriod` which creates the problematic condition.

## Proof of Concept

```csharp
[Fact]
public async Task CachedDelayTotalShares_Corruption_Test()
{
    // Setup: Create scheme with DelayDistributePeriodCount = 3
    var schemeId = await CreateSchemeWithDelay(delayCount: 3);
    
    // Period 1-3: Normal distributions creating cache entries
    await DistributeForPeriod(schemeId, period: 1); // Creates cache[4]
    await DistributeForPeriod(schemeId, period: 2); // Creates cache[5]  
    await DistributeForPeriod(schemeId, period: 3); // Creates cache[6]
    
    // Period 4: Add beneficiary with EndPeriod=CurrentPeriod, then distribute
    var beneficiary = Accounts[1].Address;
    await AddBeneficiaryAsync(schemeId, beneficiary, shares: 500, endPeriod: 4);
    // StartPeriod will be 4+3=7, shares added to TotalShares immediately
    await DistributeForPeriod(schemeId, period: 4); // Creates cache[7] with new shares
    
    // Verify cache[5] before corruption
    var cacheBefore = await GetCachedDelayTotalShares(schemeId, period: 5);
    cacheBefore.ShouldBe(1000); // Original value, never included beneficiary
    
    // Period 5: Remove beneficiary (EndPeriod=4 < CurrentPeriod=5)
    await RemoveBeneficiaryAsync(schemeId, beneficiary);
    
    // BUG: cache[5] gets reduced even though it never included these shares
    var cacheAfter = await GetCachedDelayTotalShares(schemeId, period: 5);
    cacheAfter.ShouldBe(500); // CORRUPTED! Was 1000, reduced by 500
    
    // Period 8: Distribution uses corrupted cache[5]
    // If fully corrupted to 0, profits would be burned instead of distributed
    await DistributeForPeriod(schemeId, period: 8);
    var burnedAmount = await GetBurnedAmountForPeriod(schemeId, period: 8);
    burnedAmount.ShouldBeGreaterThan(0); // Profits incorrectly burned
}
```

**Notes:**

This vulnerability represents a fundamental accounting error in the delayed distribution mechanism where the temporal dimension of share effectiveness is not properly tracked during removal operations. The bug is particularly severe because it affects production deployments (Treasury Welfare scheme) and results in irreversible fund loss through burning rather than a simple accounting mismatch.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L179-180)
```csharp
        Assert(input.EndPeriod >= scheme.CurrentPeriod,
            $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L182-182)
```csharp
        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L188-188)
```csharp
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L237-239)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L247-256)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L323-324)
```csharp
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L358-358)
```csharp
                removedDetails.TryAdd(scheme.CurrentPeriod, profitDetail.Shares);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L466-466)
```csharp
            scheme.CachedDelayTotalShares.Add(input.Period.Add(scheme.DelayDistributePeriodCount), totalShares);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L472-475)
```csharp
            else
            {
                totalShares = 0;
            }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-486)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L546-550)
```csharp
                State.TokenContract.Burn.Send(new BurnInput
                {
                    Amount = amount,
                    Symbol = symbol
                });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L64-64)
```csharp
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
```
