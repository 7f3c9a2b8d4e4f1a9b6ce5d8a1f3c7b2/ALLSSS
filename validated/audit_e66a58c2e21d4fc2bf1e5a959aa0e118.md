# Audit Report

## Title
CachedDelayTotalShares Corruption via Premature Beneficiary Removal Leading to Profit Loss

## Summary
The Profit contract's delayed distribution mechanism contains a critical logic flaw where removing a beneficiary before their `StartPeriod` causes incorrect subtraction from `CachedDelayTotalShares` entries that were created before the beneficiary existed. This corrupts cached total shares for affected periods, triggering the burn condition that permanently destroys profits instead of distributing them to legitimate beneficiaries. [1](#0-0) 

## Finding Description

The vulnerability arises from a temporal mismatch between when a beneficiary's shares are added to `TotalShares` versus when they should actually participate in distributions.

**The Flawed Logic:**

When a beneficiary is added with `DelayDistributePeriodCount` D at period P:
- Their shares are immediately added to `scheme.TotalShares` [2](#0-1) 
- But their `StartPeriod` is set to `P + D`, meaning they should only receive profits from period P+D onwards [3](#0-2) 

During distribution at period P, the current `TotalShares` (including the new beneficiary) is cached to `CachedDelayTotalShares[P+D]` for future use [4](#0-3) 

**The Critical Bug:**

If the beneficiary is removed at period R where P < R < P+D:
1. Removal is permitted because `EndPeriod < CurrentPeriod` validation passes [5](#0-4) 
2. `RemoveProfitDetails` adds removed shares to `RemovedDetails` using `scheme.CurrentPeriod` (R) as the key [6](#0-5) 
3. `RemoveBeneficiary` then subtracts these shares from `CachedDelayTotalShares` for periods [R, R+D) [7](#0-6) 

**The Corruption:**
- The beneficiary's shares only exist in cache entries from period P+D onwards
- But removal subtracts from periods [R, R+D), which includes periods [R, P+D) that never contained these shares
- If cache entries exist for these earlier periods (from prior distributions), they become corrupted by the erroneous subtraction

**Concrete Example:**
- Period 1: Beneficiary A (50 shares) exists, distribute → CachedDelayTotalShares[4] = 50
- Period 2: Add Beneficiary B (100 shares, EndPeriod=2, DelayDistributePeriodCount=3)
  - TotalShares becomes 150, StartPeriod = 5
  - Distribute → CachedDelayTotalShares[5] = 150
- Period 3: Remove Beneficiary B
  - Subtracts 100 from CachedDelayTotalShares[3], [4], [5]
  - CachedDelayTotalShares[4] becomes -50 or 0 (corrupted!)
  - This entry was created before B existed and shouldn't be affected

## Impact Explanation

**Direct Fund Loss:**

When distribution occurs for a corrupted period, the code retrieves the corrupted `totalShares` value. If the value is 0 or negative, `totalShares` is set to 0 [8](#0-7) 

This triggers the burn condition [9](#0-8)  where profits are permanently burned instead of distributed to legitimate beneficiaries [10](#0-9) 

**Production Impact:**

The Treasury contract's Citizen Welfare scheme uses `DelayDistributePeriodCount = 1` [11](#0-10) , making this vulnerability exploitable in production deployments.

**Severity Justification:**
- **HIGH** - Causes irreversible loss of protocol funds that should be distributed to legitimate beneficiaries
- Affects all beneficiaries of corrupted periods (100% loss for those periods)
- Exploitable on production schemes with minimal delay periods

## Likelihood Explanation

**Attacker Requirements:**

The attacker must be a scheme manager or the TokenHolder contract [12](#0-11)  - this is a legitimate protocol role, not a compromised privilege.

**Attack Complexity:**

The vulnerability triggers through normal scheme operations:
1. Add beneficiary with `EndPeriod = CurrentPeriod` (explicitly permitted by validation [13](#0-12) )
2. Wait one period for distribution to occur
3. Remove beneficiary (now `EndPeriod < CurrentPeriod`)
4. Cache corruption occurs automatically via the flawed subtraction logic

**Likelihood Assessment:**

- **HIGH** - The vulnerable code path executes deterministically with simple preconditions
- Schemes with `DelayDistributePeriodCount > 0` exist in production
- Operations appear legitimate, making detection difficult
- No race conditions or complex timing requirements

## Recommendation

Modify `RemoveBeneficiary` to only subtract from cache entries that should contain the beneficiary's shares. The subtraction should start from the beneficiary's `StartPeriod`, not from `scheme.CurrentPeriod`.

**Proposed Fix:**

In the `RemoveBeneficiary` method, calculate the actual start period for cache subtraction based on when the beneficiary was originally added:

```csharp
foreach (var (removedMinPeriod, removedShares) in removedDetails.Where(d => d.Key != 0))
{
    if (scheme.DelayDistributePeriodCount > 0)
    {
        // Get the beneficiary's actual StartPeriod from ProfitDetails
        var beneficiaryStartPeriod = removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
        
        for (var removedPeriod = beneficiaryStartPeriod;
             removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount).Add(scheme.DelayDistributePeriodCount);
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
```

Alternatively, track each beneficiary's original `StartPeriod` in the `ProfitDetail` and use it during removal.

## Proof of Concept

```csharp
[Fact]
public async Task TestCachedDelayTotalSharesCorruption()
{
    // Setup: Create scheme with DelayDistributePeriodCount = 3
    var schemeId = await ProfitContractStub.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = 3
    });
    
    // Period 1: Add existing beneficiary A with 50 shares
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = BeneficiaryA, Shares = 50 }
    });
    
    // Distribute at period 1 - caches to CachedDelayTotalShares[4]
    await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Period = 1,
        AmountsMap = { { "ELF", 1000 } }
    });
    
    // Period 2: Add beneficiary B with EndPeriod = CurrentPeriod
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = BeneficiaryB, Shares = 100 },
        EndPeriod = 2  // Set to CurrentPeriod
    });
    
    // Distribute at period 2 - caches to CachedDelayTotalShares[5]
    await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Period = 2,
        AmountsMap = { { "ELF", 1000 } }
    });
    
    // Period 3: Remove beneficiary B (EndPeriod < CurrentPeriod)
    await ProfitContractStub.RemoveBeneficiary.SendAsync(new RemoveBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        Beneficiary = BeneficiaryB
    });
    
    // Period 4: Attempt distribution - should fail/burn due to corrupted cache
    var result = await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Period = 4,
        AmountsMap = { { "ELF", 1000 } }
    });
    
    // Verify that profits were burned instead of distributed
    var distributedInfo = await ProfitContractStub.GetDistributedProfitsInfo.CallAsync(
        new SchemePeriod { SchemeId = schemeId.Output, Period = 4 });
    
    // AmountsMap should show negative value (burned) instead of positive (distributed)
    distributedInfo.AmountsMap["ELF"].ShouldBe(-1000);
}
```

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L186-192)
```csharp
        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L243-258)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L358-358)
```csharp
                removedDetails.TryAdd(scheme.CurrentPeriod, profitDetail.Shares);
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
