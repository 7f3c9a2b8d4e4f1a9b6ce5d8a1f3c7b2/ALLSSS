# Audit Report

## Title
Cache Desynchronization in RemoveBeneficiary Causes Profit Distribution Loss for Delayed Share Schemes

## Summary
The `RemoveBeneficiary` function contains a critical desynchronization bug where shares expiring at the current period (Key=0 entries) are excluded from `CachedDelayTotalShares` updates but still subtracted from `TotalShares`. This causes `DistributeProfits` to use inflated cached values, resulting in beneficiaries receiving significantly less profit than deserved with remaining tokens permanently locked in period virtual addresses.

## Finding Description

The vulnerability exists in the interaction between `RemoveBeneficiary` and `RemoveProfitDetails` functions when handling shares with `EndPeriod == CurrentPeriod` in schemes configured with `DelayDistributePeriodCount > 0`.

**Root Cause Analysis:**

In `RemoveProfitDetails`, shares that expire at the current period are specifically identified and added to the `removedDetails` dictionary with Key=0 (representing the current period): [1](#0-0) 

However, in `RemoveBeneficiary`, the code that updates the cached delay shares explicitly filters out Key=0 entries: [2](#0-1) 

Despite this exclusion from cache updates, ALL shares (including Key=0) are subtracted from `TotalShares`: [3](#0-2) 

**Why The Cached Value Becomes Stale:**

The delayed distribution mechanism caches future `TotalShares` values. During earlier periods, `DistributeProfits` stores the current `TotalShares` for future use: [4](#0-3) 

When the future period arrives and shares with `EndPeriod == CurrentPeriod` are removed via `RemoveBeneficiary`, the cache is NOT updated due to the Key=0 filter. However, `DistributeProfits` still uses this stale cached value (line 469), which includes shares that no longer exist.

**Execution Flow:**

1. Period P-2: `DistributeProfits` caches `CachedDelayTotalShares[P] = 100` (includes shares that will expire at period P)
2. Period P: Manager calls `RemoveBeneficiary` for beneficiary with `EndPeriod == P` 
3. `RemoveProfitDetails` identifies 50 shares expiring at current period, adds to `removedDetails[0] = 50`
4. `RemoveBeneficiary` loop excludes Key=0, so `CachedDelayTotalShares[P]` remains 100 (not updated)
5. `TotalShares` correctly reduced: `100 - 50 = 50`
6. `DistributeProfits` called for period P uses cached value 100 instead of actual 50
7. Profit calculation uses inflated denominator in `SafeCalculateProfits`: [5](#0-4) 

The calculation `shares * totalAmount / totalShares` divides by 100 instead of 50, causing beneficiaries to receive only 50% of their deserved profits.

## Impact Explanation

**Direct Financial Loss:**

This vulnerability causes quantifiable, permanent loss of funds:
- Beneficiaries receive proportionally less profit based on the ratio of inflated vs actual shares
- In the example scenario (100 cached vs 50 actual shares), beneficiaries lose 50% of their deserved profits
- Remaining tokens are locked in the period's virtual address with no recovery mechanism

**Concrete Example:**
- Cached TotalShares: 100 (includes expired shares)
- Actual TotalShares: 50 (after removal)
- Amount to distribute: 1000 tokens
- Remaining beneficiary has 50 shares

Expected distribution: `50/50 * 1000 = 1000` tokens
Actual distribution: `50/100 * 1000 = 500` tokens
**Loss: 500 tokens (50%) permanently locked**

**Affected Systems:**

This impacts core AElf economic infrastructure:
- All profit schemes with `DelayDistributePeriodCount > 0`
- TokenHolder contract profit distributions
- Treasury contract reward mechanisms
- Any staking/reward schemes using delayed profit distribution

**Severity Justification: HIGH**
- Direct, permanent loss of user funds
- Affects critical profit distribution mechanism
- No on-chain recovery path for locked tokens
- Can occur unintentionally through normal management operations
- Violates core protocol invariant that all distributed profits should be claimable

## Likelihood Explanation

**Entry Point Accessibility:**

The vulnerable function is publicly accessible to authorized scheme managers: [6](#0-5) 

**Realistic Preconditions:**

1. Profit scheme must have `DelayDistributePeriodCount > 0` - This is a common configuration for staking and reward schemes to prevent immediate gaming
2. Beneficiary must have shares with `EndPeriod == CurrentPeriod` - Natural expiration scenario that occurs regularly
3. Manager calls `RemoveBeneficiary` before `DistributeProfits` in same period - Common operational pattern for cleanup

**Execution Practicality:**

- No special privileges beyond normal scheme manager role
- Occurs during routine beneficiary cleanup operations
- Transaction ordering (RemoveBeneficiary before DistributeProfits) is under manager control
- Common in automated systems managing time-limited staking periods
- Can happen accidentally without malicious intent

**Probability Assessment: MEDIUM-HIGH**

This is likely to occur because:
- Delayed distribution schemes are widely used in AElf
- Regular beneficiary expiration is normal operational flow
- Managers naturally remove expired beneficiaries before distributing
- No warnings or checks prevent this sequence
- Can be triggered repeatedly across multiple periods

## Recommendation

The fix requires updating `CachedDelayTotalShares` for Key=0 entries. Modify the `RemoveBeneficiary` function to handle shares expiring at the current period:

```csharp
foreach (var (removedMinPeriod, removedShares) in removedDetails)
{
    if (scheme.DelayDistributePeriodCount > 0)
    {
        // For current period removals (Key=0), update all future cached periods
        var startPeriod = removedMinPeriod == 0 ? scheme.CurrentPeriod : removedMinPeriod;
        
        for (var removedPeriod = startPeriod;
             removedPeriod < startPeriod.Add(scheme.DelayDistributePeriodCount);
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

This ensures that when shares expire at the current period (Key=0), their removal is properly reflected in all future cached periods, maintaining synchronization between cached values and actual TotalShares.

## Proof of Concept

```csharp
[Fact]
public async Task ProfitContract_CacheDesync_RemoveBeneficiary_CurrentPeriod_Test()
{
    const int delayDistributePeriodCount = 2;
    const long shareAmount = 100;
    var creator = Creators[0];
    var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);
    var beneficiaryA = Accounts[0].Address;
    var beneficiaryB = Accounts[1].Address;

    // Create scheme with delay
    var result = await creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = delayDistributePeriodCount,
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    var schemeId = result.Output;

    // Period 1: Add two beneficiaries
    // A expires at period 3, B is permanent
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = beneficiaryA, Shares = shareAmount },
        EndPeriod = 3
    });
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = beneficiaryB, Shares = shareAmount }
    });

    // Period 1: Distribute (caches TotalShares=200 for period 3)
    await creator.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId,
        Symbol = "ELF",
        Amount = 1000
    });
    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1
    });

    // Period 3: Remove A BEFORE distributing (EndPeriod == CurrentPeriod, so Key=0)
    await creator.RemoveBeneficiary.SendAsync(new RemoveBeneficiaryInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiaryA
    });

    var scheme = await creator.GetScheme.CallAsync(schemeId);
    // TotalShares correctly reduced to 100
    scheme.TotalShares.ShouldBe(shareAmount);
    // But CachedDelayTotalShares[3] still contains 200 (BUG!)
    scheme.CachedDelayTotalShares[3].ShouldBe(shareAmount * 2); // Cached value not updated

    // Period 3: Distribute
    await creator.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId,
        Symbol = "ELF",
        Amount = 1000,
        Period = 3
    });
    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 3
    });

    // Check distribution uses cached 200 instead of actual 100
    var distributedInfo = await creator.GetDistributedProfitsInfo.CallAsync(new SchemePeriod
    {
        SchemeId = schemeId,
        Period = 3
    });
    distributedInfo.TotalShares.ShouldBe(shareAmount * 2); // Uses inflated cached value!

    // B only receives 50% of deserved profits
    // Expected: 100/100 * 1000 = 1000
    // Actual: 100/200 * 1000 = 500
    // 500 tokens locked in period virtual address
}
```

**Notes:**

The vulnerability is confirmed through code analysis showing the exact desynchronization between `CachedDelayTotalShares` and `TotalShares` when shares expire at the current period. The filter `Where(d => d.Key != 0)` at line 243 is the direct cause, preventing proper cache updates while line 260 still reduces `TotalShares`. This breaks the invariant that cached values must accurately reflect future share states, resulting in permanent fund loss.

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L364-372)
```csharp
        var weightCanBeRemoved = profitDetails.Details
            .Where(d => d.EndPeriod == scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
        foreach (var profitDetail in weightCanBeRemoved)
        {
            profitDetail.IsWeightRemoved = true;
        }

        var weights = weightCanBeRemoved.Sum(d => d.Shares);
        removedDetails.Add(0, weights);
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
