# Audit Report

## Title
Cache Desynchronization in RemoveBeneficiary Causes Profit Distribution Loss for Delayed Share Schemes

## Summary
The `RemoveBeneficiary` function fails to update `CachedDelayTotalShares` for shares expiring at the current period while still subtracting these shares from `TotalShares`. This desynchronization causes `DistributeProfits` to use inflated cached share values, resulting in beneficiaries receiving less profit than deserved with remaining tokens permanently locked in period virtual addresses.

## Finding Description

The vulnerability exists in the interaction between `RemoveBeneficiary` and `RemoveProfitDetails` functions when handling shares with `EndPeriod == CurrentPeriod` in profit schemes configured with `DelayDistributePeriodCount > 0`.

**Root Cause:**

In `RemoveProfitDetails`, shares that expire at the current period are identified and added to `removedDetails` with Key=0. [1](#0-0) 

In `RemoveBeneficiary`, the code explicitly filters out Key=0 entries when updating the cache using `Where(d => d.Key != 0)`. [2](#0-1) 

However, ALL shares (including Key=0) are subtracted from `TotalShares` using `removedDetails.Values.Sum()`. [3](#0-2) 

**Why Existing Protections Fail:**

The cache mechanism stores future `TotalShares` values for delayed distribution. [4](#0-3) 

When a period arrives, `DistributeProfits` retrieves the cached value from `CachedDelayTotalShares` instead of using the current `TotalShares`. The cached value from previous periods includes shares that have since been removed with Key=0, causing an inflated denominator in profit calculations. [5](#0-4) 

**Execution Path:**

1. At period P-2: `DistributeProfits` caches `CachedDelayTotalShares[P] = 100` (includes shares expiring at period P)
2. At period P: Manager calls `RemoveBeneficiary` for shares with `EndPeriod == P` before calling `DistributeProfits`
3. `RemoveProfitDetails` adds these shares to `removedDetails[0]`
4. `RemoveBeneficiary` skips updating cache (line 243 filter excludes Key=0)
5. `TotalShares` reduced to 50
6. `DistributeProfits` uses cached value 100 instead of actual 50
7. Profit calculation uses inflated denominator

The cached TotalShares value is stored in `distributedProfitsInformation`. [6](#0-5) 

The profit calculation occurs in `ProfitAllPeriods` using this stored `TotalShares` value. [7](#0-6) 

The calculation logic divides beneficiary shares by the total shares to determine profit amounts. [8](#0-7) 

## Impact Explanation

**Direct Fund Impact:**
- Legitimate beneficiaries receive proportionally less of their deserved profits when cached shares exceed actual shares
- Remaining tokens are locked in the period's virtual address and become permanently unclaimable
- This is a direct, quantifiable loss of funds for all active beneficiaries in the affected scheme

**Quantified Damage:**
If a scheme has:
- 100 shares cached at period P
- 50 shares removed with Key=0 before distribution at period P
- 1000 tokens to distribute at period P

Each remaining beneficiary with 50 shares should receive: `50/50 * 1000 = 1000` tokens
But receives: `50/100 * 1000 = 500` tokens
**Loss per beneficiary: 500 tokens (50%)**

**Who Is Affected:**
- All beneficiaries in profit schemes with `DelayDistributePeriodCount > 0`
- Particularly schemes where managers regularly call `RemoveBeneficiary` for expired shares
- Core AElf economic components (TokenHolder, Treasury) that use delayed profit distribution

**Severity Justification: HIGH**
- Direct, quantifiable loss of funds with no recovery mechanism
- Affects core profit distribution mechanism used throughout AElf ecosystem
- Tokens become permanently locked in period virtual addresses
- Can occur through normal operational flows without malicious intent

## Likelihood Explanation

**Reachable Entry Point:**
`RemoveBeneficiary` is a public function callable by scheme manager or TokenHolder contract. [9](#0-8) 

**Feasible Preconditions:**
1. Profit scheme must have `DelayDistributePeriodCount > 0` (common configuration for staking and reward schemes)
2. Beneficiary shares must have `EndPeriod == CurrentPeriod` (natural expiration scenario)
3. Manager calls `RemoveBeneficiary` before `DistributeProfits` in the same period (under manager control)

**Execution Practicality:**
- No special privileges required beyond normal manager operations
- Can occur during routine cleanup of expired beneficiaries
- Transaction ordering is under manager control
- Common in automated systems that remove expired shares before distributing

**Economic Rationality:**
- Can occur unintentionally through normal operations
- No attack cost beyond normal transaction fees
- If intentional, manager could exploit to retain tokens in virtual addresses

**Probability Assessment: MEDIUM-HIGH**
- Requires specific timing but occurs in normal operational flows
- More likely in schemes with frequent beneficiary turnover
- Can be triggered accidentally by managers cleaning up expired shares before distribution

## Recommendation

Modify `RemoveBeneficiary` to include shares with Key=0 when updating `CachedDelayTotalShares`. The filter on line 243 should be removed or adjusted to handle the current period case:

```csharp
foreach (var (removedMinPeriod, removedShares) in removedDetails)
{
    if (scheme.DelayDistributePeriodCount > 0)
    {
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

This ensures that shares expiring at the current period (Key=0) properly update the cached values for the current and future delay periods.

## Proof of Concept

```csharp
[Fact]
public async Task CacheDesynchronization_RemoveBeneficiary_Test()
{
    const long delayPeriodCount = 2;
    const long beneficiaryShares = 50;
    
    // Create scheme with delay distribution
    var schemeId = await CreateScheme(delayPeriodCount);
    
    // Add beneficiary with shares expiring at period 3
    await AddBeneficiary(schemeId, DefaultSender, beneficiaryShares, endPeriod: 3);
    
    // Period 1: Distribute profits - caches TotalShares[3] = 50
    await DistributeProfits(schemeId, period: 1, amount: 1000);
    
    // Verify cache was created for period 3
    var schemeBeforeRemove = await GetScheme(schemeId);
    schemeBeforeRemove.CachedDelayTotalShares[3].ShouldBe(beneficiaryShares);
    
    // Period 3: Remove beneficiary BEFORE distributing
    await SetCurrentPeriod(schemeId, 3);
    await RemoveBeneficiary(schemeId, DefaultSender);
    
    // Verify TotalShares was reduced but cache was NOT updated
    var schemeAfterRemove = await GetScheme(schemeId);
    schemeAfterRemove.TotalShares.ShouldBe(0); // Reduced
    schemeAfterRemove.CachedDelayTotalShares[3].ShouldBe(beneficiaryShares); // Still inflated!
    
    // Period 3: Distribute profits - uses inflated cached value
    await DistributeProfits(schemeId, period: 3, amount: 1000);
    
    // Verify distribution used wrong TotalShares
    var distributedInfo = await GetDistributedProfitsInfo(schemeId, 3);
    distributedInfo.TotalShares.ShouldBe(beneficiaryShares); // Should be 0!
    
    // Tokens are now locked in virtual address with no claimants
    var virtualAddress = await GetPeriodVirtualAddress(schemeId, 3);
    var balance = await GetBalance(virtualAddress);
    balance.ShouldBe(1000); // Locked forever
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-239)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L260-260)
```csharp
        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L567-567)
```csharp
        distributedProfitsInformation.TotalShares = totalShares;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L873-874)
```csharp
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
