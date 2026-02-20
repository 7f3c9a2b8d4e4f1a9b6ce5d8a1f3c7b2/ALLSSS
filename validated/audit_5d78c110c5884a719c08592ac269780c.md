# Audit Report

## Title
Cache Desynchronization in RemoveBeneficiary Causes Profit Distribution Loss for Delayed Share Schemes

## Summary
The `RemoveBeneficiary` function fails to update `CachedDelayTotalShares` for shares expiring at the current period, while still subtracting these shares from `TotalShares`. This causes `DistributeProfits` to use inflated cached values, resulting in beneficiaries receiving less profit than deserved with remaining tokens permanently locked in period virtual addresses.

## Finding Description

The vulnerability exists in the interaction between `RemoveBeneficiary` and `RemoveProfitDetails` functions when handling shares with `EndPeriod == CurrentPeriod` in schemes with `DelayDistributePeriodCount > 0`.

**Root Cause:**

In `RemoveProfitDetails`, shares that expire at the current period are identified and added to `removedDetails` with Key=0: [1](#0-0) 

In `RemoveBeneficiary`, the code filters out Key=0 entries when updating the cache using `Where(d => d.Key != 0)`: [2](#0-1) 

However, ALL shares (including Key=0) are subtracted from `TotalShares`: [3](#0-2) 

**Why Existing Protections Fail:**

The cache mechanism stores future `TotalShares` values for delayed distribution: [4](#0-3) 

When a period arrives, `DistributeProfits` uses the cached value if it exists rather than current `TotalShares` at line 469. The cached value from previous periods includes shares that have since been removed with Key=0, causing an inflated denominator in profit calculations.

**Execution Path:**

1. At period P-2: `DistributeProfits` caches `CachedDelayTotalShares[P] = 100` (includes shares expiring at period P)
2. At period P: Manager calls `RemoveBeneficiary` for shares with `EndPeriod == P` before calling `DistributeProfits`
3. `RemoveProfitDetails` adds these shares to `removedDetails[0]` (Key=0)
4. `RemoveBeneficiary` skips updating cache due to line 243 filter excluding Key=0
5. `TotalShares` reduced to 50 at line 260
6. `DistributeProfits` uses cached value 100 instead of actual 50
7. Profit calculation uses inflated denominator

The profit calculation stores the inflated total shares in the distributed profits information: [5](#0-4) 

Later when beneficiaries claim profits, the calculation retrieves this inflated value: [6](#0-5) 

The calculation logic divides by the inflated total shares: [7](#0-6) 

## Impact Explanation

**Direct Fund Impact:**
- Legitimate beneficiaries receive proportionally less of their deserved profits when cached shares exceed actual shares
- Remaining tokens are locked in the period's virtual address and become permanently unclaimable
- This is a direct loss of funds for all active beneficiaries in the scheme

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

**Severity Justification:** HIGH
- Direct, quantifiable loss of funds
- Affects core profit distribution mechanism
- No recovery mechanism for locked tokens in period virtual addresses
- Can occur through normal operational flows (not requiring malicious intent)

## Likelihood Explanation

**Reachable Entry Point:**
`RemoveBeneficiary` is a public function callable by scheme manager or TokenHolder contract: [8](#0-7) 

**Feasible Preconditions:**
1. Profit scheme must have `DelayDistributePeriodCount > 0` (common configuration for staking/rewards)
2. Beneficiary shares must have `EndPeriod == CurrentPeriod` (natural expiration scenario enabled by the AddBeneficiary function): [9](#0-8) 
3. Manager calls `RemoveBeneficiary` before `DistributeProfits` in the same period

**Execution Practicality:**
- No special privileges required beyond normal manager operations
- Can occur during routine cleanup of expired beneficiaries
- Transaction ordering (RemoveBeneficiary before DistributeProfits) is under manager control
- Common in automated systems that remove expired shares before distributing

**Economic Rationality:**
- Can occur unintentionally through normal operations
- No attack cost (normal transaction fees only)
- If intentional, manager could exploit to retain tokens (though marked as removed)

**Probability Assessment:** MEDIUM-HIGH
- Requires specific timing but occurs in normal operational flows
- More likely in schemes with frequent beneficiary turnover
- Can be triggered accidentally by managers cleaning up expired shares

## Recommendation

Modify the `RemoveBeneficiary` function to include Key=0 entries when updating `CachedDelayTotalShares`. The filter on line 243 should be removed or adjusted to handle shares expiring at the current period.

**Fixed code snippet:**
```csharp
// Update cache for ALL removed details, including those with Key=0
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

## Proof of Concept

```csharp
[Fact]
public async Task ProfitContract_CacheDesync_RemoveBeneficiary_BeforeDistribute()
{
    const int delayPeriodCount = 2;
    const long initialShares = 100;
    const long expiringSha res = 50;
    const long profitAmount = 1000;
    
    // Create scheme with delay
    var creator = Creators[0];
    await creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = delayPeriodCount,
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    var schemeId = (await creator.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = creator.GetAddress() })).SchemeIds.First();
    
    // Period 1: Add beneficiaries with different end periods
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = Accounts[1].Address, Shares = initialShares - expiringSha },
        EndPeriod = long.MaxValue // Permanent
    });
    
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = Accounts[2].Address, Shares = expiringShares },
        EndPeriod = 3 // Expires at period 3
    });
    
    // Distribute for period 1 - caches shares for period 3
    await TokenContract.Transfer.SendAsync(new TransferInput
    {
        To = Context.ConvertVirtualAddressToContractAddress(schemeId),
        Symbol = "ELF",
        Amount = profitAmount
    });
    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput { SchemeId = schemeId, Period = 1 });
    
    // Advance to period 3
    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput { SchemeId = schemeId, Period = 2 });
    
    // Period 3: Remove expiring beneficiary BEFORE distributing
    await creator.RemoveBeneficiary.SendAsync(new RemoveBeneficiaryInput
    {
        SchemeId = schemeId,
        Beneficiary = Accounts[2].Address
    });
    
    var scheme = await creator.GetScheme.CallAsync(schemeId);
    scheme.TotalShares.ShouldBe(initialShares - expiringShares); // 50
    
    // Distribute for period 3 - should use TotalShares=50 but uses cached 100
    await TokenContract.Transfer.SendAsync(new TransferInput
    {
        To = Context.ConvertVirtualAddressToContractAddress(schemeId),
        Symbol = "ELF",
        Amount = profitAmount
    });
    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput { SchemeId = schemeId, Period = 3 });
    
    var distributedInfo = await creator.GetDistributedProfitsInfo.CallAsync(new SchemePeriod { SchemeId = schemeId, Period = 3 });
    
    // BUG: TotalShares is 100 (cached) instead of 50 (actual)
    distributedInfo.TotalShares.ShouldBe(initialShares); // This will be 100 (wrong!)
    
    // Account[1] with 50 shares should get all 1000 tokens but gets only 500
    var profitAmount = await creator.GetProfitAmount.CallAsync(new GetProfitAmountInput
    {
        SchemeId = schemeId,
        Beneficiary = Accounts[1].Address,
        Symbol = "ELF"
    });
    
    // BUG: Gets 50/100 * 1000 = 500 instead of 50/50 * 1000 = 1000
    profitAmount.Value.ShouldBe(500); // Wrong! Should be 1000
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L179-192)
```csharp
        Assert(input.EndPeriod >= scheme.CurrentPeriod,
            $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);

        State.SchemeInfos[schemeId] = scheme;

        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };
```

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L560-570)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L864-874)
```csharp
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
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
