# Audit Report

## Title
RemoveSubScheme Fails to Update CachedDelayTotalShares Causing Incorrect Profit Distribution in Delayed Distribution Schemes

## Summary
The `RemoveSubScheme` function removes a sub-scheme's shares from `TotalShares` but fails to update `CachedDelayTotalShares`, unlike `RemoveBeneficiary` which correctly updates this cache. In schemes with delayed distribution (DelayDistributePeriodCount > 0), this causes future profit distributions to use inflated share counts, resulting in beneficiaries receiving less profit than entitled and funds becoming permanently locked in period virtual addresses.

## Finding Description

The vulnerability exists in the `RemoveSubScheme` function which only updates `TotalShares` but does not update `CachedDelayTotalShares`: [1](#0-0) 

In contrast, `RemoveBeneficiary` correctly updates `CachedDelayTotalShares` for all affected periods when removing shares: [2](#0-1) 

**Root Cause:**

The `CachedDelayTotalShares` map stores the total shares at each distribution period for schemes with delayed distribution. The proto definition confirms this field's purpose: [3](#0-2) 

When `DistributeProfits` is called with a delay, it caches the current `TotalShares` for use in future periods: [4](#0-3) 

When a delayed distribution period arrives, the cached value is stored in `DistributedProfitsInfo.TotalShares`: [5](#0-4) 

During profit claiming, beneficiaries receive their share calculated using this cached value as the denominator: [6](#0-5) 

The profit calculation formula divides by the total shares from the cached value: [7](#0-6) 

**Why Protections Fail:**

While `RemoveSubScheme` removes the sub-scheme from `scheme.SubSchemes` list and clears its `ProfitDetails`, it doesn't account for the already-cached share values in `CachedDelayTotalShares`. The removed sub-scheme won't receive distributions (it's removed from the SubSchemes list), but its shares remain in the cached denominator, causing all other beneficiaries to receive proportionally less.

## Impact Explanation

**Direct Financial Harm:**
Beneficiaries lose a portion of their entitled profits proportional to the removed sub-scheme's shares. For example, if a scheme has 100 total shares (50 from sub-scheme, 50 from beneficiaries), and the sub-scheme is removed before delayed distribution occurs, beneficiaries will receive only 50% of the distributed amount (50/100) instead of 100% (50/50), with the remaining 50% locked permanently in the period's virtual address.

**Fund Lock:**
The "missing" tokens cannot be recovered because:
1. The removed sub-scheme's `ProfitDetails` are cleared and cannot claim
2. Other beneficiaries already calculated their shares using the inflated denominator
3. No mechanism exists to redistribute unclaimed profits from period virtual addresses (confirmed by codebase search)

**Affected Parties:**
- All remaining beneficiaries in schemes with delayed distribution after a sub-scheme removal
- Token holders relying on accurate profit distribution from staking or voting schemes
- Protocol treasury and reward distribution mechanisms

**Severity Justification:**
HIGH severity due to:
- Permanent loss of funds (tokens locked forever)
- Affects core economic mechanism (profit distribution)
- Can be triggered by normal operations (scheme manager removing sub-schemes)
- No recovery mechanism exists

## Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is triggered through the public `RemoveSubScheme` method callable by the scheme manager: [8](#0-7) 

**Feasible Preconditions:**
1. Scheme must have `DelayDistributePeriodCount > 0` (confirmed as common feature in tests)
2. Scheme manager removes a sub-scheme during the delay period
3. Future distributions occur using cached shares from before the removal

**Execution Practicality:**
- No special privileges needed beyond being the scheme manager (legitimate role)
- Standard contract operations with no unusual parameters
- Delayed distribution is a real feature as demonstrated in existing tests: [9](#0-8) 

**Economic Rationality:**
The vulnerability occurs during normal operations without malicious intent. A scheme manager may legitimately need to remove a sub-scheme (e.g., a voting scheme deciding to stop delegating profits to a sub-pool), unaware of the financial consequences.

**Detection Difficulty:**
The bug is not immediately visible as:
- The transaction succeeds without error
- Effects only manifest in future distribution periods
- Requires comparing expected vs actual profit amounts across multiple periods
- No test coverage exists for `RemoveSubScheme` with delayed distribution (existing test only validates basic removal): [10](#0-9) 

## Recommendation

Update the `RemoveSubScheme` function to mirror the logic in `RemoveBeneficiary` by updating `CachedDelayTotalShares` for all affected periods. The fix should iterate through the cached delay periods and subtract the removed sub-scheme's shares, similar to how `RemoveBeneficiary` handles this at lines 245-257.

Recommended fix approach:
```csharp
public override Empty RemoveSubScheme(RemoveSubSchemeInput input)
{
    // ... existing validation code ...
    
    var shares = scheme.SubSchemes.SingleOrDefault(d => d.SchemeId == input.SubSchemeId);
    if (shares == null) return new Empty();
    
    // ... existing removal code ...
    
    // NEW: Update CachedDelayTotalShares for delayed distribution schemes
    if (scheme.DelayDistributePeriodCount > 0)
    {
        var currentPeriod = scheme.CurrentPeriod;
        for (var period = currentPeriod; 
             period < currentPeriod.Add(scheme.DelayDistributePeriodCount); 
             period++)
        {
            if (scheme.CachedDelayTotalShares.ContainsKey(period))
            {
                scheme.CachedDelayTotalShares[period] = 
                    scheme.CachedDelayTotalShares[period].Sub(shares.Shares);
            }
        }
    }
    
    scheme.TotalShares = scheme.TotalShares.Sub(shares.Shares);
    State.SchemeInfos[input.SchemeId] = scheme;
    
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task RemoveSubScheme_WithDelayedDistribution_CausesIncorrectProfitDistribution()
{
    const int delayPeriods = 3;
    const int subSchemeShares = 50;
    const int beneficiaryShares = 50;
    const int totalAmount = 1000;
    
    // Create main scheme with delayed distribution
    var creator = Creators[0];
    var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);
    
    await creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = delayPeriods,
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    var schemeId = (await creator.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = creatorAddress })).SchemeIds.First();
    
    // Create sub-scheme and add it
    var subSchemeId = await CreateSchemeAsync(1);
    await creator.AddSubScheme.SendAsync(new AddSubSchemeInput
    {
        SchemeId = schemeId,
        SubSchemeId = subSchemeId,
        SubSchemeShares = subSchemeShares
    });
    
    // Add beneficiary
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = Accounts[0].Address,
            Shares = beneficiaryShares
        },
        EndPeriod = long.MaxValue
    });
    
    // Period 1: Distribute (caches total shares = 100 for period 4)
    await ContributeAndDistribute(creator, totalAmount, 1);
    
    // Remove sub-scheme BEFORE period 4 distribution
    await creator.RemoveSubScheme.SendAsync(new RemoveSubSchemeInput
    {
        SchemeId = schemeId,
        SubSchemeId = subSchemeId
    });
    
    // Verify current TotalShares is correct (50)
    var scheme = await creator.GetScheme.CallAsync(schemeId);
    scheme.TotalShares.ShouldBe(beneficiaryShares);
    
    // Distribute periods 2, 3, 4
    await ContributeAndDistribute(creator, totalAmount, 2);
    await ContributeAndDistribute(creator, totalAmount, 3);
    await ContributeAndDistribute(creator, totalAmount, 4);
    
    // Check period 4 distribution info
    var distributedInfo = await creator.GetDistributedProfitsInfo.CallAsync(
        new SchemePeriod { SchemeId = schemeId, Period = 4 });
    
    // BUG: TotalShares still shows 100 (including removed sub-scheme)
    // Should be 50, but CachedDelayTotalShares wasn't updated
    distributedInfo.TotalShares.ShouldBe(100); // This is the bug
    
    // Beneficiary claims profit
    await creator.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId,
        Beneficiary = Accounts[0].Address
    });
    
    // Check beneficiary balance
    var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = Accounts[0].Address,
        Symbol = "ELF"
    });
    
    // BUG: Beneficiary receives only 500 (50/100 * 1000)
    // Expected: 1000 (50/50 * 1000) since only beneficiary remains
    balance.Balance.ShouldBe(500); // Demonstrates fund loss
    
    // The missing 500 tokens are locked in period 4's virtual address
    var period4Address = await creator.GetSchemeAddress.CallAsync(
        new SchemePeriod { SchemeId = schemeId, Period = 4 });
    var lockedBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = period4Address,
        Symbol = "ELF"
    });
    lockedBalance.Balance.ShouldBe(500); // Permanently locked
}
```

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L243-257)
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

**File:** protobuf/profit_contract.proto (L156-157)
```text
    // Record the scheme's current total share for deferred distribution of benefits, period -> total shares.
    map<int64, int64> cached_delay_total_shares = 11;
```

**File:** test/AElf.Contracts.Profit.Tests/BVT/SchemeTests.cs (L165-178)
```csharp
    public async Task ProfitContract_DelayDistribution_Test()
    {
        const int delayDistributePeriodCount = 3;
        const int contributeAmountEachTime = 100_000;
        var creator = Creators[0];
        var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);

        await creator.CreateScheme.SendAsync(new CreateSchemeInput
        {
            IsReleaseAllBalanceEveryTimeByDefault = true,
            ProfitReceivingDuePeriodCount = 100,
            DelayDistributePeriodCount = delayDistributePeriodCount,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L302-341)
```csharp
    public async Task ProfitContract_RemoveSubScheme_Success_Test()
    {
        const int shares1 = 80;
        const int shares2 = 20;

        var creator = Creators[0];

        var schemeId = await CreateSchemeAsync();
        var subSchemeId1 = await CreateSchemeAsync(1);
        var subSchemeId2 = await CreateSchemeAsync(2);

        await creator.AddSubScheme.SendAsync(new AddSubSchemeInput
        {
            SchemeId = schemeId,
            SubSchemeId = subSchemeId1,
            SubSchemeShares = shares1
        });

        await creator.AddSubScheme.SendAsync(new AddSubSchemeInput()
        {
            SchemeId = schemeId,
            SubSchemeId = subSchemeId2,
            SubSchemeShares = shares2
        });

        //remove sub scheme1
        {
            var removeSubSchemeResult = await creator.RemoveSubScheme.SendAsync(new RemoveSubSchemeInput
            {
                SchemeId = schemeId,
                SubSchemeId = subSchemeId1
            });
            removeSubSchemeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            var scheme = await creator.GetScheme.CallAsync(schemeId);
            scheme.TotalShares.ShouldBe(shares2);
            scheme.SubSchemes.Count.ShouldBe(1);
            scheme.SubSchemes.First().Shares.ShouldBe(shares2);
        }
    }
```
