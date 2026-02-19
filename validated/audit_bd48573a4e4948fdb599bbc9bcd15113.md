# Audit Report

## Title
CachedDelayTotalShares Corruption via Premature Beneficiary Removal Leading to Profit Loss

## Summary
The Profit contract's delayed distribution mechanism contains a critical flaw where removing a beneficiary during their delay window causes incorrect subtraction from `CachedDelayTotalShares` entries that were set before the beneficiary existed. This corrupts the cached total shares for affected periods, causing legitimate beneficiaries' profits to be burned instead of distributed.

## Finding Description

The vulnerability arises from a temporal mismatch in how beneficiary shares are tracked during the delay distribution period.

**Core Mechanism Flaw:**

When a beneficiary is added with `DelayDistributePeriodCount` D at period P, their `StartPeriod` is set to P+D [1](#0-0) , meaning profits should only be distributed to them starting from period P+D. However, the shares are immediately added to `scheme.TotalShares` [2](#0-1) .

During profit distribution at period P, the current `TotalShares` (including the new beneficiary's shares) is cached to `CachedDelayTotalShares[P+D]` [3](#0-2) . This is correct behavior - the beneficiary's shares first appear in the cache at period P+D.

**The Vulnerability:**

If the beneficiary is removed at period R where P < R < P+D, the removal is permitted when `EndPeriod < CurrentPeriod` [4](#0-3) . During removal, `RemoveProfitDetails` adds all removed shares to `RemovedDetails` using `scheme.CurrentPeriod` (R) as the key, regardless of when the beneficiary was actually added [5](#0-4) .

The `RemoveBeneficiary` function then subtracts these shares from `CachedDelayTotalShares` for periods [R, R+D-1] [6](#0-5) :

**The Critical Bug:**
- Beneficiary's shares exist in cache entries from period P+D onwards only
- But removal subtracts from periods [R, R+D-1]
- Periods [R, P+D-1] get incorrectly reduced even though they never included these shares
- These earlier periods contain cache entries from other beneficiaries that get corrupted

**Exploitation Path:**

A scheme manager can add a beneficiary at period P with `EndPeriod = CurrentPeriod` (minimum allowed per validation at lines 179-180). At period P+1, since `EndPeriod < CurrentPeriod`, the beneficiary can be removed. This triggers the automatic corruption of `CachedDelayTotalShares` entries for periods that never included the beneficiary's shares.

## Impact Explanation

**Direct Protocol Fund Loss:**

When `CachedDelayTotalShares[period]` is incorrectly reduced, the distribution calculation for that period uses the corrupted value. If the cached value becomes zero or missing, `totalShares` is set to 0 [7](#0-6) . This triggers the burn condition [8](#0-7) , where profits are permanently burned instead of distributed to legitimate beneficiaries [9](#0-8) .

**Quantified Damage:**
- With `DelayDistributePeriodCount = 3`, removing a beneficiary at optimal timing corrupts up to 2 periods' cache entries
- Each corrupted period results in 100% profit loss for that period
- All legitimate beneficiaries who should receive distributions from corrupted periods lose their entitled profits
- The Treasury contract uses `DelayDistributePeriodCount = 1` for Citizen Welfare scheme [10](#0-9) , making this vulnerability exploitable in production

**Severity: HIGH** - Direct, irreversible protocol fund loss affecting multiple periods and all beneficiaries of the scheme.

## Likelihood Explanation

**Attacker Capabilities:**
The attacker must be the scheme manager or TokenHolder contract [11](#0-10)  and [12](#0-11) . This is a legitimate role, not a compromised privilege.

**Attack Complexity: Low**
1. Add beneficiary with `EndPeriod = CurrentPeriod` (explicitly allowed)
2. Wait one period for distribution
3. Remove beneficiary (now `EndPeriod < CurrentPeriod`)
4. Cache corruption occurs automatically via the flawed logic

**Feasibility:**
- No special permissions beyond normal scheme management
- Schemes with `DelayDistributePeriodCount > 0` exist in production (Treasury Welfare scheme uses D=1)
- Deterministic behavior - no race conditions or timing dependencies
- Difficult to detect as add/remove operations appear legitimate

**Likelihood: HIGH** - The vulnerable code path executes deterministically when the simple preconditions are met, and the operations required are all legitimate scheme management functions.

## Recommendation

**Fix:** Modify `RemoveBeneficiary` to only subtract shares from cache periods where the beneficiary's shares actually exist. Specifically:

1. Track the original addition period for each profit detail
2. When removing, calculate the correct range: `[max(CurrentPeriod, StartPeriod), StartPeriod + DelayDistributePeriodCount - 1]`
3. Only subtract from cache entries within this corrected range

Alternatively, prevent removal of beneficiaries whose `StartPeriod > CurrentPeriod` (i.e., they haven't started receiving distributions yet) unless `CanRemoveBeneficiaryDirectly` is true.

The fix should ensure that shares are only subtracted from cache entries that were created after the beneficiary was added to the scheme.

## Proof of Concept

```csharp
[Fact]
public async Task PrematureBeneficiaryRemoval_CorruptsCachedShares()
{
    const long schemeDelay = 2;
    const long initialShares = 1000;
    const long attackShares = 100;
    
    // Setup: Create scheme with DelayDistributePeriodCount = 2
    var schemeId = await CreateSchemeAsync(schemeDelay);
    
    // Period 1: Add legitimate beneficiary B with shares
    await AddBeneficiaryAsync(schemeId, BeneficiaryB, initialShares, long.MaxValue);
    await DistributeProfitsAsync(schemeId, period: 1); // Caches to [1+2=3]
    
    // Period 2: Add attack beneficiary A with EndPeriod = CurrentPeriod
    await AddBeneficiaryAsync(schemeId, BeneficiaryA, attackShares, endPeriod: 2);
    await DistributeProfitsAsync(schemeId, period: 2); // Caches to [2+2=4]
    
    // Verify cache before attack
    var scheme = await GetSchemeAsync(schemeId);
    Assert.Equal(initialShares, scheme.CachedDelayTotalShares[3]); // Period 3 has B's shares only
    Assert.Equal(initialShares + attackShares, scheme.CachedDelayTotalShares[4]); // Period 4 has both
    
    // Period 3: Remove attack beneficiary (EndPeriod=2 < CurrentPeriod=3)
    await RemoveBeneficiaryAsync(schemeId, BeneficiaryA);
    
    // BUG: Cache[3] incorrectly reduced even though A's shares never existed there
    scheme = await GetSchemeAsync(schemeId);
    Assert.Equal(initialShares - attackShares, scheme.CachedDelayTotalShares[3]); // CORRUPTED: Should be 1000, now 900
    
    // Impact: When distributing for period 3, totalShares = 900 instead of 1000
    // Result: B loses 10% of profits, or if this repeats 10x, all profits are burned
}
```

**Notes:**

This vulnerability is particularly concerning because:

1. **Production Impact**: The Treasury contract already uses delayed distribution for the Citizen Welfare scheme, making this exploitable in live deployments
2. **Cascading Effect**: Multiple such removals can reduce a period's cached shares to zero, causing complete profit loss
3. **Irreversible**: Burned profits cannot be recovered
4. **Silent Corruption**: The cache corruption happens automatically without explicit malicious action, and beneficiaries may not realize they're receiving reduced profits until manually auditing distributions

The flaw fundamentally breaks the profit distribution invariant that beneficiaries receive their proportional share of profits based on when they were actually entitled to receive them.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L182-184)
```csharp
        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);

        State.SchemeInfos[schemeId] = scheme;
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L237-239)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L358-359)
```csharp
                removedDetails.TryAdd(scheme.CurrentPeriod, profitDetail.Shares);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-486)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L517-558)
```csharp
    private Empty BurnProfits(long period, Dictionary<string, long> profitsMap, Scheme scheme,
        Address profitsReceivingVirtualAddress)
    {
        scheme.CurrentPeriod = period.Add(1);

        var distributedProfitsInfo = new DistributedProfitsInfo
        {
            IsReleased = true
        };
        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            if (amount > 0)
            {
                var balanceOfToken = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = symbol
                });
                if (balanceOfToken.Balance < amount)
                    continue;
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = Context.Self,
                        Amount = amount,
                        Symbol = symbol
                    }.ToByteString());
                State.TokenContract.Burn.Send(new BurnInput
                {
                    Amount = amount,
                    Symbol = symbol
                });
                distributedProfitsInfo.AmountsMap.Add(symbol, -amount);
            }
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;
        State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInfo;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L60-67)
```csharp
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
                // Distribution of Citizen Welfare will delay one period.
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
```
