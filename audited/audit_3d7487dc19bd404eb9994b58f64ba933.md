### Title
CachedDelayTotalShares Corruption via RemoveSubScheme in Delayed Distribution Schemes

### Summary
The `RemoveSubScheme` method fails to update `CachedDelayTotalShares` when removing a sub-scheme from a parent scheme with delayed distribution enabled (`DelayDistributePeriodCount > 0`). This causes cached total shares to remain inflated with the removed sub-scheme's shares, leading to incorrect profit distribution in future periods where beneficiaries receive less than their entitled share.

### Finding Description

The Profit contract maintains a `CachedDelayTotalShares` map (period → total shares) for schemes with delayed distribution to track what the total shares should be for future distribution periods. [1](#0-0) 

When distributing profits with delay enabled, the system caches the current `TotalShares` for a future period and retrieves cached values for the current period. [2](#0-1) 

**Root Cause:** The `RemoveSubScheme` method updates `TotalShares` but completely omits updating `CachedDelayTotalShares`. [3](#0-2) 

This creates an inconsistency because:
1. `RemoveBeneficiary` correctly iterates through all cached periods and subtracts removed shares from each. [4](#0-3) 
2. `ClaimProfits` also correctly updates all cached periods when removing expired profit details. [5](#0-4) 
3. But `RemoveSubScheme` only updates line 152 (`TotalShares`) without any `CachedDelayTotalShares` maintenance.

The Treasury contract actively uses `RemoveSubScheme` via its `ResetWeight` helper method. [6](#0-5) 

### Impact Explanation

**Direct Financial Impact - Reward Misallocation:**

When a sub-scheme is removed from a parent with `DelayDistributePeriodCount = N`, the cached shares for the next N periods remain inflated. When profit distribution occurs for those periods, the denominator (total shares) uses the stale cached value instead of the actual reduced value.

**Concrete Example:**
- Period 1: Parent scheme has Sub-A (50 shares) + Sub-B (50 shares) = 100 total
- Period 2: Distribute 1000 tokens, caches TotalShares=100 for Period 5 (with delay=3)
- Period 3: Manager calls `RemoveSubScheme` to remove Sub-A
  - `TotalShares` becomes 50 ✓
  - `CachedDelayTotalShares[5]` stays at 100 ✗ (BUG)
- Period 5: Distribute 1000 tokens
  - Uses cached value of 100 instead of actual 50
  - Sub-B receives: 50/100 × 1000 = 500 tokens (50% loss)
  - Should receive: 50/50 × 1000 = 1000 tokens
  - Missing 500 tokens distributed to period's virtual address

**Who is Affected:**
- Remaining sub-schemes and their beneficiaries receive only a fraction of entitled profits
- Individual beneficiaries in the parent scheme receive inflated profits at sub-schemes' expense
- This violates the critical invariant: "Profit/Treasury/TokenHolder share calculations, donation/release logic, dividend distribution and settlement accuracy"

### Likelihood Explanation

**Reachable Entry Point:** `RemoveSubScheme` is a public method callable by the scheme manager. [7](#0-6) 

**Feasible Preconditions:**
1. Scheme must be created with `DelayDistributePeriodCount > 0` - this is a documented feature used in production (CitizenWelfare scheme in Treasury uses delay=1). [8](#0-7) 
2. Sub-schemes must be added and profits distributed to populate the cache
3. Manager calls `RemoveSubScheme` (legitimate operation for weight adjustments)

**Execution Practicality:** The Treasury contract demonstrates this pattern is used in production - the `ResetWeight` method removes and re-adds sub-schemes to update weight allocations. While the current MinerReward scheme doesn't have delay enabled, any future scheme or external contract using this pattern would be vulnerable.

**Attack Complexity:** LOW - This is triggered during normal operations, not requiring any sophisticated attack. Any scheme manager performing legitimate weight adjustments on a delayed distribution scheme will trigger this bug.

### Recommendation

**Code-Level Mitigation:**
Update `RemoveSubScheme` to match the pattern used in `RemoveBeneficiary`. After line 152, add:

```csharp
// Update cached delay total shares if delay distribution is enabled
if (scheme.DelayDistributePeriodCount > 0)
{
    foreach (var cachedPeriod in scheme.CachedDelayTotalShares.Keys.ToList())
    {
        scheme.CachedDelayTotalShares[cachedPeriod] = 
            scheme.CachedDelayTotalShares[cachedPeriod].Sub(shares.Shares);
    }
}
```

**Invariant Check:**
Add assertion before distribution: verify that if no shares were added/removed since last cache, the cached value equals current `TotalShares`.

**Test Case:**
Create test `ProfitContract_RemoveSubScheme_WithDelayDistribution_Test` that:
1. Creates scheme with `DelayDistributePeriodCount = 3`
2. Adds two sub-schemes with 50 shares each
3. Distributes for periods 1-3 (populating cache)
4. Removes one sub-scheme in period 3
5. Verifies `CachedDelayTotalShares` values all equal 50 (not 100)
6. Distributes for period 6 and verifies correct profit allocation

### Proof of Concept

**Initial State:**
1. Create scheme with `DelayDistributePeriodCount = 3, TotalShares = 0`
2. Add SubSchemeA with 50 shares → `TotalShares = 50`
3. Add SubSchemeB with 50 shares → `TotalShares = 100`

**Transaction Sequence:**
1. **Period 1:** `DistributeProfits(period=1, amount=1000)` 
   - Caches: `CachedDelayTotalShares[4] = 100`
   - No cached value for period 1, so `totalShares = 0` (no distribution)

2. **Period 2:** `DistributeProfits(period=2, amount=1000)`
   - Caches: `CachedDelayTotalShares[5] = 100`
   - No cached value for period 2, so `totalShares = 0` (no distribution)

3. **Period 3:** `DistributeProfits(period=3, amount=1000)`
   - Caches: `CachedDelayTotalShares[6] = 100`
   - No cached value for period 3, so `totalShares = 0` (no distribution)

4. **Period 3:** `RemoveSubScheme(schemeId=parent, subSchemeId=SubSchemeA)`
   - Updates: `TotalShares = 50` ✓
   - **BUG:** `CachedDelayTotalShares[4]=100, [5]=100, [6]=100` remain unchanged

5. **Period 4:** `DistributeProfits(period=4, amount=1000)`
   - Uses cached: `totalShares = CachedDelayTotalShares[4] = 100`
   - SubSchemeB receives: `50/100 × 1000 = 500` tokens

**Expected Result:** SubSchemeB should receive 1000 tokens (all shares)

**Actual Result:** SubSchemeB receives only 500 tokens (50% loss due to stale cache)

**Success Condition:** Verify `GetBalance(SubSchemeB) = 500` instead of expected `1000`, confirming the misallocation.

### Citations

**File:** protobuf/profit_contract.proto (L156-157)
```text
    // Record the scheme's current total share for deferred distribution of benefits, period -> total shares.
    map<int64, int64> cached_delay_total_shares = 11;
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L793-797)
```csharp
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
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
