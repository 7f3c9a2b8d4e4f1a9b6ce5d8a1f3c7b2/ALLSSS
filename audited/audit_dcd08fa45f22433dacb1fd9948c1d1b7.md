### Title
Unbounded Storage Growth via Maximum Period Profit Distribution Schemes

### Summary
The Profit contract allows any user to create schemes with the maximum `ProfitReceivingDuePeriodCount` of 1024 and distribute profits across all periods, creating permanent storage entries in `DistributedProfitsMap` that are never cleaned up. An attacker can repeatedly exploit this to cause unbounded state growth at the cost of only transaction fees, eventually exhausting blockchain storage capacity and degrading node performance.

### Finding Description

**Root Cause:** Missing cleanup mechanism for distributed profit period storage.

The Profit contract stores distributed profit information for each period in the `DistributedProfitsMap` state variable: [1](#0-0) 

When profits are distributed via `DistributeProfits`, a new entry is created for each period: [2](#0-1) 

The constant defines a maximum of 1024 periods: [3](#0-2) 

**Attack Path:**

1. Anyone can create a profit scheme without authorization: [4](#0-3) 

2. The scheme creator becomes the manager and can call `DistributeProfits` for sequential periods: [5](#0-4) [6](#0-5) 

3. Each call creates permanent storage, even with zero profits or shares: [7](#0-6) 

**Why Protections Fail:**

The contract implements cleanup logic for expired beneficiary details (`ProfitDetailsMap`) but completely lacks cleanup for period storage (`DistributedProfitsMap`): [8](#0-7) 

No code path removes old `DistributedProfitsMap` entries. The `ProfitReceivingDuePeriodCount` parameter only controls how long beneficiaries can **claim** profits, not how long period storage persists: [9](#0-8) 

After the due period expires, the storage entries remain accessible but permanently uncollectable: [10](#0-9) 

### Impact Explanation

**Direct Harm:**
- Each malicious scheme creates 1024 permanent storage entries (one per period) in `DistributedProfitsMap`
- Each entry stores `DistributedProfitsInfo` containing total shares, amounts map, and release status
- Multiple attackers or repeated attacks create multiplicative storage bloat
- Storage is never reclaimed, even after `ProfitReceivingDuePeriodCount` expires

**Affected Parties:**
- All blockchain nodes must store and index this data indefinitely
- Node operators face increased disk space and memory requirements
- Network performance degrades as state size grows unbounded
- Honest users experience slower transaction processing and higher sync times

**Severity Justification:**
- **High severity** due to permanent, irreversible damage to blockchain state
- No mechanism exists to remove the malicious storage entries
- Attack can be repeated indefinitely by creating multiple schemes
- Each attack amplifies the problem by 1024 storage entries
- Blockchain storage capacity is finite and this attack directly exhausts it

### Likelihood Explanation

**Attacker Capabilities:**
- No special permissions required - any address can create schemes and distribute profits
- Attacker only needs sufficient tokens to pay transaction fees for 1 + 1024 transactions (CreateScheme + DistributeProfits × 1024)
- No requirement to contribute actual profit tokens - empty distributions still create storage

**Attack Complexity:**
- Simple sequential execution pattern demonstrated in existing tests: [11](#0-10) 

- No complex preconditions or race conditions required
- Attack is deterministic and guaranteed to succeed

**Feasibility Conditions:**
- Attack requires only standard transaction submission capabilities
- Can be executed through normal contract interaction
- No reliance on compromising trusted roles
- Economic cost (transaction fees) is reasonable compared to damage inflicted

**Detection/Operational Constraints:**
- Individual transactions appear legitimate (normal DistributeProfits calls)
- Attack pattern only becomes apparent when observing state growth over time
- No existing monitoring or rate limiting on scheme creation or period distributions

**Probability Assessment:** High likelihood - attack is trivially executable with minimal cost and maximum impact.

### Recommendation

**Immediate Mitigation:**
Implement automatic cleanup of old `DistributedProfitsMap` entries in the `DistributeProfits` method:

```csharp
// After line 494 in DistributeProfits, add cleanup logic
var cleanupPeriod = scheme.CurrentPeriod - scheme.ProfitReceivingDuePeriodCount - 1;
if (cleanupPeriod > 0)
{
    var oldPeriodAddress = GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, cleanupPeriod);
    State.DistributedProfitsMap.Remove(oldPeriodAddress);
}
```

**Additional Safeguards:**
1. Add configurable limits on maximum active periods per scheme
2. Implement storage rent for schemes that maintain many period entries
3. Add governance-controlled rate limiting on scheme creation
4. Emit events for storage cleanup to enable monitoring

**Invariant Checks:**
- Assert that `DistributedProfitsMap` size for a scheme never exceeds `ProfitReceivingDuePeriodCount + buffer`
- Monitor aggregate storage growth across all schemes

**Test Cases:**
1. Create scheme with max periods and verify cleanup after exceeding due period count
2. Verify storage size bounds when distributing across many periods
3. Test that old period data is properly cleaned while maintaining claimability window
4. Stress test with multiple schemes to ensure no storage bloat

### Proof of Concept

**Initial State:**
- Attacker has account with sufficient tokens for transaction fees
- No special permissions required

**Attack Sequence:**

1. **Create malicious scheme:**
```
CreateScheme({
    ProfitReceivingDuePeriodCount: 1024,
    IsReleaseAllBalanceEveryTimeByDefault: false
})
→ Returns schemeId, attacker becomes manager
```

2. **Distribute profits across all 1024 periods:**
```
for (period = 1; period <= 1024; period++) {
    DistributeProfits({
        SchemeId: schemeId,
        Period: period,
        AmountsMap: {} // Empty - no actual tokens required
    })
}
→ Each call creates permanent DistributedProfitsMap[virtualAddress(schemeId, period)] entry
```

3. **Verify storage growth:**
```
for (period = 1; period <= 1024; period++) {
    GetDistributedProfitsInfo({SchemeId: schemeId, Period: period})
    → Returns DistributedProfitsInfo (storage entry exists)
}
```

4. **Verify no cleanup occurs:**
```
// Wait for ProfitReceivingDuePeriodCount periods to pass
// Advance CurrentPeriod beyond 1024 + 1024 = 2048
for (period = 1025; period <= 2048; period++) {
    DistributeProfits({SchemeId: schemeId, Period: period, AmountsMap: {}})
}

// Check that old periods still consume storage
GetDistributedProfitsInfo({SchemeId: schemeId, Period: 1})
→ Still returns DistributedProfitsInfo (never cleaned up)
```

**Expected Result:** Old period entries should be automatically cleaned after exceeding `ProfitReceivingDuePeriodCount`.

**Actual Result:** All 1024 period entries remain in storage permanently, consuming blockchain resources indefinitely. Attacker can repeat this process with multiple schemes to amplify the storage exhaustion attack.

**Success Condition:** Storage entries for periods older than `CurrentPeriod - ProfitReceivingDuePeriodCount` continue to exist in `DistributedProfitsMap` and can be queried, demonstrating unbounded state growth.

---

**Notes:**

The vulnerability stems from an asymmetry in the contract's cleanup strategy: `ProfitDetailsMap` (beneficiary-level data) has explicit cleanup logic, but `DistributedProfitsMap` (period-level distribution data) lacks any removal mechanism. The `ProfitReceivingDuePeriodCount` parameter only affects **claim eligibility**, not **storage lifetime**, creating a permanent storage leak exploitable by any user at low cost.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L11-11)
```csharp
    public MappedState<Address, DistributedProfitsInfo> DistributedProfitsMap { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L44-54)
```csharp
    public override Hash CreateScheme(CreateSchemeInput input)
    {
        ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
        else
            Assert(
                input.ProfitReceivingDuePeriodCount > 0 &&
                input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
                "Invalid profit receiving due period count.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L203-207)
```csharp
        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L479-494)
```csharp
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");

        var profitsReceivingVirtualAddress =
            GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, releasingPeriod);

        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);

        Context.LogDebug(() => $"Receiving virtual address: {profitsReceivingVirtualAddress}");

        UpdateDistributedProfits(profitsMap, profitsReceivingVirtualAddress, totalShares);

        PerformDistributeProfits(profitsMap, scheme, totalShares, profitsReceivingVirtualAddress);

        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L517-557)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L857-860)
```csharp
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L864-871)
```csharp
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L7-7)
```csharp
    public const int MaximumProfitReceivingDuePeriodCount = 1024;
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L1243-1254)
```csharp
        for (var i = 0; i < periodCount; i++)
        {
            await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
            {
                SchemeId = schemeId,
                AmountsMap =
                {
                    { ProfitContractTestConstants.NativeTokenSymbol, amount }
                },
                Period = i + 1
            });
        }
```
