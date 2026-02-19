### Title
Unbounded State Growth in DistributedProfitsMap Causes Inevitable Storage Exhaustion

### Summary
The `DistributedProfitsMap` state in the Profit contract grows unboundedly with no cleanup mechanism, accumulating one entry per period for each profit scheme. Over the lifetime of the blockchain, system schemes (Treasury and Election) automatically create thousands of entries, leading to progressive storage exhaustion affecting all nodes. This represents a medium-severity operational denial-of-service vulnerability.

### Finding Description

The root cause is in the `DistributedProfitsMap` state storage pattern: [1](#0-0) 

This map stores `DistributedProfitsInfo` for each scheme-period combination using virtual addresses as keys. Entries are created in two locations:

**Location 1 - UpdateDistributedProfits:** [2](#0-1) 

**Location 2 - BurnProfits:** [3](#0-2) 

Both are called from `DistributeProfits`, which increments the scheme period: [4](#0-3) 

**Critical flaw:** The codebase contains **zero** calls to `DistributedProfitsMap.Remove()`. Unlike `ProfitDetailsMap` which has cleanup logic in `AddBeneficiary` and `ClaimProfits`, the `DistributedProfitsMap` entries persist indefinitely.

**System scheme usage in Treasury:** [5](#0-4) 

**System scheme usage in Election:** [6](#0-5) 

These system contracts call `DistributeProfits` every term (approximately daily/weekly), creating 6 new entries per term across the Reward, VotesWeightReward, ReElectionReward, BasicReward, Subsidy, and Welfare schemes.

### Impact Explanation

**Harm:**
- **Storage growth rate:** Minimum 6 entries per term × ~50-100 bytes per entry = 300-600 bytes/term
- **Over 10,000 terms** (multi-year operation): 60,000+ entries consuming several MB for system schemes alone
- **User schemes amplify impact:** TokenHolder schemes add unlimited additional growth
- **All nodes affected:** Every validator and full node must store this unbounded state
- **Progressive degradation:** Storage costs increase linearly with blockchain age, eventually making node operation prohibitively expensive

**Who is affected:**
- All network validators (increased storage/sync costs)
- Full node operators (storage burden)
- Network reliability (potential node dropouts due to storage constraints)

**Severity justification:**
Medium severity because the impact is gradual but inevitable. While not immediately exploitable for fund theft, it creates an unsustainable storage model that threatens long-term network viability.

### Likelihood Explanation

**Attacker capabilities:** None required - this occurs through normal protocol operation.

**Attack complexity:** Not an active attack; this is a design flaw that manifests automatically.

**Feasibility conditions:**
- System schemes call `DistributeProfits` every term via consensus/treasury integration [7](#0-6) 

- TokenHolder contract allows any user to create schemes and distribute profits [8](#0-7) 

**Probability:** 100% - occurs during every term transition, which is a fundamental blockchain operation.

**Detection constraints:** The growth is gradual (megabytes over years), making it difficult to detect until storage becomes a significant operational burden.

### Recommendation

**1. Implement periodic cleanup mechanism:**

Add a cleanup function in `DistributeProfits` or `ClaimProfits` to remove `DistributedProfitsMap` entries older than `ProfitReceivingDuePeriodCount`:

```csharp
// In DistributeProfits after line 498
private void CleanupOldDistributedProfits(Hash schemeId, long currentPeriod, long duePeriodCount)
{
    var cleanupPeriod = currentPeriod.Sub(duePeriodCount).Sub(1);
    if (cleanupPeriod > 0)
    {
        var oldVirtualAddress = GetDistributedPeriodProfitsVirtualAddress(schemeId, cleanupPeriod);
        State.DistributedProfitsMap.Remove(oldVirtualAddress);
    }
}
```

**2. Add invariant check:**
Ensure total `DistributedProfitsMap` entries per scheme never exceeds `ProfitReceivingDuePeriodCount + DelayDistributePeriodCount + safety buffer`.

**3. Test cases:**
- Verify cleanup after `ProfitReceivingDuePeriodCount` periods
- Test with maximum `MaximumProfitReceivingDuePeriodCount` (1024) [9](#0-8) 
- Confirm no storage leak over 10,000+ periods

### Proof of Concept

**Initial state:**
- Scheme created with `ProfitReceivingDuePeriodCount = 10`
- Current period = 1

**Transaction sequence:**
1. Call `DistributeProfits(period=1)` → Creates entry at virtual address for period 1
2. Call `DistributeProfits(period=2)` → Creates entry for period 2
3. Repeat for periods 3-100

**Expected result:** 
Only periods (current_period - 10) to current_period should have entries (11 entries maximum)

**Actual result:**
All 100 periods have entries in `DistributedProfitsMap`. No cleanup occurs. Entries at periods 1-89 are no longer claimable (beyond `ProfitReceivingDuePeriodCount`) but consume storage indefinitely.

**Success condition:**
Query `DistributedProfitsMap` for period 1 after period 100 - entry still exists despite being unclaimed for 90 periods, proving unbounded growth.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L11-11)
```csharp
    public MappedState<Address, DistributedProfitsInfo> DistributedProfitsMap { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L705-735)
```csharp
    private void ReleaseTreasurySubProfitItems(long termNumber)
    {
        var amountsMap = State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L);
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.RewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.ReElectionRewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.BasicRewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L428-428)
```csharp
        State.CurrentTermNumber.Value = input.TermNumber.Add(1);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L442-454)
```csharp
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.SubsidyHash.Value,
            Period = input.TermNumber,
            AmountsMap = { amountsMap }
        });

        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.WelfareHash.Value,
            Period = input.TermNumber,
            AmountsMap = { amountsMap }
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-146)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager, true);
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
        var distributeProfitsInput = new Profit.DistributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Period = scheme.Period
        };
        if (input.AmountsMap != null && input.AmountsMap.Any()) distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

        State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
        scheme.Period = scheme.Period.Add(1);
        State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L7-7)
```csharp
    public const int MaximumProfitReceivingDuePeriodCount = 1024;
```
