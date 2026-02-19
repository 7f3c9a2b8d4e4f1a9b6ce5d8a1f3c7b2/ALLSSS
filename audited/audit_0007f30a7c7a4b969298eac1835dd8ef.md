### Title
Inconsistent Symbol Tracking Causes Profit Distribution Discrepancies and Fund Lock

### Summary
The Profit contract inconsistently tracks token symbols in the `ReceivedTokenSymbols` list, leading to discrepancies between query methods and preventing beneficiaries from claiming distributed profits. When `DistributeProfits` is called with a symbol not previously registered via `ContributeProfits`, the symbol is distributed but not added to `ReceivedTokenSymbols`, causing `ClaimProfits` and `GetAllProfitsMap` to ignore those profits while `GetProfitAmount` correctly shows them.

### Finding Description

The root cause lies in how the `ReceivedTokenSymbols` list is maintained:

**Symbol Registration Points:**
- `ContributeProfits` adds symbols to `ReceivedTokenSymbols` [1](#0-0) 
- Sub-scheme distribution adds symbols to sub-scheme's `ReceivedTokenSymbols` [2](#0-1) 
- `DistributeProfits` does NOT add symbols to the parent scheme's `ReceivedTokenSymbols` [3](#0-2) 

**Symbol Usage in Profit Calculation:**
The private `GetAllProfitsMap` method uses `ReceivedTokenSymbols` when no specific symbol is provided: [4](#0-3) 

This logic is used by:
1. `ClaimProfits` - calls `ProfitAllPeriods` without targetSymbol [5](#0-4) 
2. Public `GetAllProfitsMap` - passes null symbol to private method [6](#0-5) 

However, when a specific symbol is provided, it bypasses `ReceivedTokenSymbols`:
- `GetProfitAmount` passes the symbol parameter [7](#0-6) 
- `GetAllProfitAmount` passes the symbol parameter [8](#0-7) 

**Why Protections Fail:**
The contract allows `DistributeProfits` to distribute any symbol present in the scheme's virtual address without validation [9](#0-8) . There is no check that symbols being distributed are in `ReceivedTokenSymbols`, and no update to `ReceivedTokenSymbols` after distribution.

### Impact Explanation

**Direct Fund Lock:**
When tokens are distributed via `DistributeProfits` with a symbol not in `ReceivedTokenSymbols`:
1. The distributed profits are recorded in `DistributedProfitsInfo.AmountsMap` for that period
2. `GetProfitAmount(symbol)` correctly calculates and displays these profits
3. `ClaimProfits()` cannot claim them because it only iterates through `ReceivedTokenSymbols`
4. The profits remain permanently locked in the period's virtual address

**View Inconsistency:**
- `GetProfitAmount("SYMBOL")` returns the correct claimable amount
- `GetAllProfitsMap()` omits this symbol entirely from the results [10](#0-9) 

**Affected Parties:**
All beneficiaries of schemes where this occurs lose access to their share of the distributed tokens. The total locked value equals the sum of all distributions made with unregistered symbols.

**Severity Justification:**
Medium severity because it requires manager action (calling `DistributeProfits` with new symbols) but results in permanent fund loss for beneficiaries without recovery mechanism.

### Likelihood Explanation

**Realistic Scenarios:**
1. **Direct Transfer Path:** The contract comment acknowledges direct transfers: "If someone directly use virtual address to do the contribution, won't sense the token symbol he was using" [11](#0-10) . If tokens are transferred directly to the virtual address, then distributed via `DistributeProfits`, the symbol won't be registered.

2. **New Token Distribution:** A scheme manager introducing a new token symbol by calling `DistributeProfits` directly with that symbol in the `AmountsMap` without prior `ContributeProfits` call.

3. **Cross-Contract Transfers:** Other contracts may transfer tokens to scheme virtual addresses, which then get distributed without symbol registration.

**Attack Complexity:**
Low - requires only:
- Tokens in scheme virtual address (via direct transfer or other means)
- Manager calling `DistributeProfits` with the symbol

**Detection Difficulty:**
High - the discrepancy only becomes apparent when comparing different query methods or when beneficiaries attempt to claim and receive less than expected.

**Probability:**
Medium - while it requires manager action, the lack of validation makes it easy to occur accidentally during legitimate operations, especially when introducing new tokens to existing schemes.

### Recommendation

**Code-Level Mitigation:**
Add symbol registration to `DistributeProfits` after line 490 in ProfitContract.cs:

```csharp
UpdateDistributedProfits(profitsMap, profitsReceivingVirtualAddress, totalShares);

// Add this block:
foreach (var symbol in profitsMap.Keys)
{
    if (!scheme.ReceivedTokenSymbols.Contains(symbol))
    {
        scheme.ReceivedTokenSymbols.Add(symbol);
    }
}

PerformDistributeProfits(profitsMap, scheme, totalShares, profitsReceivingVirtualAddress);
```

**Invariant Check:**
Add assertion in `DistributeProfits` to validate that all symbols being distributed are already registered, or automatically register them during distribution.

**Test Cases:**
1. Test distributing a symbol that was never contributed via `ContributeProfits`
2. Verify `ClaimProfits` successfully claims all distributed symbols
3. Verify `GetAllProfitsMap` returns all distributed symbols
4. Test direct token transfers followed by distribution

### Proof of Concept

**Initial State:**
- Scheme S exists with `ReceivedTokenSymbols = ["ELF"]`
- Beneficiary B has 100 shares in scheme S
- Total scheme shares: 1000

**Attack Sequence:**
1. Attacker/User transfers 1000 USDT directly to scheme S's virtual address (bypassing `ContributeProfits`)
2. Scheme manager calls `DistributeProfits(S, currentPeriod, {"USDT": 1000})`
3. USDT is distributed to period virtual address but NOT added to `ReceivedTokenSymbols`

**Expected vs Actual:**
- `GetProfitAmount(S, "USDT", B)` returns 100 USDT ✓ (beneficiary's share)
- `GetAllProfitsMap(S, B)` returns only {"ELF": X} ✗ (USDT omitted)
- `ClaimProfits(S, B)` transfers only ELF tokens ✗ (100 USDT remains unclaimed)

**Success Condition:**
After `ClaimProfits`, beneficiary B has received ELF but the 100 USDT allocated to them remains in the period's virtual address, permanently inaccessible through normal claiming mechanisms. The query methods show inconsistent results for the same profit data.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L417-498)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        if (input.AmountsMap.Any())
            Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");

        ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

        var profitsMap = new Dictionary<string, long>();
        if (input.AmountsMap.Any())
        {
            foreach (var amount in input.AmountsMap)
            {
                var actualAmount = amount.Value == 0
                    ? State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = amount.Key
                    }).Balance
                    : amount.Value;
                profitsMap.Add(amount.Key, actualAmount);
            }
        }
        else
        {
            if (scheme.IsReleaseAllBalanceEveryTimeByDefault && scheme.ReceivedTokenSymbols.Any())
                // Prepare to distribute all from general ledger.
                foreach (var symbol in scheme.ReceivedTokenSymbols)
                {
                    var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = symbol
                    }).Balance;
                    profitsMap.Add(symbol, balance);
                }
        }

        var totalShares = scheme.TotalShares;

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

        var releasingPeriod = scheme.CurrentPeriod;
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

        State.SchemeInfos[input.SchemeId] = scheme;

        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L641-644)
```csharp
            if (!subScheme.ReceivedTokenSymbols.Contains(symbol))
            {
                subScheme.ReceivedTokenSymbols.Add(symbol);
                State.SchemeInfos[subSchemeShares.SchemeId] = subScheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L715-715)
```csharp
        // If someone directly use virtual address to do the contribution, won't sense the token symbol he was using.
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L716-716)
```csharp
        if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol)) scheme.ReceivedTokenSymbols.Add(input.Symbol);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L784-784)
```csharp
            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L851-851)
```csharp
        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L64-64)
```csharp
        var allProfitsMapResult = GetAllProfitsMap(input.SchemeId, input.Beneficiary, input.Symbol);
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L74-74)
```csharp
        var allProfitsMapResult = GetAllProfitsMap(input.SchemeId, input.Beneficiary, input.Symbol);
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L98-101)
```csharp
    public override GetAllProfitsMapOutput GetAllProfitsMap(GetAllProfitsMapInput input)
    {
        return GetAllProfitsMap(input.SchemeId, input.Beneficiary);
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L103-142)
```csharp
    private GetAllProfitsMapOutput GetAllProfitsMap(Hash schemeId, Address beneficiary, string symbol = null)
    {
        var scheme = State.SchemeInfos[schemeId];
        Assert(scheme != null, "Scheme not found.");
        beneficiary = beneficiary ?? Context.Sender;
        var profitDetails = State.ProfitDetailsMap[schemeId][beneficiary];

        if (profitDetails == null) return new GetAllProfitsMapOutput();

        // ReSharper disable once PossibleNullReferenceException
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod < scheme.CurrentPeriod && (d.LastProfitPeriod == 0
                ? d.EndPeriod >= d.StartPeriod
                : d.EndPeriod >= d.LastProfitPeriod)
        ).ToList();
        
        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, availableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);

        var allProfitsDict = new Dictionary<string, long>();
        var claimableProfitsDict = new Dictionary<string, long>();
        for (var i = 0; i < availableDetails.Count; i++)
        {
            var profitDetail = availableDetails[i];
            if (profitDetail.LastProfitPeriod == 0) profitDetail.LastProfitPeriod = profitDetail.StartPeriod;
            
            var totalProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod),true, symbol);
            AddProfitToDict(allProfitsDict, totalProfitsDictForEachProfitDetail);
            if(i >= profitableDetailCount) continue;
            var claimableProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount,true, symbol);
            AddProfitToDict(claimableProfitsDict, claimableProfitsDictForEachProfitDetail);
        }

        return new GetAllProfitsMapOutput
        {
            AllProfitsMap = { allProfitsDict },
            OneTimeClaimableProfitsMap = { claimableProfitsDict }
        };
    }
```
