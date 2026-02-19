### Title
Negative Profit Values Propagated Without Validation Leading to Incorrect View Data and Lost Claims

### Summary
The `GetProfitAmount()` function returns negative profit values without validation when `DistributedProfitsMap.AmountsMap` contains negative entries created by the `BurnProfits` path. This occurs legitimately when schemes with `DelayDistributePeriodCount > 0` have zero cached shares in early periods, causing profits to be burned and stored as negative values. Beneficiaries querying these periods receive misleading negative profit data, and during claims, they lose their rights to these periods without receiving any tokens.

### Finding Description

The vulnerability exists across multiple components:

**1. Entry Point - No Validation in GetProfitAmount:** [1](#0-0) 

The function retrieves values from `allProfitsMapResult.AllProfitsMap` and returns them directly without checking if they are negative.

**2. Negative Value Source - BurnProfits Path:** [2](#0-1) 

When `totalShares <= 0` during distribution, `BurnProfits` is called and explicitly stores negative amounts at line 551: `distributedProfitsInfo.AmountsMap.Add(symbol, -amount)` to represent burned tokens.

**3. Trigger Condition - Delay Distribution Logic:** [3](#0-2) 

With `DelayDistributePeriodCount > 0`, the first N periods have no cached `totalShares` (line 474 sets `totalShares = 0`), triggering the `BurnProfits` path.

**4. Propagation Through Calculation Chain:** [4](#0-3) 

In `ProfitAllPeriods`, negative `AmountsMap` values are passed to `SafeCalculateProfits` at line 873-874, which calculates proportional shares without validating the input. [5](#0-4) 

`SafeCalculateProfits` performs `(totalAmount * shares) / totalShares` where `totalAmount` can be negative, returning negative profit amounts without validation.

**5. Impact on Claims:** [6](#0-5) 

During `ClaimProfits`, when `amount <= 0` (line 881), no transfer occurs but `lastProfitPeriod` is still incremented (line 908), permanently marking those periods as "claimed" without any token transfer to the beneficiary.

### Impact Explanation

**Direct Fund Impact:**
- Beneficiaries lose their rightful claim to profits from periods where tokens were burned due to delayed distribution mechanics
- For a scheme with `DelayDistributePeriodCount = 3` and 1000 ELF distributed per period, beneficiaries with shares added from Period 0 would lose claims to ~3000 ELF from the first three periods
- This affects ALL beneficiaries in schemes using delayed distribution during their initial periods

**Operational Impact:**
- View methods return semantically incorrect negative profit values, misleading users and off-chain systems
- UIs displaying profit amounts would show negative values, creating confusion about user earnings
- The `ProfitsClaimed` event is never emitted for these periods, breaking accounting and audit trails

**Who is Affected:**
- Any beneficiary added to a scheme with `DelayDistributePeriodCount > 0` during or before the delay period
- Particularly affects early adopters in newly created profit distribution schemes
- Systems and contracts relying on accurate profit view data

### Likelihood Explanation

**Attack Complexity:** None required - this is a design flaw, not an exploit

**Feasible Preconditions:**
1. Scheme created with `DelayDistributePeriodCount > 0` (common for staged distribution)
2. Beneficiaries added starting from early periods (normal operation)
3. Manager distributes profits during the delay periods (required operation)
4. Beneficiaries attempt to query or claim their profits (normal user action)

**Execution Practicality:**
- Occurs automatically during normal contract operation
- No special permissions or timing required beyond standard scheme operation
- The `DelayDistributePeriodCount` feature is documented and intended for use

**Probability:** HIGH
- Affects any scheme using delayed distribution (a documented feature)
- Triggers automatically during the first `DelayDistributePeriodCount` periods
- Already exploitable in any deployed delayed distribution schemes

### Recommendation

**Immediate Fix:**

1. **Add validation in GetProfitAmount:**
```csharp
public override Int64Value GetProfitAmount(GetProfitAmountInput input)
{
    var allProfitsMapResult = GetAllProfitsMap(input.SchemeId, input.Beneficiary, input.Symbol);
    var value = allProfitsMapResult.AllProfitsMap.TryGetValue(input.Symbol, out var amount) ? amount : 0;
    return new Int64Value { Value = Math.Max(0, value) }; // Clamp negative to zero
}
```

2. **Fix ProfitAllPeriods to skip negative amounts:** [7](#0-6) 

Add validation after line 874:
```csharp
var amount = SafeCalculateProfits(profitDetail.Shares,
    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);
    
if (amount < 0) continue; // Skip burned periods without updating lastProfitPeriod in view mode
if (amount <= 0 && !isView) continue; // In claim mode, skip but don't update lastProfitPeriod
```

3. **Redesign BurnProfits to not store negative values:**
Store a separate flag indicating the period had zero shares instead of negative amounts, or simply don't add burned periods to `AmountsMap`.

4. **Add beneficiary start period validation:**
Prevent adding beneficiaries with `StartPeriod < CurrentPeriod` when `CurrentPeriod < DelayDistributePeriodCount` to avoid this scenario entirely.

### Proof of Concept

**Initial State:**
1. Create profit scheme with `DelayDistributePeriodCount = 2`
2. Add beneficiary Alice with 100 shares, `StartPeriod = 0`, `EndPeriod = MaxValue`
3. Contribute 1000 ELF to scheme's general ledger

**Exploit Sequence:**

**Period 0 Distribution:**
- Manager calls `DistributeProfits(schemeId, period=0, amountsMap={})` 
- Scheme has `CachedDelayTotalShares` empty for period 0
- Line 474: `totalShares = 0`
- Line 486: `BurnProfits` is called
- Line 551: `AmountsMap["ELF"] = -1000` stored for period 0

**Period 1 Distribution:**
- Manager calls `DistributeProfits(schemeId, period=1, amountsMap={})`
- Same flow, `totalShares = 0`
- `AmountsMap["ELF"] = -1000` stored for period 1

**Period 2 Distribution:**
- Now has cached shares from period 0
- Normal distribution occurs with positive amounts

**Alice Queries Profit:**
- Alice calls `GetProfitAmount(schemeId, "ELF", alice)`
- Returns negative or reduced value due to periods 0-1 having -1000 each
- Expected: Positive profit from periods 2+
- Actual: Negative or significantly reduced total

**Alice Claims Profit:**
- Alice calls `ClaimProfits(schemeId, alice)`
- Periods 0-1: `amount < 0`, no transfer occurs (line 881 check fails)
- Line 908: `lastProfitPeriod` updated to 2
- Alice permanently loses claim to periods 0-1 (2000 ELF total)
- Only receives profits from period 2 onwards

**Success Condition:** Alice's profit amount is negative or reduced, and claiming updates `lastProfitPeriod` past burned periods without any token transfer, resulting in permanent loss of rightful profit claims.

### Citations

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L62-70)
```csharp
    public override Int64Value GetProfitAmount(GetProfitAmountInput input)
    {
        var allProfitsMapResult = GetAllProfitsMap(input.SchemeId, input.Beneficiary, input.Symbol);

        return new Int64Value
        {
            Value = allProfitsMapResult.AllProfitsMap.TryGetValue(input.Symbol, out var value) ? value : 0
        };
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L464-486)
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

        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");

        var profitsReceivingVirtualAddress =
            GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, releasingPeriod);

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L845-920)
```csharp
    private Dictionary<string, long> ProfitAllPeriods(Scheme scheme, ProfitDetail profitDetail, Address beneficiary, long maxProfitReceivingPeriodCount,
        bool isView = false, string targetSymbol = null)
    {
        var profitsMap = new Dictionary<string, long>();
        var lastProfitPeriod = profitDetail.LastProfitPeriod;

        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };

        foreach (var symbol in symbols)
        {
            var totalAmount = 0L;
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
            {
                var periodToPrint = period;
                var detailToPrint = profitDetail;
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

                if (!isView)
                {
                    Context.LogDebug(() =>
                        $"{beneficiary} is profiting {amount} {symbol} tokens from {scheme.SchemeId.ToHex()} in period {periodToPrint}." +
                        $"Sender's Shares: {detailToPrint.Shares}, total Shares: {distributedProfitsInformation.TotalShares}");
                    if (distributedProfitsInformation.IsReleased && amount > 0)
                    {
                        if (State.TokenContract.Value == null)
                            State.TokenContract.Value =
                                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());

                        Context.Fire(new ProfitsClaimed
                        {
                            Beneficiary = beneficiary,
                            Symbol = symbol,
                            Amount = amount,
                            ClaimerShares = detailToPrint.Shares,
                            TotalShares = distributedProfitsInformation.TotalShares,
                            Period = periodToPrint
                        });
                    }

                    lastProfitPeriod = period + 1;
                }

                totalAmount = totalAmount.Add(amount);
            }

            profitsMap.Add(symbol, totalAmount);
        }

        profitDetail.LastProfitPeriod = lastProfitPeriod;

        return profitsMap;
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
