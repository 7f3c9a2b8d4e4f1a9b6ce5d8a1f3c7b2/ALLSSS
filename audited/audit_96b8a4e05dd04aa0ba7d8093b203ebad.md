### Title
LastProfitPeriod Backwards Update Enables Double-Claiming of Profits in Multi-Token Schemes

### Summary
The `ProfitAllPeriods` function updates `lastProfitPeriod` to `period + 1` for each symbol processed within a shared variable scope. When a scheme has multiple token symbols distributed across different periods, later-processed symbols that lack distributions in higher periods will overwrite `lastProfitPeriod` to a lower value, allowing beneficiaries to re-claim already-claimed periods and steal funds from other beneficiaries.

### Finding Description [1](#0-0) 

The root cause is in the `ProfitAllPeriods` function where `lastProfitPeriod` is initialized once at line 849 but updated inside nested loops. The outer loop iterates over token symbols, and the inner loop iterates over periods. [2](#0-1) [3](#0-2) 

For each period where a symbol has distributed profits, line 908 unconditionally sets `lastProfitPeriod = period + 1`. When processing multiple symbols, if Symbol A has distributions in periods 1-3 (setting `lastProfitPeriod = 4`), but Symbol B only has distributions in periods 1-2 (overwriting to `lastProfitPeriod = 3`), the final value stored at line 917 will be 3 instead of 4. [4](#0-3) [5](#0-4) 

When the beneficiary claims again, they start from period 3 and can re-claim period 3 profits for Symbol A that were already transferred. [6](#0-5) 

There is no validation preventing `lastProfitPeriod` from being set to a lower value than its previous iteration value. The continue statement at line 871 prevents updating when a symbol is missing, but later symbols that DO have distributions will still overwrite to their last processed period. [7](#0-6) 

### Impact Explanation
**Direct Fund Theft**: A beneficiary can claim the same period's profits multiple times for symbols that were distributed in that period but not in subsequent periods processed by later symbols in the scheme's `ReceivedTokenSymbols` list.

**Quantified Damage**: If a beneficiary has 50% shares and period 3 distributed 1000 ELF, they should receive 500 ELF once. With this vulnerability, they can claim 500 ELF twice (1000 ELF total), stealing 500 ELF that belongs to other beneficiaries or should remain in the period's virtual address.

**Affected Parties**: All other beneficiaries in the scheme lose their proportional share of profits. The scheme's integrity is compromised as total claimed amounts exceed distributed amounts from the same periods.

**Severity**: HIGH - Direct theft of funds with no special privileges required beyond being a scheme beneficiary.

### Likelihood Explanation
**Attacker Capabilities**: Attacker only needs to be a registered beneficiary in a profit scheme with multiple token symbols. No special permissions or role compromise required.

**Attack Complexity**: LOW - The vulnerability triggers naturally during normal operations when:
1. A profit scheme tracks multiple token symbols
2. Different periods have different symbols distributed (common scenario)
3. Beneficiary calls `ClaimProfits` normally [8](#0-7) 

**Feasibility**: VERY HIGH - Multi-token schemes are standard in AElf's economics model (ELF, USDT, and other tokens). Distribution patterns naturally vary by period based on what's contributed or released. The symbol order in `ReceivedTokenSymbols` is determined by contribution order and cannot be controlled by attackers, but the vulnerability exists regardless of order.

**Detection/Operational Constraints**: The double-claim appears as a legitimate `ClaimProfits` transaction. Event logs will show `ProfitsClaimed` events for the same period multiple times, but this requires careful monitoring. [9](#0-8) 

**Probability**: MEDIUM-HIGH - Occurs whenever multi-token schemes have uneven symbol distributions across periods, which is a realistic operational pattern.

### Recommendation
Replace the unconditional assignment at line 908 with a maximum-tracking update to ensure `lastProfitPeriod` only advances forward:

```csharp
lastProfitPeriod = Math.Max(lastProfitPeriod, period + 1);
```

This ensures that once a higher period is processed for any symbol, `lastProfitPeriod` cannot regress to a lower value when processing subsequent symbols.

**Additional Validation**: Add an assertion before line 917 to verify `lastProfitPeriod` is never less than `profitDetail.LastProfitPeriod`:
```csharp
Assert(lastProfitPeriod >= profitDetail.LastProfitPeriod, 
    "LastProfitPeriod cannot decrease during profit claiming.");
```

**Test Cases**: Add regression tests covering:
1. Multi-token schemes with different symbols distributed per period
2. Verify `LastProfitPeriod` advances to maximum processed period across all symbols
3. Verify double-claim attempts fail after fix

### Proof of Concept

**Initial State:**
- Scheme SCHEME_A with 200 total shares
- Attacker has 100 shares (50%)
- ReceivedTokenSymbols: ["ELF", "USDT"]
- Period 1: Distributed 1000 ELF + 500 USDT
- Period 2: Distributed 1000 ELF + 500 USDT  
- Period 3: Distributed 1000 ELF only (no USDT)
- Scheme.CurrentPeriod = 4

**Transaction 1 - First ClaimProfits:**
1. Attacker calls `ClaimProfits(schemeId: SCHEME_A)`
2. `ProfitAllPeriods` processes symbols ["ELF", "USDT"]
3. For "ELF": periods 1,2,3 processed → transfers 500+500+500=1500 ELF → `lastProfitPeriod=4`
4. For "USDT": periods 1,2 processed (period 3 skipped, no USDT) → transfers 250+250=500 USDT → `lastProfitPeriod=3`
5. `profitDetail.LastProfitPeriod` stored as 3

**Expected Result:** LastProfitPeriod should be 4 (all periods claimed)
**Actual Result:** LastProfitPeriod is 3 (backdated by USDT processing)

**Transaction 2 - Second ClaimProfits:**
1. Attacker calls `ClaimProfits(schemeId: SCHEME_A)` again
2. `ProfitAllPeriods` starts from period 3 (due to backdated LastProfitPeriod)
3. For "ELF": period 3 processed again → transfers 500 ELF (DOUBLE CLAIM)
4. `profitDetail.LastProfitPeriod` now correctly set to 4

**Expected Result:** No profits claimable (all periods already claimed)
**Actual Result:** 500 ELF claimed again from period 3, stealing from other beneficiaries

**Success Condition:** Attacker received 2000 ELF total (1500+500) instead of correct 1500 ELF for periods 1-3, representing theft of 500 ELF.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L750-809)
```csharp
    public override Empty ClaimProfits(ClaimProfitsInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        if (scheme == null) throw new AssertionException("Scheme not found.");
        var beneficiary = input.Beneficiary ?? Context.Sender;
        var profitDetails = State.ProfitDetailsMap[input.SchemeId][beneficiary];
        if (profitDetails == null) throw new AssertionException("Profit details not found.");

        Context.LogDebug(
            () => $"{Context.Sender} is trying to profit from {input.SchemeId.ToHex()} for {beneficiary}.");

        // LastProfitPeriod is set as 0 at the very beginning, and be updated as current period every time when it is claimed.
        // What's more, LastProfitPeriod can also be +1 more than endPeroid, for it always points to the next period to claim.
        // So if LastProfitPeriod is 0, that means this profitDetail hasn't be claimed before, so just check whether it is a valid one;
        // And if a LastProfitPeriod is larger than EndPeriod, it should not be claimed, and should be removed later.
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();

        Context.LogDebug(() =>
            $"Profitable details: {profitableDetails.Aggregate("\n", (profit1, profit2) => profit1.ToString() + "\n" + profit2)}");

        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
        // Only can get profit from last profit period to actual last period (profit.CurrentPeriod - 1),
        // because current period not released yet.
        for (var i = 0; i < profitableDetailCount; i++)
        {
            var profitDetail = profitableDetails[i];
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
        }

        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;

        foreach (var profitDetail in profitDetailsToRemove)
        {
            availableDetails.Remove(profitDetail);
        }

        State.ProfitDetailsMap[input.SchemeId][beneficiary] = new ProfitDetails { Details = { availableDetails } };

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
