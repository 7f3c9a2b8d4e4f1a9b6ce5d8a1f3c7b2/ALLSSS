# Audit Report

## Title
Missing Balance Validation Before Virtual Transfers in Profit Claiming Creates DoS Vulnerability

## Summary
The `ProfitAllPeriods()` function performs multiple virtual token transfers across different periods without validating balance availability beforehand. When any inline transfer fails due to insufficient funds, the entire `ClaimProfits` transaction fails and reverts all state changes, permanently blocking users from claiming legitimate profits from any period, including those with adequate balances.

## Finding Description

The vulnerability exists in the `ProfitAllPeriods()` private method which is called during profit claiming. The function loops through multiple periods and issues virtual inline transfers without pre-validating that each period's virtual address has sufficient balance to cover the transfer. [1](#0-0) 

The function calls `Context.SendVirtualInline()` to transfer tokens from each period's virtual address to the beneficiary. This is a void method that only queues transactions without providing immediate feedback on whether transfers will succeed. [2](#0-1) 

When inline transactions are executed, the AElf runtime processes them sequentially. If any inline transaction fails, execution halts immediately. [3](#0-2) 

The failure propagates through the trace hierarchy. The `IsSuccessful()` method recursively validates that all inline traces succeeded. [4](#0-3) 

When a transaction fails due to inline transaction failure, the state update logic only persists changes from successful pre-traces and post-traces, **not** the main transaction's state changes. [5](#0-4) 

This means the critical update to `lastProfitPeriod` at line 908 and the final assignment at line 917 of `ProfitAllPeriods()` are **not persisted** when the transaction fails, creating a deadlock where users cannot advance their claim progress.

The `ClaimProfits` function provides no mechanism to claim specific periods or skip problematic ones. [6](#0-5) 

The input structure only accepts `scheme_id` and `beneficiary` - there is no way to select which periods to claim or skip periods with insufficient balance.

**Inconsistent Pattern**: Other parts of the codebase DO implement defensive balance checking. The `BurnProfits` method checks balance before calling `SendVirtualInline` and uses `continue` to skip tokens with insufficient balance. [7](#0-6) 

This defensive pattern is **NOT applied** in `ProfitAllPeriods()`, representing a clear design inconsistency.

Token transfers fail with an assertion error when balance is insufficient. [8](#0-7) 

## Impact Explanation

This vulnerability directly impacts the profit withdrawal mechanism, a critical invariant of the Profit contract system. Users become permanently unable to withdraw their legitimately earned profits. Even if 99 periods have sufficient balance and only 1 period has insufficient balance, the user cannot claim ANY profits.

The harm is quantifiable as complete loss of access to earned funds. The beneficiary's `lastProfitPeriod` marker cannot be updated, creating an indefinite deadlock where profits remain inaccessible. This affects all beneficiaries of profit schemes who have accumulated profits across multiple periods where at least one period's virtual address has insufficient balance.

The severity is **HIGH** because this constitutes a direct Denial of Service of the fund withdrawal mechanism, violating the critical system invariant that users should be able to access their earned profits.

## Likelihood Explanation

The entry point is the public `ClaimProfits()` method callable by any beneficiary without special privileges. Insufficient balance in a period's virtual address can occur through several realistic scenarios in complex multi-period, multi-beneficiary, multi-symbol profit schemes with sub-schemes:

1. **Rounding errors** accumulating over multiple distributions
2. **Sequential claiming** where multiple beneficiaries drain a period's balance, leaving later claimants with insufficient funds
3. **Sub-scheme distribution** discrepancies affecting remaining balances
4. **Edge cases** in profit distribution calculations
5. **State inconsistencies** from interrupted distributions

The complexity is LOW - no special privileges are required, and this occurs naturally from edge cases in normal operation. Users discover the issue only when claiming fails, with no preventive monitoring mechanisms.

Given the complexity of the profit distribution system with multiple tokens, periods, beneficiaries, and nested sub-schemes, balance mismatches have reasonable probability over time. The fact that developers implemented balance checking in `BurnProfits` demonstrates they recognized this risk in at least one code path.

## Recommendation

Implement defensive balance validation before calling `SendVirtualInline()` in `ProfitAllPeriods()`, following the same pattern used in `BurnProfits()`. The method should:

1. Check the balance of each period's virtual address before attempting the transfer
2. Skip periods with insufficient balance using `continue` instead of failing the entire transaction
3. Only update `lastProfitPeriod` for periods that were successfully claimed
4. Allow partial claiming so users can access profits from periods with adequate balances

Alternative solutions:
- Add a parameter to `ClaimProfitsInput` to specify which periods to claim
- Implement a separate method to reset or manually adjust `lastProfitPeriod` with appropriate authorization
- Add a view method to check period balances before claiming

## Proof of Concept

A test demonstrating this vulnerability would:

1. Create a profit scheme with multiple periods
2. Distribute profits to multiple periods (e.g., periods 1-5)
3. Add a beneficiary to the scheme
4. Manually drain the balance from one period's virtual address (e.g., period 3)
5. Attempt to claim profits via `ClaimProfits()`
6. Verify the transaction fails with "Insufficient balance" error
7. Verify `lastProfitPeriod` was not updated
8. Verify subsequent claim attempts continue to fail on the same period
9. Demonstrate that profits from periods 1-2 and 4-5 (with adequate balances) cannot be accessed

This demonstrates the permanent DoS condition where users cannot access any profits despite having legitimate earnings in other periods.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L532-538)
```csharp
                var balanceOfToken = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = symbol
                });
                if (balanceOfToken.Balance < amount)
                    continue;
```

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-895)
```csharp
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
```

**File:** src/AElf.Sdk.CSharp/CSharpSmartContractContext.cs (L219-223)
```csharp
    public void SendVirtualInline(Hash fromVirtualAddress, Address toAddress, string methodName, ByteString args)
    {
        SmartContractBridgeContextImplementation.SendVirtualInline(fromVirtualAddress, toAddress, methodName,
            args);
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L105-126)
```csharp
    private static bool TryUpdateStateCache(TransactionTrace trace, TieredStateCache groupStateCache)
    {
        if (trace == null)
            return false;

        if (!trace.IsSuccessful())
        {
            var transactionExecutingStateSets = new List<TransactionExecutingStateSet>();

            AddToTransactionStateSets(transactionExecutingStateSets, trace.PreTraces);
            AddToTransactionStateSets(transactionExecutingStateSets, trace.PostTraces);

            groupStateCache.Update(transactionExecutingStateSets);
            trace.SurfaceUpError();
        }
        else
        {
            groupStateCache.Update(trace.GetStateSets());
        }

        return true;
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L236-246)
```csharp
            var inlineTrace = await ExecuteOneAsync(singleTxExecutingDto, cancellationToken);

            if (inlineTrace == null)
                break;
            trace.InlineTraces.Add(inlineTrace);
            if (!inlineTrace.IsSuccessful())
                // Already failed, no need to execute remaining inline transactions
                break;

            internalStateCache.Update(inlineTrace.GetStateSets());
        }
```

**File:** src/AElf.Kernel.Core/Extensions/TransactionTraceExtensions.cs (L8-19)
```csharp
    public static bool IsSuccessful(this TransactionTrace txTrace)
    {
        if (txTrace.ExecutionStatus != ExecutionStatus.Executed) return false;

        if (txTrace.PreTraces.Any(trace => !trace.IsSuccessful())) return false;

        if (txTrace.InlineTraces.Any(trace => !trace.IsSuccessful())) return false;

        if (txTrace.PostTraces.Any(trace => !trace.IsSuccessful())) return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```
