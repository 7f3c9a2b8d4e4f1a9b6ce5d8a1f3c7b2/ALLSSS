# Audit Report

## Title
Unbounded Iteration in GetProfitsMap View Method Causes DoS via ExecutionCallThreshold Exhaustion

## Summary
The `GetProfitsMap()` view method in the Profit contract contains unbounded iteration over profit details and periods, causing it to exceed the AElf runtime's ExecutionCallThreshold of 15,000 method calls. This results in `RuntimeCallThresholdExceededException`, preventing users from querying their accumulated profits while the transaction method `ClaimProfits` remains functional due to proper iteration limits.

## Finding Description

The vulnerability exists in the Profit contract's view method implementation where `GetProfitsMap()` calls `GetAllProfitsMap()` with unbounded iteration. [1](#0-0) 

The loop iterates over ALL `availableDetails.Count` without any limit, and for each detail calls `ProfitAllPeriods` with a period count of `profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod)`, which can span hundreds or thousands of periods if the beneficiary hasn't claimed profits or if EndPeriod is set far in the future.

Inside `ProfitAllPeriods`, nested loops iterate over token symbols and periods: [2](#0-1) 

Each period iteration calls helper methods like `GetDistributedPeriodProfitsVirtualAddress()` and `SafeCalculateProfits()`, with each method call incrementing the ExecutionObserver's call counter. The AElf runtime enforces a hard limit: [3](#0-2) 

When this threshold is reached, the ExecutionObserver throws an exception: [4](#0-3) 

Crucially, view methods ARE subject to ExecutionObserver enforcement. The observer is created and set before method execution, regardless of whether it's a view method: [5](#0-4) 

The only difference for view methods is that state changes aren't recorded (line 143-146), but call counting still applies.

In contrast, the transaction method `ClaimProfits` properly limits iterations: [6](#0-5) 

The constant `ProfitReceivingLimitForEachTime` is set to 10: [7](#0-6) 

Multiple view methods rely on the vulnerable `GetAllProfitsMap()` helper: [8](#0-7) 

## Impact Explanation

**Operational DoS - Medium Severity**

This vulnerability causes denial-of-service for profit query operations, preventing users from viewing their accumulated profits through `GetProfitsMap()`, `GetProfitAmount()`, and `GetAllProfitAmount()`. Frontend integrations cannot display profit information, forcing users to claim profits blindly.

**Critical Limitations:**
- **NO fund loss**: Profits remain fully claimable via `ClaimProfits` which has proper iteration limits
- **NO token lockup**: All funds remain accessible  
- **State integrity maintained**: No corruption of profit accounting

The severity is Medium because while it creates operational disruption and poor UX, it does not prevent core functionality (profit claiming) and causes no financial loss. Users can still claim their profits; they simply cannot preview amounts first.

## Likelihood Explanation

**Medium Probability - Natural Accumulation**

This issue occurs naturally through legitimate protocol usage without malicious intent:

**Realistic Scenario (6-12 months):**
- Profit scheme running 500+ periods (daily periods over months)
- User has 30-50 profit details accumulated through TokenHolder stake adjustments
- Scheme uses 8-10 token symbols
- User hasn't claimed in 50+ periods
- **Calculation**: 50 details × 10 symbols × 50 periods × 2 ops/period = 50,000 operations → exceeds 15,000 threshold

**Why Details Accumulate:**

Only scheme manager or TokenHolder contract can add beneficiaries: [9](#0-8) 

The TokenHolder contract calls `AddBeneficiary` when users adjust staked positions: [10](#0-9) 

Each call creates a new profit detail. Old details are only removed if expired AND beyond the cleanup window: [11](#0-10) 

Active schemes with long EndPeriods retain all details, leading to natural accumulation.

## Recommendation

Add iteration limits to view methods matching the transaction method limits:

1. Apply `ProfitReceivingLimitForEachTime` limit to `GetAllProfitsMap()` detail iteration
2. Use `GetMaximumPeriodCountForProfitableDetail()` to calculate bounded period counts for each detail
3. Return partial results with pagination support or indicate truncated data

Example fix for `GetAllProfitsMap()`:
- Change line 125 from `for (var i = 0; i < availableDetails.Count; i++)` 
- To: `for (var i = 0; i < profitableDetailCount; i++)`
- Apply bounded period calculation to line 130 instead of using full `EndPeriod.Sub(LastProfitPeriod)`

This aligns view method behavior with the proven safe implementation in `ClaimProfits`.

## Proof of Concept

A test demonstrating this vulnerability would require:

1. Create a profit scheme with multiple token symbols
2. Add a beneficiary with 50+ profit details (simulating repeated `AddBeneficiary` calls)
3. Distribute profits across 100+ periods without the beneficiary claiming
4. Call `GetProfitsMap()` and observe `RuntimeCallThresholdExceededException`
5. Verify `ClaimProfits()` still succeeds due to its iteration limits

The test would prove that view methods fail while transaction methods succeed, confirming the vulnerability exists due to missing iteration bounds in view method implementation.

### Citations

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L62-86)
```csharp
    public override Int64Value GetProfitAmount(GetProfitAmountInput input)
    {
        var allProfitsMapResult = GetAllProfitsMap(input.SchemeId, input.Beneficiary, input.Symbol);

        return new Int64Value
        {
            Value = allProfitsMapResult.AllProfitsMap.TryGetValue(input.Symbol, out var value) ? value : 0
        };
    }

    public override GetAllProfitAmountOutput GetAllProfitAmount(GetAllProfitAmountInput input)
    {
        var allProfitsMapResult = GetAllProfitsMap(input.SchemeId, input.Beneficiary, input.Symbol);
        return new GetAllProfitAmountOutput
        {
            AllProfitAmount = allProfitsMapResult.AllProfitsMap.TryGetValue(input.Symbol, out var allProfitAmount)
                ? allProfitAmount
                : 0,
            OneTimeClaimableProfitAmount =
                allProfitsMapResult.OneTimeClaimableProfitsMap.TryGetValue(input.Symbol,
                    out var oneTimeClaimableProfitAmount)
                    ? oneTimeClaimableProfitAmount
                    : 0
        };
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L125-135)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L203-207)
```csharp
        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L772-785)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L851-875)
```csharp
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

```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L21-26)
```csharp
    public void CallCount()
    {
        if (_callThreshold != -1 && _callCount == _callThreshold)
            throw new RuntimeCallThresholdExceededException($"Contract call threshold {_callThreshold} exceeded.");

        _callCount++;
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L127-146)
```csharp
        var observer =
            new ExecutionObserver(CurrentTransactionContext.ExecutionObserverThreshold.ExecutionCallThreshold,
                CurrentTransactionContext.ExecutionObserverThreshold.ExecutionBranchThreshold);

        try
        {
            if (!_callHandlers.TryGetValue(methodName, out var handler))
                throw new RuntimeException(
                    $"Failed to find handler for {methodName}. We have {_callHandlers.Count} handlers: " +
                    string.Join(", ", _callHandlers.Keys.OrderBy(k => k))
                );

            _smartContractProxy.SetExecutionObserver(observer);

            ExecuteTransaction(handler);

            if (!handler.IsView())
                CurrentTransactionContext.Trace.StateSet = GetChanges();
            else
                CurrentTransactionContext.Trace.StateSet = new TransactionExecutingStateSet();
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L5-5)
```csharp
    public const int ProfitReceivingLimitForEachTime = 10;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L168-176)
```csharp
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = input.Amount
            }
        });
```
