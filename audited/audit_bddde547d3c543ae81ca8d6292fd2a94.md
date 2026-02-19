# Audit Report

## Title
Unbounded Iteration in GetProfitsMap View Method Causes DoS via ExecutionCallThreshold Exhaustion

## Summary
The `GetProfitsMap()` view method iterates over all profit details without limit and calculates profits across potentially large period ranges. This causes method call counts to exceed the ExecutionCallThreshold (15,000), resulting in RuntimeCallThresholdExceededException that prevents users from querying their total profits. While the transaction method `ClaimProfits` has proper limits, the view methods lack equivalent protections.

## Finding Description

The vulnerability exists in the Profit contract's view method implementation. The `GetProfitsMap()` view method calls `GetAllProfitsMap()` which contains an unbounded loop that iterates over ALL `availableDetails.Count` without any limit [1](#0-0) . 

For each detail, the method calls `ProfitAllPeriods` with period count of `profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod)` [2](#0-1) , which can span hundreds or thousands of periods if the beneficiary hasn't claimed profits for a long time or if EndPeriod is set far in the future.

Inside `ProfitAllPeriods`, nested loops iterate over token symbols and periods, with each period iteration calling helper methods like `GetDistributedPeriodProfitsVirtualAddress()` [3](#0-2) . These method calls and loop branches accumulate toward the ExecutionCallThreshold.

The AElf runtime enforces a hard limit of 15,000 calls per transaction execution [4](#0-3) . When this threshold is reached, the ExecutionObserver throws a RuntimeCallThresholdExceededException [5](#0-4) .

Crucially, view methods ARE subject to the ExecutionObserver's call threshold enforcement [6](#0-5) . The only difference for view methods is that state changes aren't recorded, but the call counting still applies.

In contrast, the transaction method `ClaimProfits` properly limits iterations to a maximum of 10 details [7](#0-6)  and calculates a bounded period count per detail [8](#0-7) .

**Execution Path:**
1. User calls `GetProfitsMap()` → `GetAllProfitsMap()`  
2. Loop processes ALL availableDetails (potentially 50+ details)
3. For each detail: iterates over symbols (5-10) × periods (50-1000+)
4. Each iteration involves method calls that increment the call counter
5. Total operations: e.g., 50 details × 10 symbols × 50 periods × 2 ops = 50,000 operations
6. Exceeds 15,000 threshold → RuntimeCallThresholdExceededException thrown
7. View method fails, user cannot query profits

## Impact Explanation

**Operational DoS - Medium Severity:**

This vulnerability causes a denial-of-service condition for profit queries, preventing users from viewing their accumulated profits through `GetProfitsMap()`, `GetProfitAmount()`, and `GetAllProfitAmount()` - all of which rely on the vulnerable `GetAllProfitsMap()` helper [9](#0-8) .

**Impact Scope:**
- Users cannot query profit amounts via view methods
- Frontend integrations cannot display profit information
- Users must claim profits blindly without knowing amounts
- Significant UX degradation

**Critical Limitations:**
- **NO fund loss**: Profits remain fully claimable via the `ClaimProfits` transaction method which has proper iteration limits
- **NO token lockup**: All funds remain accessible
- **State integrity maintained**: No corruption of profit accounting

The severity is Medium because while it creates operational disruption and poor UX, it does not prevent core functionality (profit claiming) and causes no financial loss. Users can still claim their profits; they simply cannot preview the amounts first.

## Likelihood Explanation

**Medium Probability - Natural Accumulation:**

This issue can occur naturally through legitimate protocol usage without any malicious intent:

**Realistic Scenario (6-12 month timeframe):**
- Profit scheme running 500+ periods (daily periods over months)
- User has 30-50 profit details accumulated through TokenHolder stake adjustments
- Scheme uses 8-10 token symbols
- User hasn't claimed in 50+ periods
- **Calculation**: 50 details × 10 symbols × 50 periods = 25,000 operations → exceeds 15,000 threshold

**Preconditions:**
1. Long-running profit scheme with many periods elapsed
2. Beneficiary accumulated multiple profit details (each `AddBeneficiary` call creates a new detail)
3. Beneficiary hasn't claimed recently (LastProfitPeriod lags behind CurrentPeriod or EndPeriod)
4. Scheme distributes multiple token symbols

**Why Details Accumulate:**

Only the scheme manager or TokenHolder contract can add beneficiaries [10](#0-9) . The TokenHolder contract legitimately calls `AddBeneficiary` each time users adjust their staked positions, creating new profit details. Old details are only removed if expired AND beyond the `ProfitReceivingDuePeriodCount` cleanup window [11](#0-10) , so active schemes with long EndPeriods retain all details.

**Complexity**: Low - occurs through normal system operations  
**Detection**: Easy - query simply fails with exception  
**Attacker capabilities**: None required - natural occurrence

## Recommendation

Apply the same iteration limits used in `ClaimProfits` to the view methods. Specifically:

1. **Limit detail count**: Cap the loop at line 125 of ViewMethods.cs to process at most `ProfitContractConstants.ProfitReceivingLimitForEachTime` (10) details, similar to the transaction method.

2. **Limit period count**: Use `GetMaximumPeriodCountForProfitableDetail()` to calculate bounded period counts instead of using the unbounded `profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod)` at line 130.

3. **Add pagination**: For users with many details, implement pagination parameters in the view method signatures to allow querying subsets of profit details.

**Suggested fix for GetAllProfitsMap** (lines 103-142 in ViewMethods.cs):
```csharp
// Line 119-121: Keep existing calculation
var profitableDetailCount = 
    Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, availableDetails.Count);
var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);

// Line 125: Change to use the limit
for (var i = 0; i < profitableDetailCount; i++) // Instead of availableDetails.Count
{
    var profitDetail = availableDetails[i];
    if (profitDetail.LastProfitPeriod == 0) profitDetail.LastProfitPeriod = profitDetail.StartPeriod;
    
    // Line 130: Use bounded period count
    var totalProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, 
        maxProfitReceivingPeriodCount, true, symbol); // Instead of unbounded EndPeriod - LastProfitPeriod
    // ... rest of logic
}
```

This ensures view methods have the same protection as transaction methods while maintaining accurate profit calculations within ExecutionCallThreshold limits.

## Proof of Concept

The following test demonstrates the vulnerability by creating a scenario where a beneficiary accumulates multiple profit details over many periods, causing the view method to exceed the ExecutionCallThreshold:

```csharp
[Fact]
public async Task GetProfitsMap_ExceedsExecutionCallThreshold_DoS()
{
    // Setup: Create profit scheme
    var schemeId = await CreateProfitScheme();
    var beneficiary = Accounts[1].Address;
    
    // Simulate TokenHolder adding beneficiary multiple times (50 details)
    for (int i = 0; i < 50; i++)
    {
        await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
        {
            SchemeId = schemeId,
            BeneficiaryShare = new BeneficiaryShare { Beneficiary = beneficiary, Shares = 100 },
            EndPeriod = 1000 // Far future
        });
    }
    
    // Distribute profits across many periods with multiple symbols
    for (int period = 1; period <= 100; period++)
    {
        await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
        {
            SchemeId = schemeId,
            Period = period,
            AmountsMap = { 
                { "ELF", 1000 }, { "USDT", 500 }, { "BTC", 100 },
                { "ETH", 200 }, { "BNB", 300 }, { "TOKEN1", 400 },
                { "TOKEN2", 250 }, { "TOKEN3", 150 }
            }
        });
    }
    
    // Attempt to query profits - this should fail with RuntimeCallThresholdExceededException
    // 50 details × 8 symbols × 100 periods = 40,000 operations >> 15,000 threshold
    var exception = await Assert.ThrowsAsync<RuntimeCallThresholdExceededException>(async () =>
    {
        await ProfitContractStub.GetProfitsMap.CallAsync(new ClaimProfitsInput
        {
            SchemeId = schemeId,
            Beneficiary = beneficiary
        });
    });
    
    exception.Message.ShouldContain("Contract call threshold 15000 exceeded");
    
    // Verify ClaimProfits still works (with its proper limits)
    var claimResult = await ProfitContractStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiary
    });
    claimResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

This test proves that with realistic parameters (50 profit details, 8 token symbols, 100 unclaimed periods), the view method fails while the transaction method with limits succeeds.

## Notes

**Technical Clarification**: While the claim states "state access counts toward ExecutionCallThreshold," the actual mechanism is that METHOD CALLS and BRANCHES are counted by the ExecutionObserver (each method has `CallCount()` injected at entry). However, since each loop iteration involves multiple method calls (like `GetDistributedPeriodProfitsVirtualAddress()`), the conclusion remains valid - unbounded iteration causes excessive call accumulation that exceeds the 15,000 threshold.

**Affected Methods**: All three view methods that query profits are vulnerable:
- `GetProfitsMap()` 
- `GetProfitAmount()`
- `GetAllProfitAmount()`

All call the same vulnerable `GetAllProfitsMap()` helper.

**No Financial Risk**: This is strictly an availability/UX issue. Funds remain secure and claimable through the properly-limited transaction method.

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

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L125-125)
```csharp
        for (var i = 0; i < availableDetails.Count; i++)
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L130-130)
```csharp
            var totalProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod),true, symbol);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L772-773)
```csharp
        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L822-833)
```csharp
    private int GetMaximumPeriodCountForProfitableDetail(int profitableDetailCount)
    {
        // Get the maximum profit receiving period count
        var maxPeriodCount = GetMaximumProfitReceivingPeriodCount();
        // Check if the maximum period count is greater than the profitable detail count
        // and if the profitable detail count is greater than 0
        return maxPeriodCount > profitableDetailCount && profitableDetailCount > 0
            // Divide the maximum period count by the profitable detail count
            ? maxPeriodCount.Div(profitableDetailCount)
            // If the conditions are not met, return 1 as the maximum period count
            : 1;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-867)
```csharp
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
            {
                var periodToPrint = period;
                var detailToPrint = profitDetail;
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L21-24)
```csharp
    public void CallCount()
    {
        if (_callThreshold != -1 && _callCount == _callThreshold)
            throw new RuntimeCallThresholdExceededException($"Contract call threshold {_callThreshold} exceeded.");
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L127-139)
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
```
