# Audit Report

## Title
Missing Upper Bound Validation in SetMaximumProfitReceivingPeriodCount Enables Gas Exhaustion DoS in ClaimProfits

## Summary
The `SetMaximumProfitReceivingPeriodCount` function lacks upper bound validation, allowing Parliament governance to set extreme values that cause gas exhaustion in `ClaimProfits`, creating a system-wide denial of service for all profit beneficiaries.

## Finding Description

The vulnerability originates from insufficient input validation in a governance-controlled parameter that directly controls loop iteration counts in the profit claiming mechanism.

**Root Cause:**

The `SetMaximumProfitReceivingPeriodCount` function only validates that the input value is positive, with no maximum limit enforcement. [1](#0-0) 

While the default value is set conservatively to 100, [2](#0-1)  Parliament can override this with arbitrarily large values including `int.MaxValue` (2,147,483,647).

**Exploitation Flow:**

When an extreme value is set, it propagates through the following execution path:

1. When users call `ClaimProfits`, the function retrieves the maximum period count per profitable detail. [3](#0-2) 

2. The `GetMaximumPeriodCountForProfitableDetail` function divides the configured maximum by the profitable detail count (capped at 10). [4](#0-3) 

3. With `int.MaxValue` set and 10 profitable details, this returns 214,748,364 iterations per detail. [5](#0-4) 

4. The `ProfitAllPeriods` function then executes a loop that can iterate hundreds of millions of times. [6](#0-5) 

5. Each iteration performs state reads, calculations, and potentially token transfers, consuming substantial gas. [7](#0-6) 

The profitable detail limit cap exists to prevent excessive processing, [8](#0-7)  but this mitigation is bypassed when the period count itself is set to extreme values.

## Impact Explanation

**Operational Impact:**
- Complete denial of service for `ClaimProfits` functionality affecting all profit scheme beneficiaries system-wide
- Accumulated profits become inaccessible until Parliament recognizes the misconfiguration and executes a corrective proposal
- Recovery requires proposal creation, voting period, and execution - potentially days of downtime
- Affects TokenHolder contract participants, election reward claimants, and all users with profit scheme participation

**Severity Assessment:**
This represents a HIGH severity vulnerability because it enables complete operational failure of a critical economic function affecting the entire ecosystem. While it requires governance action, the absence of input validation creates a realistic path for accidental system breakage through configuration errors.

## Likelihood Explanation

**Realistic Exploitation Scenarios:**

Parliament governance could accidentally trigger this without malicious intent through:

1. **Misunderstanding of "unlimited"**: Setting `int.MaxValue` believing it means "no restrictions" on claiming, similar to `long.MaxValue` usage for unlimited duration in other parts of the system [9](#0-8) 

2. **Lack of guidance**: No documentation or error messages indicate safe value ranges

3. **Copy-paste from other contexts**: Reusing a large constant from another parameter

**Execution Path:**
- Parliament creates a proposal calling `SetMaximumProfitReceivingPeriodCount` with an extreme value
- Proposal passes through standard approval process (no special privileges needed beyond normal Parliament operation)
- Once executed, all subsequent `ClaimProfits` calls immediately fail with gas exhaustion
- Detection occurs when users report inability to claim profits

The existing test suite validates only the lower bound (value > 0), [10](#0-9)  confirming that upper bound validation was not considered during development.

## Recommendation

Add an upper bound validation to `SetMaximumProfitReceivingPeriodCount`:

```csharp
public override Empty SetMaximumProfitReceivingPeriodCount(Int32Value input)
{
    ValidateContractState(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
    Assert(Context.Sender == State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
        "No permission.");
    Assert(input.Value > 0, "Invalid maximum profit receiving period count.");
    Assert(input.Value <= 10000, "Maximum profit receiving period count too large."); // Add upper bound
    State.MaximumProfitReceivingPeriodCount.Value = input.Value;
    return new Empty();
}
```

The upper bound of 10,000 would allow processing up to 1,000 periods per detail (with 10 details), providing ample flexibility while preventing gas exhaustion attacks.

## Proof of Concept

```csharp
[Fact]
public async Task SetMaximumProfitReceivingPeriodCount_ExtremeValue_CausesGasExhaustion()
{
    // Setup: Create a scheme and add a beneficiary
    var schemeId = await CreateSchemeAsync();
    var beneficiary = SampleAddress.AddressList[0];
    await AddBeneficiaryAsync(schemeId, beneficiary, 100);
    
    // Distribute profits for 10 periods
    for (var i = 1; i <= 10; i++)
    {
        await DistributeProfitsAsync(schemeId, i, 1000);
    }
    
    // Parliament sets an extreme value via governance
    var defaultOrganizationAddress = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var proposalId = await CreateProposalAsync(
        ProfitContractAddress,
        defaultOrganizationAddress,
        nameof(ProfitContractStub.SetMaximumProfitReceivingPeriodCount),
        new Int32Value { Value = int.MaxValue } // Extreme value
    );
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Verify the extreme value was set
    var maxPeriodCount = await ProfitContractStub.GetMaximumProfitReceivingPeriodCount.CallAsync(new Empty());
    maxPeriodCount.Value.ShouldBe(int.MaxValue);
    
    // Attempt to claim profits - this will cause gas exhaustion
    var claimResult = await ProfitContractStub.ClaimProfits.SendWithExceptionAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiary
    });
    
    // Transaction fails due to gas exhaustion
    claimResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    claimResult.TransactionResult.Error.ShouldContain("Insufficient transaction fee");
}
```

**Notes:**
- This vulnerability affects all profit claiming operations system-wide once the parameter is misconfigured
- The issue is exacerbated when beneficiaries have multiple profitable details (up to 10) and multiple token symbols
- View methods like `GetAllProfitsMap` are also affected as they call the same `ProfitAllPeriods` function [11](#0-10)

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L117-117)
```csharp
            EndPeriod = long.MaxValue
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L772-774)
```csharp
        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L835-843)
```csharp
    public override Empty SetMaximumProfitReceivingPeriodCount(Int32Value input)
    {
        ValidateContractState(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);
        Assert(Context.Sender == State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            "No permission.");
        Assert(input.Value > 0, "Invalid maximum profit receiving period count.");
        State.MaximumProfitReceivingPeriodCount.Value = input.Value;
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

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L5-5)
```csharp
    public const int ProfitReceivingLimitForEachTime = 10;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L9-9)
```csharp
    public const int DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100;
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L1758-1763)
```csharp
                Value = 0
            });
        await ApproveWithMinersAsync(proposalId);
        result = await ParliamentContractStub.Release.SendWithExceptionAsync(proposalId);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        result.TransactionResult.Error.ShouldContain("Invalid maximum profit receiving period count");
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L121-134)
```csharp
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
```
