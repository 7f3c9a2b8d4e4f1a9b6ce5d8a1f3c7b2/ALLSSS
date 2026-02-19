# Audit Report

## Title
Invalid Profit Detail Creation When EndPeriod Equals CurrentPeriod with Delayed Distribution

## Summary
The `AddBeneficiary` function in the Profit contract fails to validate that `EndPeriod` accounts for the scheme's `DelayDistributePeriodCount`. When a manager adds a beneficiary with `EndPeriod = CurrentPeriod` to a scheme with `DelayDistributePeriodCount > 0`, an invalid profit detail is created where `StartPeriod > EndPeriod`. This beneficiary can never claim profits, but their shares permanently inflate `TotalShares`, diluting all future distributions to legitimate beneficiaries.

## Finding Description

The vulnerability exists in the `AddBeneficiary` method where validation is insufficient: [1](#0-0) 

This assertion only validates that `EndPeriod >= CurrentPeriod`, but does not account for the scheme's delay configuration. The `StartPeriod` is then calculated as: [2](#0-1) 

When `EndPeriod = CurrentPeriod` and `DelayDistributePeriodCount > 0`, this creates `StartPeriod = CurrentPeriod + DelayDistributePeriodCount > EndPeriod`, violating the fundamental invariant that a beneficiary's benefit period must have `StartPeriod <= EndPeriod`.

The beneficiary's shares are immediately added to `TotalShares`: [3](#0-2) 

During profit claiming, this invalid detail is filtered out and cannot claim: [4](#0-3) 

For a detail with `LastProfitPeriod = 0` (never claimed), the condition `d.EndPeriod >= d.StartPeriod` evaluates to false when `StartPeriod > EndPeriod`, excluding it from `availableDetails`.

The cleanup mechanisms fail to remove the invalid detail. The cleanup in `AddBeneficiary` requires `LastProfitPeriod >= EndPeriod`: [5](#0-4) 

Since `LastProfitPeriod` starts at 0 and the condition `0 >= CurrentPeriod` is false, the invalid detail persists. The cleanup in `ClaimProfits` only processes details already in `profitableDetails`: [6](#0-5) 

Since the invalid detail was filtered out at line 766, it never reaches this cleanup logic.

This vulnerability affects any scheme with `DelayDistributePeriodCount > 0`. The Treasury Welfare scheme in production uses this configuration: [7](#0-6) 

## Impact Explanation

**Permanent Fund Misallocation:** When an invalid beneficiary with shares S is added to a scheme with existing shares T, all future distributions allocate S/(T+S) of profits to an unclaimed address. These profits remain locked in the period's virtual address indefinitely while legitimate beneficiaries receive only their proportional share of the reduced total.

**Quantified Example:** If a scheme has 100 existing shares and an invalid beneficiary is added with 100 shares, `TotalShares` becomes 200. Each distribution now allocates 50% to legitimate beneficiaries (who should receive 100%) and 50% to the unclaimed invalid address. Over 100 periods distributing 1,000 tokens each, 50,000 tokens would be permanently locked.

**No Recovery Mechanism:** While a manager could manually call `RemoveBeneficiary`, this requires awareness of the issue. The invalid detail provides no indication it is unclaimed, and automated cleanup mechanisms fail to remove it.

## Likelihood Explanation

**Entry Point:** The `AddBeneficiary` function is publicly accessible to scheme managers: [8](#0-7) 

**Feasible Scenarios:**
- **Accidental:** A scheme manager setting `EndPeriod` to "current period" without understanding that delayed distribution requires additional buffer periods
- **Malicious:** A manager intentionally locking a portion of distributions to manipulate profit allocation

**Execution Simplicity:** Requires only a single `AddBeneficiary` call with `EndPeriod = CurrentPeriod`. No complex state manipulation or precise timing needed.

**Probability:** Medium. While it requires manager action (a privileged role), the lack of validation makes this mistake straightforward. For schemes with human managers and `DelayDistributePeriodCount > 0`, the vulnerability is directly exploitable.

## Recommendation

Add validation to ensure `EndPeriod` provides sufficient buffer for the delay distribution period:

```csharp
Assert(input.EndPeriod >= scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
    $"Invalid end period. Must be at least {scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount)} " +
    $"(CurrentPeriod + DelayDistributePeriodCount)");
```

This should be added after line 179 in `AddBeneficiary` to ensure all beneficiaries can claim at least one distribution period.

Additionally, consider adding cleanup logic in `ClaimProfits` to detect and remove invalid details where `StartPeriod > EndPeriod`, subtracting their shares from `TotalShares`.

## Proof of Concept

```csharp
[Fact]
public async Task AddBeneficiary_WithDelayAndCurrentEndPeriod_CreatesInvalidDetail()
{
    var creator = Creators[0];
    
    // Create scheme with delay distribution
    await creator.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = 1,
        ProfitReceivingDuePeriodCount = 100
    });
    
    var schemeId = (await creator.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = creator.GetAddress() })).SchemeIds.First();
    
    var scheme = await creator.GetScheme.CallAsync(schemeId);
    var currentPeriod = scheme.CurrentPeriod; // Should be 1
    
    // Add beneficiary with EndPeriod = CurrentPeriod
    await creator.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare 
        { 
            Beneficiary = Accounts[0].Address, 
            Shares = 100 
        },
        EndPeriod = currentPeriod // This creates StartPeriod = 2, EndPeriod = 1
    });
    
    // Verify shares were added
    scheme = await creator.GetScheme.CallAsync(schemeId);
    scheme.TotalShares.ShouldBe(100);
    
    // Try to claim - should fail because detail is invalid
    await creator.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = currentPeriod,
        AmountsMap = { { "ELF", 1000 } }
    });
    
    var result = await Accounts[0].ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId
    });
    
    // Beneficiary cannot claim, but shares remain in TotalShares
    var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = Accounts[0].Address,
        Symbol = "ELF"
    });
    balance.Balance.ShouldBe(0); // Cannot claim despite having shares
    
    // Shares still inflating TotalShares
    scheme = await creator.GetScheme.CallAsync(schemeId);
    scheme.TotalShares.ShouldBe(100); // Shares not removed
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L179-180)
```csharp
        Assert(input.EndPeriod >= scheme.CurrentPeriod,
            $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L182-184)
```csharp
        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);

        State.SchemeInfos[schemeId] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L186-192)
```csharp
        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L204-207)
```csharp
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-766)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-792)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
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
