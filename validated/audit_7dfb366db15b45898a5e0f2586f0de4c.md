# Audit Report

## Title
Period Boundary Validation Bypass Causes Permanent Share Dilution in Profit Distribution

## Summary
The `AddBeneficiary` method in the Profit contract fails to validate that `EndPeriod >= StartPeriod` after calculating `StartPeriod` with the delay offset, allowing profit details with inverted period boundaries to be created. These malformed details have their shares permanently added to `TotalShares` but are filtered out during claims, causing irreversible dilution of all legitimate beneficiaries' profit distributions.

## Finding Description

The vulnerability exists in the `AddBeneficiary` method's period validation logic. [1](#0-0) 

The method validates that the user-provided `EndPeriod` is greater than or equal to the scheme's `CurrentPeriod`. [2](#0-1) 

However, after this validation passes, the `StartPeriod` is calculated by adding `DelayDistributePeriodCount` to `CurrentPeriod`, and the `EndPeriod` is directly assigned from user input. [3](#0-2) 

**There is no validation that `EndPeriod >= StartPeriod` after the delay is applied.** This allows the following scenario when `CurrentPeriod = 100` and `DelayDistributePeriodCount = 1`:
- User provides `EndPeriod = 100`
- Validation passes: `100 >= 100` ✓
- But `StartPeriod = 101`, resulting in `StartPeriod > EndPeriod`
- Shares are added to `TotalShares` before the period calculation. [4](#0-3) 

During profit claims, the malformed detail is filtered out by the `availableDetails` check. When `LastProfitPeriod == 0` (never claimed before), the condition `d.EndPeriod >= d.StartPeriod` fails, excluding the detail from `availableDetails`. [5](#0-4) 

Share cleanup only occurs for details in `profitDetailsToRemove`, which is derived from `profitableDetails` (itself derived from `availableDetails`). [6](#0-5) 

Since the malformed detail never enters `availableDetails`, it's never added to `profitDetailsToRemove`, and its shares remain in `TotalShares` permanently.

The same filtering logic exists in the view methods. [7](#0-6) 

The `FixProfitDetail` method has the same validation gap, allowing managers to modify existing valid details into malformed ones. [8](#0-7) 

## Impact Explanation

When orphaned shares remain in `TotalShares`, all future profit distributions use an inflated denominator. The profit calculation uses the proportional formula, causing legitimate beneficiaries to receive proportionally reduced amounts. [9](#0-8) 

**Example scenario:**
- Scheme with Alice (1,000 shares)
- Manager adds Bob with 9,000 shares where `StartPeriod > EndPeriod`
- `TotalShares = 10,000`, but Bob can never claim
- Distribution of 100,000 tokens: Alice receives `(1,000 / 10,000) * 100,000 = 10,000`
- Alice gets only 10% instead of 100%
- Remaining 90,000 tokens stay locked in period virtual addresses indefinitely

The Citizen Welfare scheme in the Treasury contract is initialized with `DelayDistributePeriodCount = 1`, making this vulnerability immediately applicable to a production economic distribution mechanism. [10](#0-9) 

## Likelihood Explanation

**Attack Vectors:**

1. **Unintentional Misconfiguration**: Scheme managers may not understand the interaction between `DelayDistributePeriodCount` and `EndPeriod` validation, accidentally creating malformed profit details when setting `EndPeriod = CurrentPeriod`.

2. **Malicious Manager Exploitation**: A scheme manager can intentionally add beneficiaries with invalid periods to dilute other beneficiaries' shares. While scheme managers are generally trusted, compromised managers or managers with conflicting interests could exploit this.

3. **FixProfitDetail Exploitation**: Even after initial setup, managers can use `FixProfitDetail` to modify existing valid details into malformed ones without proper validation.

**Feasibility:**
- Entry points (`AddBeneficiary`, `FixProfitDetail`) are public methods accessible to scheme managers
- Precondition: Scheme with `DelayDistributePeriodCount > 0` (the Citizen Welfare scheme meets this)
- Execution: Single transaction with specific parameter values
- Detection: Difficult without inspecting `ProfitDetailsMap` entries directly

**Probability:** High for accidental triggers due to the non-obvious validation gap; Medium-to-High for deliberate exploitation depending on scheme manager trust model.

## Recommendation

Add validation in `AddBeneficiary` to ensure `EndPeriod >= StartPeriod` after calculating `StartPeriod`:

```csharp
public override Empty AddBeneficiary(AddBeneficiaryInput input)
{
    // ... existing validation code ...
    
    Assert(input.EndPeriod >= scheme.CurrentPeriod,
        $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");
    
    var startPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount);
    
    // Add new validation
    Assert(input.EndPeriod >= startPeriod,
        $"Invalid end period. End Period must be >= Start Period. End Period: {input.EndPeriod}, Start Period: {startPeriod}");
    
    // ... rest of the method ...
}
```

Apply the same validation in `FixProfitDetail`:

```csharp
public override Empty FixProfitDetail(FixProfitDetailInput input)
{
    // ... existing code to find and clone the detail ...
    
    newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
    newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
    
    // Add validation
    Assert(newDetail.EndPeriod >= newDetail.StartPeriod,
        $"Invalid period range. End Period must be >= Start Period. End Period: {newDetail.EndPeriod}, Start Period: {newDetail.StartPeriod}");
    
    // ... rest of the method ...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task AddBeneficiary_WithInvalidPeriodBoundaries_CausesPermanentShareDilution()
{
    // Setup: Create scheme with DelayDistributePeriodCount = 1
    var schemeId = await ProfitContractStub.CreateScheme.SendAsync(new CreateSchemeInput
    {
        DelayDistributePeriodCount = 1,
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    // Setup: Add legitimate beneficiary Alice with 1000 shares
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = AliceAddress, Shares = 1000 },
        EndPeriod = long.MaxValue
    });
    
    var schemeBeforeExploit = await ProfitContractStub.GetScheme.CallAsync(schemeId.Output);
    var currentPeriod = schemeBeforeExploit.CurrentPeriod; // Period 1
    
    // Exploit: Add Bob with EndPeriod = CurrentPeriod when DelayDistributePeriodCount = 1
    // This creates: StartPeriod = 2, EndPeriod = 1 (inverted!)
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare { Beneficiary = BobAddress, Shares = 9000 },
        EndPeriod = currentPeriod // EndPeriod = 1
    });
    
    // Verify: TotalShares includes both Alice and Bob
    var schemeAfterExploit = await ProfitContractStub.GetScheme.CallAsync(schemeId.Output);
    schemeAfterExploit.TotalShares.ShouldBe(10000); // 1000 + 9000
    
    // Distribute profits
    await ProfitContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Amount = 100000,
        Symbol = "ELF"
    });
    
    await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Period = currentPeriod,
        AmountsMap = { { "ELF", 0 } }
    });
    
    // Alice can claim, but receives only 10% (10,000) instead of 100% (100,000)
    var aliceProfitBefore = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = AliceAddress,
        Symbol = "ELF"
    });
    
    await ProfitContractStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId.Output,
        Beneficiary = AliceAddress
    });
    
    var aliceProfitAfter = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = AliceAddress,
        Symbol = "ELF"
    });
    
    var aliceReceived = aliceProfitAfter.Balance - aliceProfitBefore.Balance;
    aliceReceived.ShouldBe(10000); // Only 10% due to dilution
    
    // Bob cannot claim (malformed detail is filtered out)
    var bobProfitAmount = await ProfitContractStub.GetProfitAmount.CallAsync(new GetProfitAmountInput
    {
        SchemeId = schemeId.Output,
        Beneficiary = BobAddress,
        Symbol = "ELF"
    });
    bobProfitAmount.Value.ShouldBe(0); // Bob's shares are orphaned
    
    // Verify: 90,000 tokens remain locked, TotalShares still inflated
    var schemeAfterClaim = await ProfitContractStub.GetScheme.CallAsync(schemeId.Output);
    schemeAfterClaim.TotalShares.ShouldBe(10000); // Still includes Bob's 9000 orphaned shares
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L158-214)
```csharp
    public override Empty AddBeneficiary(AddBeneficiaryInput input)
    {
        AssertValidInput(input);
        if (input.EndPeriod == 0)
            // Which means this profit Beneficiary will never expired unless removed.
            input.EndPeriod = long.MaxValue;

        var schemeId = input.SchemeId;
        var scheme = State.SchemeInfos[schemeId];

        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");

        Context.LogDebug(() =>
            $"{input.SchemeId}.\n End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        Assert(input.EndPeriod >= scheme.CurrentPeriod,
            $"Invalid end period. End Period: {input.EndPeriod}, Current Period: {scheme.CurrentPeriod}");

        scheme.TotalShares = scheme.TotalShares.Add(input.BeneficiaryShare.Shares);

        State.SchemeInfos[schemeId] = scheme;

        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };

        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);

        // Remove details too old.
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);

        State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary] = currentProfitDetails;

        Context.LogDebug(() =>
            $"Added {input.BeneficiaryShare.Shares} weights to scheme {input.SchemeId.ToHex()}: {profitDetail}");

        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L265-306)
```csharp
    public override Empty FixProfitDetail(FixProfitDetailInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        var scheme = State.SchemeInfos[input.SchemeId];
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
        }

        // Try to get profitDetails by Id
        var profitDetails = State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary];
        ProfitDetail fixingDetail = null;
        if (input.ProfitDetailId != null)
        {
            // In new rules, rofitDetail.Id equals to its vote id.
            fixingDetail = profitDetails.Details.SingleOrDefault(d => d.Id == input.ProfitDetailId);
        }

        if (fixingDetail == null)
        {
            // However, in the old time, profitDetail.Id is null, so use Shares.
            fixingDetail = profitDetails.Details.OrderBy(d => d.StartPeriod)
                .FirstOrDefault(d => d.Shares == input.BeneficiaryShare.Shares);
        }

        if (fixingDetail == null)
        {
            throw new AssertionException("Cannot find proper profit detail to fix.");
        }

        // Clone the old one to a new one, remove the old, and add the new.
        var newDetail = fixingDetail.Clone();
        // The startPeriod is 0, so use the original one.
        newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
        profitDetails.Details.Remove(fixingDetail);
        profitDetails.Details.Add(newDetail);
        State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary] = profitDetails;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-767)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-797)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L113-117)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod < scheme.CurrentPeriod && (d.LastProfitPeriod == 0
                ? d.EndPeriod >= d.StartPeriod
                : d.EndPeriod >= d.LastProfitPeriod)
        ).ToList();
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
