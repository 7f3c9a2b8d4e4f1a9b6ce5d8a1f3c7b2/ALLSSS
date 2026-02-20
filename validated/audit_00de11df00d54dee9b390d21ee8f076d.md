# Audit Report

## Title
Negative Period Values Bypass Validation Leading to DoS in Profit Claiming

## Summary
The `FixProfitDetail` method in the Profit contract lacks validation on `StartPeriod` and `EndPeriod` values, allowing scheme managers to set negative period values that cause gas exhaustion in profit-related operations. When beneficiaries or users attempt to query or claim profits, loops iterate from large negative values to positive values, resulting in denial of service through gas exhaustion.

## Finding Description

The `FixProfitDetail` method accepts arbitrary period values without validating that they are non-negative. [1](#0-0)  The method simply overwrites the period values without checking if they fall within valid ranges.

When a scheme manager sets `StartPeriod` to a large negative value (e.g., -1000000) and `EndPeriod` to a positive value (e.g., 100), the validation check in `GetAllProfitsMap` fails to reject this invalid state. [2](#0-1)  The check evaluates `d.EndPeriod >= d.StartPeriod` which becomes `100 >= -1000000 → true`, allowing the malformed profit detail to pass validation.

When `GetAllProfitsMap` processes this invalid detail, it sets `LastProfitPeriod` to the negative `StartPeriod` value. [3](#0-2)  It then calculates the maximum period count as `profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod)`, [4](#0-3)  which with `EndPeriod=100` and `LastProfitPeriod=-1000000` yields `100 - (-1000000) = 1,000,100` periods.

This enormous period count influences the calculation of `maxProfitPeriod` in `ProfitAllPeriods`. [5](#0-4)  The loop then executes from the negative `LastProfitPeriod` value. [6](#0-5)  Depending on scheme state and the calculated `maxProfitPeriod`, this can result in over 1 million iterations with hash computations and state lookups on each iteration, causing transaction failure due to gas exhaustion.

The same vulnerable logic path exists in `ClaimProfits`. [7](#0-6)  The validation check is identical and the negative period propagates to the same loop structure, [8](#0-7)  though the impact is somewhat mitigated by period count limits.

## Impact Explanation

**Operational Disruption**: Affected beneficiaries cannot execute `ClaimProfits` to withdraw their profit shares. View functions including `GetAllProfitsMap`, `GetProfitAmount`, and `GetAllProfitAmount` fail with gas exhaustion, breaking user interfaces and preventing balance visibility.

**Scope Limitation**: Impact is contained to beneficiaries within schemes controlled by malicious or compromised managers. However, the access control allows both scheme managers and the TokenHolder contract to call `FixProfitDetail`, [9](#0-8)  potentially broadening the attack surface if the TokenHolder contract or other integrated contracts have vulnerabilities allowing unsanitized inputs to reach this method.

**Severity: MEDIUM** - This is a DoS vulnerability that prevents legitimate profit withdrawals and breaks view functionality but does not result in fund theft. Beneficiaries' earnings remain locked until the malformed `ProfitDetail` is manually corrected through authorized intervention. The severity is elevated from LOW due to the potential impact on system-critical profit distribution schemes and the inability of victims to access their earned profits through normal means.

## Likelihood Explanation

**Attacker Requirements**: The attacker must be a scheme manager. This can be obtained by creating their own scheme (trivial - no authorization required [10](#0-9) ) or by compromising an existing manager account. Scheme managers are per-scheme roles and are not in the trusted roles list (genesis, Parliament/Association/Referendum, consensus contracts).

**Attack Execution**: Extremely simple - a single transaction calling `FixProfitDetail` with negative `StartPeriod` values is sufficient. No complex setup or multi-step process required beyond initial scheme creation and beneficiary addition.

**Real-World Scenarios**:
- **Malicious scheme operators**: A scheme manager can DoS their own beneficiaries
- **Compromised manager accounts**: If a manager's credentials are compromised, the attacker can lock all beneficiaries out of profits
- **Integration vulnerabilities**: If external contracts (including TokenHolder) call `FixProfitDetail` with unsanitized user inputs, they may inadvertently trigger this issue

**Detection**: The attack is immediately apparent when victims attempt to claim profits or query balances and all transactions fail. However, remediation requires manual intervention to correct the invalid state.

**Likelihood: MEDIUM** - While obtaining manager privileges for one's own scheme is trivial, meaningful impact requires either convincing users to join a malicious scheme or compromising existing legitimate schemes. The existence of this vulnerability in a core contract without input validation represents a clear defensive gap.

## Recommendation

Add validation in the `FixProfitDetail` method to ensure period values are non-negative:

```csharp
public override Empty FixProfitDetail(FixProfitDetailInput input)
{
    Assert(input.SchemeId != null, "Invalid scheme id.");
    
    // Add validation for period values
    Assert(input.StartPeriod >= 0 || input.StartPeriod == 0, "StartPeriod must be non-negative.");
    Assert(input.EndPeriod >= 0 || input.EndPeriod == 0, "EndPeriod must be non-negative.");
    
    var scheme = State.SchemeInfos[input.SchemeId];
    // ... rest of method
}
```

Additionally, add a secondary validation check before the loop in `ProfitAllPeriods` to prevent processing invalid period ranges:

```csharp
private Dictionary<string, long> ProfitAllPeriods(...)
{
    // Add safety check
    Assert(profitDetail.LastProfitPeriod >= 0, "Invalid LastProfitPeriod value.");
    
    // ... rest of method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Profit_NegativePeriod_DoS_Test()
{
    // Setup: Create a scheme (anyone can do this)
    var attacker = Creators[0];
    var victim = Creators[1];
    var victimAddress = Address.FromPublicKey(CreatorKeyPair[1].PublicKey);
    
    var schemeId = await attacker.CreateScheme.SendAsync(new CreateSchemeInput());
    
    // Add victim as beneficiary
    await attacker.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = victimAddress,
            Shares = 100
        },
        EndPeriod = 1000
    });
    
    // Attack: Set negative StartPeriod
    await attacker.FixProfitDetail.SendAsync(new FixProfitDetailInput
    {
        SchemeId = schemeId.Output,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = victimAddress,
            Shares = 100
        },
        StartPeriod = -1000000,  // Large negative value
        EndPeriod = 100           // Positive value
    });
    
    // Verify: GetAllProfitsMap causes gas exhaustion
    // This call will fail due to excessive loop iterations
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await attacker.GetAllProfitsMap.CallAsync(new GetAllProfitsMapInput
        {
            SchemeId = schemeId.Output,
            Beneficiary = victimAddress
        });
    });
    
    // The transaction should fail with gas-related error
    exception.ShouldNotBeNull();
}
```

## Notes

This vulnerability specifically affects the profit distribution mechanism where negative period values bypass validation and cause computational DoS. The core issue is the insufficient validation in `FixProfitDetail` combined with the assumption in downstream methods that period values are always non-negative. The attack vector is accessible to any user who can create a scheme, though meaningful exploitation requires either social engineering (convincing users to join malicious schemes) or compromising existing legitimate scheme managers.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L44-57)
```csharp
    public override Hash CreateScheme(CreateSchemeInput input)
    {
        ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
        else
            Assert(
                input.ProfitReceivingDuePeriodCount > 0 &&
                input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
                "Invalid profit receiving due period count.");

        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L269-272)
```csharp
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L299-301)
```csharp
        newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-766)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L780-784)
```csharp
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L856-859)
```csharp
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-860)
```csharp
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L114-116)
```csharp
            d.LastProfitPeriod < scheme.CurrentPeriod && (d.LastProfitPeriod == 0
                ? d.EndPeriod >= d.StartPeriod
                : d.EndPeriod >= d.LastProfitPeriod)
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L128-128)
```csharp
            if (profitDetail.LastProfitPeriod == 0) profitDetail.LastProfitPeriod = profitDetail.StartPeriod;
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L130-130)
```csharp
            var totalProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod),true, symbol);
```
