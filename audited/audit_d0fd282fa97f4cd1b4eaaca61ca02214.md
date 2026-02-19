# Audit Report

## Title
Negative Period Values Bypass Validation Leading to DoS in Profit Claiming

## Summary
The `FixProfitDetail` method in the Profit contract lacks validation on `StartPeriod` and `EndPeriod` values, allowing scheme managers to set negative period values that cause gas exhaustion in profit claiming operations. When beneficiaries attempt to claim profits, the loop in `ProfitAllPeriods` iterates millions of times from negative to positive period values, resulting in denial of service.

## Finding Description

The `FixProfitDetail` method accepts arbitrary period values without validation. [1](#0-0) 

When a scheme manager sets `StartPeriod` to a large negative value (e.g., -1000000) and `EndPeriod` to a positive value (e.g., 100), the validation check in `GetAllProfitsMap` fails to reject this invalid state. [2](#0-1) 

The check `d.EndPeriod >= d.StartPeriod` when `LastProfitPeriod == 0` evaluates to `100 >= -1000000 → true`, allowing the malformed profit detail to pass through.

When `GetAllProfitsMap` processes this invalid detail, it first sets `LastProfitPeriod` to the negative `StartPeriod` value, [3](#0-2)  then calculates the period count as `EndPeriod - LastProfitPeriod`. [4](#0-3) 

With `EndPeriod=100` and `LastProfitPeriod=-1000000`, this yields `100 - (-1000000) = 1,000,100` periods.

This enormous period count is passed to `ProfitAllPeriods`, where the loop executes over the entire range. [5](#0-4) 

The loop runs from `-1000000` to approximately `100`, performing over 1 million iterations with hash computations and state lookups on each iteration, causing transaction failure due to gas exhaustion.

The same vulnerable logic path exists in the `ClaimProfits` function, [6](#0-5)  causing identical DoS when beneficiaries attempt to claim their legitimate profit shares.

## Impact Explanation

**Operational Disruption**: Affected beneficiaries cannot execute `ClaimProfits` to withdraw their profit shares. All attempts result in gas exhaustion and transaction reversion.

**View Function Failures**: Query functions including `GetAllProfitsMap`, `GetProfitAmount`, and `GetAllProfitAmount` fail with gas exhaustion, breaking user interfaces and preventing balance visibility.

**Scope Limitation**: Impact is contained to beneficiaries within schemes controlled by malicious or compromised managers. However, the access control allows both scheme managers and the TokenHolder contract to call this method, [7](#0-6)  potentially broadening the attack surface to system-critical contracts managing staking rewards.

**Severity: MEDIUM** - This is a DoS vulnerability that prevents legitimate profit withdrawals but does not result in fund theft. Beneficiaries' earnings remain locked until the malformed `ProfitDetail` is manually corrected. The severity is elevated from LOW due to the potential impact on system-critical contracts and the inability of victims to access their earned profits.

## Likelihood Explanation

**Attacker Requirements**: The attacker must be a scheme manager, which can be obtained by either creating their own scheme (trivial for any user) or compromising an existing manager account. Scheme managers are per-scheme roles and are not in the trusted roles list (genesis, Parliament/Association/Referendum, consensus contracts).

**Attack Execution**: Extremely simple - a single transaction calling `FixProfitDetail` with negative `StartPeriod` values is sufficient. No complex setup or multi-step process required.

**Real-World Scenarios**:
- **Malicious scheme operators**: A scheme manager can DoS their own beneficiaries
- **Compromised manager accounts**: If a manager's credentials are compromised, the attacker can lock all beneficiaries out of profits
- **Integration vulnerabilities**: If external contracts call `FixProfitDetail` with unsanitized user inputs, they may inadvertently trigger this issue

**Detection**: The attack is immediately apparent when victims attempt to claim profits and all transactions fail. However, remediation requires manual intervention to correct the invalid state.

**Likelihood: MEDIUM** - While obtaining manager privileges for one's own scheme is trivial, meaningful impact requires either convincing users to join a malicious scheme or compromising existing legitimate schemes. The existence of this vulnerability in a core contract without input validation represents a clear defensive gap.

## Recommendation

Add input validation to the `FixProfitDetail` method to ensure period values are non-negative and within reasonable bounds:

```csharp
public override Empty FixProfitDetail(FixProfitDetailInput input)
{
    Assert(input.SchemeId != null, "Invalid scheme id.");
    
    // Add validation for period values
    if (input.StartPeriod != 0)
    {
        Assert(input.StartPeriod > 0, "StartPeriod must be positive.");
    }
    if (input.EndPeriod != 0)
    {
        Assert(input.EndPeriod > 0, "EndPeriod must be positive.");
        if (input.StartPeriod != 0)
        {
            Assert(input.EndPeriod >= input.StartPeriod, "EndPeriod must be >= StartPeriod.");
        }
    }
    
    var scheme = State.SchemeInfos[input.SchemeId];
    // ... rest of existing logic
}
```

Additionally, consider adding validation to ensure period values don't deviate excessively from the current scheme period to prevent both negative values and unreasonably large future periods.

## Proof of Concept

```csharp
[Fact]
public async Task NegativePeriodCausesDoS_Test()
{
    // Setup: Create scheme and add beneficiary
    var schemeId = await CreateDefaultScheme();
    var beneficiary = Accounts[1].Address;
    
    await ProfitContractStub.AddBeneficiary.SendAsync(new AddBeneficiaryInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = beneficiary,
            Shares = 100
        },
        EndPeriod = 100
    });
    
    // Attack: Manager sets negative StartPeriod via FixProfitDetail
    await ProfitContractStub.FixProfitDetail.SendAsync(new FixProfitDetailInput
    {
        SchemeId = schemeId,
        BeneficiaryShare = new BeneficiaryShare
        {
            Beneficiary = beneficiary,
            Shares = 100
        },
        StartPeriod = -1000000,
        EndPeriod = 100
    });
    
    // Verify: ClaimProfits fails with gas exhaustion
    // This will timeout/fail due to excessive loop iterations
    var result = await ProfitContractStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeId = schemeId,
        Beneficiary = beneficiary
    });
    
    // Expected: Transaction should fail due to gas exhaustion
    // The loop will attempt to iterate from -1000000 to ~100
}
```

**Notes:**
- Scheme managers are not part of the trusted roles in AElf (which include only genesis, Parliament/Association/Referendum, and consensus contracts), making malicious or compromised managers a valid threat model
- The vulnerability affects all beneficiaries in the impacted scheme, not just the attacker
- While the TokenHolder contract has permission to call `FixProfitDetail`, code analysis shows it does not currently call this method, reducing immediate system-wide risk
- The Election contract does call `FixProfitDetail` [8](#0-7)  but only sets `EndPeriod` (not `StartPeriod`), so it is not vulnerable to this specific attack path

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L269-273)
```csharp
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L299-301)
```csharp
        newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L784-784)
```csharp
            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L856-860)
```csharp
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L113-117)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod < scheme.CurrentPeriod && (d.LastProfitPeriod == 0
                ? d.EndPeriod >= d.StartPeriod
                : d.EndPeriod >= d.LastProfitPeriod)
        ).ToList();
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L128-128)
```csharp
            if (profitDetail.LastProfitPeriod == 0) profitDetail.LastProfitPeriod = profitDetail.StartPeriod;
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L130-130)
```csharp
            var totalProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod),true, symbol);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L144-154)
```csharp
            State.ProfitContract.FixProfitDetail.Send(new FixProfitDetailInput
            {
                SchemeId = State.WelfareHash.Value,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = electionVotingRecord.Voter,
                    Shares = electionVotingRecord.Weight
                },
                EndPeriod = endPeriod,
                ProfitDetailId = voteId
            });
```
